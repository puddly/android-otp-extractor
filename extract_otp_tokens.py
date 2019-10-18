#!/usr/bin/env python3

import os
import sys
import time
import json
import shlex
import base64
import getpass
import logging
import sqlite3
import hashlib
import argparse
import contextlib
import webbrowser
import subprocess

from io import BytesIO
from pathlib import PurePosixPath, Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from xml.etree import ElementTree
from urllib.parse import quote, urlencode
from urllib.request import pathname2url


TRACE = logging.DEBUG - 5
logging.addLevelName(TRACE, 'TRACE')

class TraceLogger(logging.getLoggerClass()):
    def trace(self, msg, *args, **kwargs):
        self.log(TRACE, msg, *args, **kwargs)

logging.setLoggerClass(TraceLogger)

logging.basicConfig(format='[%(asctime)s] %(levelname)8s [%(funcName)s:%(lineno)d] %(message)s')
logger = logging.getLogger(__name__)


class OTPAccount:
    type = None

    def __init__(self, name, secret, issuer=None):
        self.name = name
        self.secret = normalize_secret(secret)
        self.issuer = issuer

    def __hash__(self):
        return hash(self.as_uri())

    def __eq__(self, other):
        return self.type == other.type and self.name == other.name and self.secret == other.secret

    def as_andotp(self):
        return {
            'secret': self.secret,
            'label': self.name,
            'type': self.type.upper()
        }

    def uri_params(self):
        raise NotImplementedError()

    def as_uri(self, prepend_issuer=False):
        params = {k: str(v) for k, v in self.uri_params().items()}
        params['secret'] = self.secret

        if self.issuer:
            params['issuer'] = self.issuer

        if prepend_issuer and self.issuer:
            name = f'{self.issuer}: {self.name}'
        else:
            name = self.name or 'Unknown'

        return f'otpauth://{self.type}/{quote(name)}?' + urlencode(sorted(params.items()))

    def __repr__(self):
        args = ', '.join(f'{k}={v!r}' for k, v in self.as_andotp().items() if k != 'type')

        return f'<{self.__class__.__name__}({args})>'


class HOTPAccount(OTPAccount):
    type = 'hotp'

    def __init__(self, name, secret, counter, issuer=None, digits=6, algorithm='SHA1'):
        super().__init__(name, secret, issuer)
        self.counter = counter
        self.digits = digits
        self.algorithm = algorithm

    def as_andotp(self):
        return {**super().as_andotp(), **self.uri_params()}

    def counterless_eq(self, other):
        return super().__eq__(other) and self.digits == other.digits and self.algorithm == other.algorithm

    def uri_params(self):
        return {
            'counter': self.counter,
            'digits': self.digits,
            'algorithm': self.algorithm
        }


class TOTPAccount(OTPAccount):
    type = 'totp'

    def __init__(self, name, secret, issuer=None, digits=6, period=30, algorithm='SHA1'):
        super().__init__(name, secret, issuer)
        self.digits = digits
        self.period = period
        self.algorithm = algorithm

    def as_andotp(self):
        return {**super().as_andotp(), **self.uri_params()}

    def uri_params(self):
        return {
            'digits': self.digits,
            'period': self.period,
            'algorithm': self.algorithm
        }


class SteamAccount(TOTPAccount):
    type = 'steam'

    def __init__(self, name, secret, issuer=None):
        super().__init__(name, secret, issuer, digits=5)


class ADBInterface:
    def run(self, command, *, prefix, root=False):
        end_tag = '3bb22bb739c29e435151cb38'

        command = f'{command}; echo {end_tag}'

        if root:
            command = f'su -c "{command}"'

        # `adb exec-out` doesn't work properly on some devices. We have to fall back to `adb shell`,
        # which takes at least 600ms to exit with `su` even if the actual command runs quickly.
        # Echoing a unique, non-existent string (end_tag) marks the end of
        # the stream, allowing us to let `adb shell` finish up its stuff in the background.
        lines = []
        process = subprocess.Popen(
            args=['adb', 'shell', command],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL
        )
        logger.trace('Running %s', process.args)

        for line in process.stdout:
            logger.trace('Read: %s', line)

            if line.startswith(end_tag.encode('ascii')):
                return lines
            elif b': not found' in line:
                raise RuntimeError('Binary not found')

            if prefix not in line:
                lines.append(line)
                continue

            message = line.partition(prefix)[2].strip()
            process.kill()

            if b'No such file or directory' in message:
                raise FileNotFoundError()
            else:
                raise IOError(message)

        raise ValueError(f'adb command failed: {lines}')

    def list_dir(self, path):
        raise NotImplementedError()

    def read_file(self, path):
        raise NotImplementedError()

    def hash_file(self, path):
        raise NotImplementedError()


class SingleBinaryADBInterface(ADBInterface):
    def __init__(self, binary):
        self.binary = binary

    def list_dir(self, path):
        path = PurePosixPath(path)
        logger.debug('Listing directory %s', path)

        lines = self.run(f'{self.binary} ls -1 {shlex.quote(str(path))}', prefix=b'ls: ', root=True)

        # There apparently exist phones that don't use just newlines (see pull #24)
        return [path/l.rstrip(b'\r\n').decode('utf-8') for l in lines]

    def read_file(self, path):
        path = PurePosixPath(path)

        logger.debug('Trying to read file %s', path)
        lines = self.run(f'{self.binary} base64 {shlex.quote(str(path))}', prefix=b'base64: ', root=True)
        contents = base64.b64decode(b''.join(lines))
        logger.debug('Successfully read %d bytes', len(contents))

        return BytesIO(contents)

    def hash_file(self, path):
        path = PurePosixPath(path)
        logger.debug('Hashing file %s', path)

        # Assume `ls -l` only changes when the file changes
        lines = self.run(f'{self.binary} ls -l {shlex.quote(str(path))}', prefix=b'ls: ', root=True)

        # Hash both the metadata and the file's contents
        key = repr((lines, self.read_file(path).read())).encode('ascii')

        return hashlib.sha256(key).hexdigest()


def normalize_secret(secret):
    if set(secret.lower()) <= set('0123456789abcdef'):
        return base64.b32encode(bytes.fromhex(secret)).decode('ascii').rstrip('=')
    else:
        return secret.upper().rstrip('=')


@contextlib.contextmanager
def open_remote_sqlite_database(adb, database):
    database = PurePosixPath(database)

    with TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)

        for suffix in ['', '-journal', '-wal', '-shm']:
            remote_file = database.with_name(database.name + suffix)

            try:
                contents = adb.read_file(remote_file)
            except FileNotFoundError as e:
                # Throw the original exception if the actual db file cannot be read
                if suffix == '':
                    raise e
            else:
                with (temp_dir/remote_file.name).open('wb') as local_file:
                    local_file.write(contents.read())

        db_path = str(temp_dir/database.name)

        with contextlib.closing(sqlite3.connect(db_path)) as connection:
            yield connection


def read_authy_accounts(adb, data_root):
    for pref_file in ['com.authy.storage.tokens.authenticator.xml', 'com.authy.storage.tokens.authy.xml']:
        try:
            f = adb.read_file(data_root/'com.authy.authy/shared_prefs'/pref_file)
        except FileNotFoundError:
            continue

        accounts = json.loads(ElementTree.parse(f).find('string').text)

        for account in accounts:
            if 'decryptedSecret' in account:
                period = 30
                secret = account['decryptedSecret']
            else:
                period = 10
                secret = account['secretSeed']

            yield TOTPAccount(account['name'], secret=secret, digits=account['digits'], period=period)


def read_freeotp_accounts(adb, data_root):
    try:
        f = adb.read_file(data_root/'org.fedorahosted.freeotp/shared_prefs/tokens.xml')
    except FileNotFoundError:
        return

    for string in ElementTree.parse(f).findall('string'):
        account = json.loads(string.text)

        # <string name="tokenOrder"> doesn't contain an account
        if 'secret' not in account:
            continue

        secret = bytes([b & 0xff for b in account['secret']]).hex()
        issuer = account.get('issuerAlt') or account['issuerExt'] or None
        name = account['label']

        if account['type'] == 'TOTP':
            yield TOTPAccount(name, secret, issuer=issuer, digits=account['digits'], period=account['period'], algorithm=account['algo'])
        elif account['type'] == 'HOTP':
            yield HOTPAccount(name, secret, issuer=issuer, digits=account['digits'], counter=account['counter'], algorithm=account['algo'])
        else:
            logger.warning('Unknown FreeOTP account type: %s', account['type'])


def read_duo_accounts(adb, data_root):
    try:
        f = adb.read_file(data_root/'com.duosecurity.duomobile/files/duokit/accounts.json')
    except FileNotFoundError:
        return

    for account in json.load(f):
        secret = account['otpGenerator']['otpSecret']

        if 'counter' in account['otpGenerator']:
            yield HOTPAccount(account['name'], secret, counter=account['otpGenerator']['counter'])
        else:
            yield TOTPAccount(account['name'], secret)


def read_google_authenticator_accounts(adb, data_root):
    try:
        with open_remote_sqlite_database(adb, data_root/'com.google.android.apps.authenticator2/databases/databases') as connection:
            cursor = connection.cursor()
            cursor.execute('SELECT email, original_name, secret, counter, type, issuer FROM accounts;')

            for email, name, secret, counter, type, issuer in cursor.fetchall():
                name = name if name is not None else email

                if type == 0:
                    yield TOTPAccount(name, secret, issuer=issuer)
                elif type == 1:
                    yield HOTPAccount(name, secret, issuer=issuer, counter=counter)
                else:
                    logger.warning('Unknown Google Authenticator account type: %s', type)
    except FileNotFoundError:
        return


def read_microsoft_authenticator_accounts(adb, data_root):
    try:
        with open_remote_sqlite_database(adb, data_root/'com.azure.authenticator/databases/PhoneFactor') as connection:
            cursor = connection.cursor()
            cursor.execute('SELECT name, oath_secret_key FROM accounts WHERE account_type=0;')

            for name, secret in cursor.fetchall():
                yield TOTPAccount(name, secret)
    except FileNotFoundError:
        return


def read_andotp_accounts(adb, data_root):
    # Parse the preferences file to determine what kind of backups we can have AndOTP generate and where they will reside
    try:
        f = adb.read_file(data_root/'org.shadowice.flocke.andotp/shared_prefs/org.shadowice.flocke.andotp_preferences.xml')
    except FileNotFoundError:
        return

    preferences = ElementTree.parse(f)

    try:
        backup_path = PurePosixPath(preferences.find('.//string[@name="pref_backup_directory"]').text)
    except AttributeError:
        backup_path = PurePosixPath('$EXTERNAL_STORAGE/andOTP')

    try:
        allowed_backup_broadcasts = [s.text for s in preferences.findall('.//set[@name="pref_backup_broadcasts"]/string')]
    except AttributeError:
        allowed_backup_broadcasts = []

    try:
        initial_backup_files = {f: adb.hash_file(f) for f in adb.list_dir(backup_path)}
    except FileNotFoundError:
        initial_backup_files = {}

    logger.info('Sending AndOTP a broadcast to create a backup. This may take a few seconds...')

    if 'encrypted' in allowed_backup_broadcasts:
        try:
            from Crypto.Cipher import AES
        except:
            logger.error('Reading encrypted AndOTP backups requires PyCryptodome')
            return

        adb.run('am broadcast -a org.shadowice.flocke.andotp.broadcast.ENCRYPTED_BACKUP org.shadowice.flocke.andotp', prefix=b'am: ')
    elif 'plain' in allowed_backup_broadcasts:
        if not input('Encrypted AndOTP backups are disabled. Are you sure you want to create a plaintext backup (y/N)? ').lower().startswith('y'):
            logger.info('Aborted AndOTP plaintext backup')
            return

        adb.run('am broadcast -a org.shadowice.flocke.andotp.broadcast.PLAIN_TEXT_BACKUP org.shadowice.flocke.andotp', prefix=b'am: ')
    else:
        logger.error('No AndOTP backup broadcasts are setup. Please enable encrypted backups.')
        return

    backup_data = None
    backup_file = None

    # Find all newly-created backup files
    for i in range(10):
        try:
            logger.info('Waiting for AndOTP to generate the backup file (attempt %d)', i + 1)
            time.sleep(1)

            new_backups = [f for f in adb.list_dir(backup_path) if initial_backup_files.get(f) != adb.hash_file(f)]

            if not new_backups:
                continue

            logger.debug('Found AndOTP backup files: %s', new_backups)

            backup_file = new_backups[0]
            backup_data = adb.read_file(backup_file)
            break
        except FileNotFoundError:
            continue
    else:
        logger.error('Could not find the AndOTP backup file. Do you have a backup password set?')
        return

    if 'encrypted' in allowed_backup_broadcasts:
        while True:
            backup_password = getpass.getpass('Enter the AndOTP backup password: ')

            if not backup_password:
                logger.warning('Aborting AndOTP export because user did not enter a password!')
                return

            success = False

            for new_format in (False, True):
                backup_data.seek(0)

                if new_format:
                    num_iterations = int.from_bytes(backup_data.read(4), 'big')
                    salt = backup_data.read(12)
                    key = hashlib.pbkdf2_hmac(
                        hash_name='sha1', 
                        password=backup_password.encode('utf-8'),
                        salt=salt, 
                        iterations=num_iterations, 
                        dklen=32
                    )
                else:
                    key = hashlib.sha256(backup_password.encode('utf-8')).digest()

                # Only the new format has a "header"
                data = BytesIO(backup_data.read())

                # Structure of backup file (github.com/asmw/andOTP-decrypt)
                size = len(data.getvalue())

                nonce = data.read(12)
                ciphertext = data.read(size - 12 - 16)
                tag = data.read(16)

                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

                try:
                    accounts_json = cipher.decrypt(ciphertext)
                    cipher.verify(tag)
                    success = True
                    break
                except ValueError:
                    if new_format:
                        # At this point we've tried both formats so the password is wrong
                        logger.error('Could not decrypt the AndOTP backup. Is your password correct?')

                    continue

            if success:
                break
    else:
        accounts_json = backup_data.read()

        if backup_file.suffix == '.json':
            if not input('Do you want to delete the plaintext backup (y/N)? ').lower().startswith('y'):
                adb.run(f'rm {shlex.quote(str(backup_file))}', prefix=b'rm: ', root=True)

    for account in json.loads(accounts_json):
        if account['type'] == 'TOTP':
            yield TOTPAccount(account['label'], account['secret'], digits=account['digits'], period=account['period'], algorithm=account['algorithm'])
        elif account['type'] == 'HOTP':
            yield HOTPAccount(account['label'], account['secret'], digits=account['digits'], counter=account['counter'], algorithm=account['algorithm'])
        elif account['type'] == 'STEAM':
            yield SteamAccount(account['label'], account['secret'])
        else:
            logger.warning('Unknown AndOTP account type: %s', account['type'])


def read_steam_authenticator_accounts(adb, data_root):
    try:
        account_files = adb.list_dir(data_root/'com.valvesoftware.android.steam.community/files')
    except FileNotFoundError:
        return

    for account_file in account_files:
        account_json = json.load(adb.read_file(account_file))

        secret = base64.b32encode(base64.b64decode(account_json['shared_secret'])).decode('ascii')

        yield SteamAccount(account_json['account_name'], secret)


def display_qr_codes(accounts, prepend_issuer=False):
    accounts_html = '''
        <!doctype html>

        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
        <meta http-equiv="Pragma" content="no-cache" />
        <meta http-equiv="Expires" content="0" />

        <title>OTP QR Codes</title>
        <style type="text/css">
            body {
                width: 100%%;
            }
        </style>

        <body>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/qrious/4.0.2/qrious.min.js" integrity="sha384-Dr98ddmUw2QkdCarNQ+OL7xLty7cSxgR0T7v1tq4UErS/qLV0132sBYTolRAFuOV" crossorigin="anonymous"></script>
            <script>
                var accounts = %s;

                for (var i = 0; i < accounts.length; i++) {
                    var account = accounts[i];

                    var heading = document.createElement('h2');
                    heading.textContent = decodeURIComponent(account.split('?')[0].split('/')[3]);
                    document.body.appendChild(heading);

                    var image = document.createElement('img');
                    image.style.width = '100%%';
                    image.style.maxWidth = '500px';
                    image.style.height = 'auto';
                    document.body.appendChild(image);

                    var qr_image = new QRious({
                        element: image,
                        value: account,
                        size: 500
                    });

                    var label = document.createElement('pre');
                    label.textContent = account;
                    document.body.appendChild(label);
                }
            </script>
        </body>''' % json.dumps([a.as_uri(prepend_issuer) for a in accounts])

    # Temporary files are only readable by the current user (mode 0600)
    with NamedTemporaryFile(delete=False, suffix='.html') as temp_html_file:
        temp_html_file.write(accounts_html.encode('utf-8'))

    try:
        webbrowser.open(f'file:{pathname2url(temp_html_file.name)}')
        time.sleep(10)  # webbrowser.open exits immediately so we should wait before deleting the file
    finally:
        os.remove(temp_html_file.name)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extracts TOTP secrets from a rooted Android phone.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--no-andotp', action='store_true', help='do not create and parse an AndOTP backup')
    parser.add_argument('--no-authy', action='store_true', help='no Authy codes')
    parser.add_argument('--no-duo', action='store_true', help='no Duo codes')
    parser.add_argument('--no-freeotp', action='store_true', help='no FreeOTP codes')
    parser.add_argument('--no-google-authenticator', action='store_true', help='no Google Authenticator codes')
    parser.add_argument('--no-microsoft-authenticator', action='store_true', help='no Microsoft Authenticator codes')
    parser.add_argument('--no-steam-authenticator', action='store_true', help='no Steam Authenticator codes')

    parser.add_argument('--data', type=PurePosixPath, default=PurePosixPath('$ANDROID_DATA/data/'), help='path to the app data folder')
    parser.add_argument('--busybox-path', type=PurePosixPath, default=None, help='path to {Busy,Toy}box supporting base64 and ls')

    parser.add_argument('--no-show-uri', action='store_true', help='disable printing the accounts as otpauth:// URIs')
    parser.add_argument('--show-qr', action='store_true', help='displays the accounts as a local webpage with scannable QR codes')

    parser.add_argument('--prepend-issuer', action='store_true', help='adds the issuer to the token name')
    parser.add_argument('--andotp-backup', type=Path, help='saves the accounts as an AndOTP backup file')

    parser.add_argument('-v', '--verbose', dest='verbose', action='count', default=0, help='increases verbosity')

    args = parser.parse_args()

    logger.setLevel([logging.INFO, logging.DEBUG, TRACE][min(max(0, args.verbose), 2)])

    if args.busybox_path is not None:
        adb = SingleBinaryADBInterface(args.busybox_path)
    else:
        adb = None

        for binary in ['toybox', 'busybox']:
            logger.info('Testing if your phone uses %s...', binary)

            test = SingleBinaryADBInterface(binary)

            try:
                files = test.list_dir('/')

                logger.debug('Contents of / are: %s', files)

                if not files:
                    raise IOError('Root is empty')
            except (IOError, RuntimeError) as e:
                logger.warning('Could not list /: %s', e)
                continue

            logger.info('It does!')
            adb = test
            break
        else:
            logger.error('Could not find a suitable file reading interface!')
            sys.exit(1)

    logger.info('Checking for root by listing the contents of %s. You might have to grant ADB temporary root access.', args.data)

    if not adb.list_dir(args.data):
        logger.error('Root not found or data directory is incorrect!')
        sys.exit(1)

    logger.info('Checking if files can be properly read by reading $ANDROID_ROOT/build.prop')

    if not adb.read_file('$ANDROID_ROOT/build.prop'):
        logger.error('Root not found or unable to dump file contents!')
        sys.exit(1)


    accounts = set()

    for name, flag, function in [
        ('AndOTP',                  args.no_andotp,                  read_andotp_accounts),
        ('Authy',                   args.no_authy,                   read_authy_accounts),
        ('Duo',                     args.no_duo,                     read_duo_accounts),
        ('FreeOTP',                 args.no_freeotp,                 read_freeotp_accounts),
        ('Google Authenticator',    args.no_google_authenticator,    read_google_authenticator_accounts),
        ('Microsoft Authenticator', args.no_microsoft_authenticator, read_microsoft_authenticator_accounts),
        ('Steam Authenticator',     args.no_steam_authenticator,     read_steam_authenticator_accounts),
    ]:
        if flag:
            continue

        logger.info('Reading %s accounts', name)
        new = list(function(adb, args.data))
        old_count = len(accounts)

        for account in new:
            logger.debug('Found an account %s', account)

            if not isinstance(account, HOTPAccount):
                accounts.add(account)
                continue

            try:
                duplicate = next(account for other in accounts if account.counterless_eq(other))
            except StopIteration:
                accounts.add(account)
                continue

            logger.warning('Identical HOTP accounts exist with different counters: %s != %s', account, duplicate)
            logger.warning('Picking the one with the largest counter.')

            if duplicate.counter < account.counter:
                accounts.remove(duplicate)
                account.add(account)

        logger.info('Found %d accounts (%d new)', len(new), len(accounts) - old_count)

    if not args.no_show_uri:
        for account in accounts:
            print(account.as_uri(args.prepend_issuer))

    if args.show_qr:
        display_qr_codes(accounts, args.prepend_issuer)

    if args.andotp_backup:
        with open(args.andotp_backup, 'w') as f:
            f.write(json.dumps([a.as_andotp() for a in accounts]))
