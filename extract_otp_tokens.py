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
import tempfile
import argparse
import webbrowser
import subprocess

from io import BytesIO
from pathlib import PurePosixPath, Path
from tempfile import NamedTemporaryFile
from xml.etree import ElementTree
from collections import namedtuple
from urllib.parse import quote, urlencode
from urllib.request import pathname2url

Account = namedtuple('Account', ['name', 'digits', 'period', 'secret', 'type', 'algorithm'])

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
        return self.as_uri() == other.as_uri()

    def as_andotp(self):
        raise NotImplementedError()

    def uri_params(self):
        return {}

    def as_uri(self, prepend_issuer=False):
        params = self.uri_params()
        params['secret'] = self.secret

        if self.issuer:
            params['issuer'] = self.issuer

        if prepend_issuer and self.issuer:
            name = f'{self.issuer}: {self.name}'
        else:
            name = self.name or "Unknown"

        return f'otpauth://{self.type}/{quote(name)}?' + urlencode(sorted(params.items()))


class HOTPAccount(OTPAccount):
    type = 'hotp'

    def __init__(self, name, secret, counter, issuer=None, digits=6, algorithm='SHA1'):
        super().__init__(name, secret, issuer)
        self.counter = counter
        self.digits = 6
        self.algorithm = algorithm

    def as_andotp(self):
        return {
            'secret': self.secret,
            'label': self.name,
            'digits': self.digits,
            'counter': self.counter,
            'digits': self.digits,
            'type': self.type,
            'algorithm': self.algorithm
        }

    def uri_params(self):
        return {
            'counter': str(self.counter),
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
        return {
            'secret': self.secret,
            'label': self.name,
            'digits': self.digits,
            'period': self.period,
            'type': self.type,
            'algorithm': self.algorithm
        }

    def uri_params(self):
        return {
            'digits': self.digits,
            'period': self.period,
            'algorithm': self.algorithm
        }


class SteamAccount(OTPAccount):
    type = 'steam'

    def as_andotp(self):
        return {
            'secret': self.secret,
            'label': self.name,
            'type': self.type
        }



def adb_fast_run(command, prefix, *, sentinel='3bb22bb739c29e435151cb38'):
    # `adb exec-out` doesn't work properly on some devices. We have to fall back to `adb shell`,
    # which takes at least 600ms to exit even if the actual command runs quickly.
    # Reading a unique, non-existent file prints a predictable error message that delimits the end of
    # the stream, allowing us to let `adb shell` finish up its stuff in the background.
    lines = []
    process = subprocess.Popen(
        args=['adb', 'shell', command + f'; ls /{sentinel}'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )

    logger.debug('Running %s', process.args)

    for line in process.stdout:
        logger.debug('Read: %s', line)

        if b'ls: /' + sentinel.encode('ascii') in line:
            return lines

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


def adb_list_dir(path):
    logger.debug('Listing directory %s', path)

    lines = adb_fast_run(f'su -c "ls -1 {shlex.quote(str(path))}"', prefix=b'ls: ')

    return [path/l[:-1].decode('utf-8') for l in lines]

def adb_read_file(path):
    logger.debug('Reading file %s', path)

    lines = adb_fast_run(f'su -c "toybox base64 {shlex.quote(str(path))}"', prefix=b'base64: ')

    return BytesIO(base64.b64decode(b''.join(lines)))


def normalize_secret(secret):
    if set(secret.lower()) <= set('0123456789abcdef'):
        return base64.b32encode(bytes.fromhex(secret)).decode('ascii').rstrip('=')
    else:
        return secret.upper().rstrip('=')


def read_authy_accounts(data_root):
    for pref_file in ['com.authy.storage.tokens.authenticator.xml', 'com.authy.storage.tokens.authy.xml']:
        try:
            handle = adb_read_file(data_root/'com.authy.authy/shared_prefs'/pref_file)
        except FileNotFoundError as e:
            continue

        accounts = json.loads(ElementTree.parse(handle).find('string').text)

        for account in accounts:
            if 'decryptedSecret' in account:
                period = 30
                secret = account['decryptedSecret']
            else:
                period = 10
                secret = account['secretSeed']

            yield TOTPAccount(account['name'], secret=secret, digits=account['digits'], period=period)


def read_freeotp_accounts(data_root):
    try:
        handle = adb_read_file(data_root/'org.fedorahosted.freeotp/shared_prefs/tokens.xml')
    except FileNotFoundError:
        return

    for string in ElementTree.parse(handle).findall('string'):
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


def read_duo_accounts(data_root):
    try:
        handle = adb_read_file(data_root/'com.duosecurity.duomobile/files/duokit/accounts.json')
    except FileNotFoundError:
        return

    for account in json.load(handle):
        secret = account['otpGenerator']['otpSecret']

        if 'counter' in account['otpGenerator']:
            yield HOTPAccount(account['name'], secret, counter=account['otpGenerator']['counter'])
        else:
            yield TOTPAccount(account['name'], secret)


def read_google_authenticator_accounts(data_root):
    try:
        database = adb_read_file(data_root/'com.google.android.apps.authenticator2/databases/databases')
    except FileNotFoundError:
        return

    with NamedTemporaryFile(delete=False) as temp_handle:
        temp_handle.write(database.read())

    try:
        connection = sqlite3.connect(temp_handle.name)
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

        connection.close()
    finally:
        os.unlink(temp_handle.name)


def read_microsoft_authenticator_accounts(data_root):
    try:
        database = adb_read_file(data_root/'com.azure.authenticator/databases/PhoneFactor')
    except FileNotFoundError:
        return

    with NamedTemporaryFile(delete=False) as temp_handle:       
        temp_handle.write(database.read())

    try:
        connection = sqlite3.connect(temp_handle.name)
        cursor = connection.cursor()
        cursor.execute('SELECT name, oath_secret_key FROM accounts WHERE account_type=0;')

        for name, secret in cursor.fetchall():
            yield TOTPAccount(name, secret)
    finally:
        os.unlink(temp_handle.name)


def read_andotp_accounts(data_root):
    # Parse the preferences file to determine what kind of backups we can have AndOTP generate and where they will reside
    try:
        handle = adb_read_file(data_root/'org.shadowice.flocke.andotp/shared_prefs/org.shadowice.flocke.andotp_preferences.xml')
    except FileNotFoundError:
        return

    preferences = ElementTree.parse(handle)

    try:
        backup_path = PurePosixPath(preferences.find('.//string[@name="pref_backup_directory"]').text)
    except AttributeError:
        backup_path = PurePosixPath('$EXTERNAL_STORAGE/andOTP')

    try:
        allowed_backup_broadcasts = [s.text for s in preferences.findall('.//set[@name="pref_backup_broadcasts"]/string')]
    except AttributeError:
        allowed_backup_broadcasts = []

    try:
        initial_backup_files = set(adb_list_dir(backup_path))
    except FileNotFoundError:
        initial_backup_files = set()

    if 'encrypted' in allowed_backup_broadcasts:
        try:
            from Crypto.Cipher import AES
        except:
            logger.error('Reading encrypted AndOTP backups requires PyCryptodome')
            return

        adb_fast_run('am broadcast -a org.shadowice.flocke.andotp.broadcast.ENCRYPTED_BACKUP org.shadowice.flocke.andotp', prefix=b'am: ')
    elif 'plain' in allowed_backup_broadcasts:
        if not input('Encrypted AndOTP backups are disabled. Are you sure you want to create a plaintext backup (y/N)? ').lower().startswith('y'):
            logger.debug('Aborted AndOTP plaintext backup')
            return

        adb_fast_run('am broadcast -a org.shadowice.flocke.andotp.broadcast.PLAIN_TEXT_BACKUP org.shadowice.flocke.andotp', prefix=b'am: ')
    else:
        logger.error('No AndOTP backup broadcasts are setup. Please enable at least encrypted backups in the AndOTP settings.')
        return

    backup_data = None
    backup_file = None

    # Find all newly-created backup files
    for i in range(10):
        try:
            time.sleep(0.1)
            new_backups = list(set(adb_list_dir(backup_path)) - initial_backup_files)

            if not new_backups:
                continue

            backup_file = new_backups[0]
            backup_data = adb_read_file(backup_file)
            break
        except FileNotFoundError:
            logger.warning('Did not find any new backup files in %s (attempt %d)', backup_path, i + 1)
    else:
        logger.error('Could not read the AndOTP backup file. Do you have a backup password set?')
        return

    if 'encrypted' in allowed_backup_broadcasts:
        backup_password = getpass.getpass('Enter the AndOTP backup password: ')

        # Structure of backup file (github.com/asmw/andOTP-decrypt)
        size = len(backup_data.getvalue())

        nonce = backup_data.read(12)
        ciphertext = backup_data.read(size - 12 - 16)
        tag = backup_data.read(16)

        key = hashlib.sha256(backup_password.encode('utf-8')).digest()

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        try:
            accounts_json = cipher.decrypt(ciphertext)
            cipher.verify(tag)
        except ValueError:
            logger.error('Could not decrypt the AndOTP backup. Is your password correct?')
            return
    else:
        accounts_json = backup_data.read()

        if backup_file.suffix == '.json':
            if not input('Do you want to delete the plaintext backup (y/N)? ').lower().startswith('y'):
                adb_fast_run(f'su -c "rm {shlex.quote(str(backup_file))}"', prefix=b'rm: ')

    for account in json.loads(accounts_json):
        if account['type'] == 'TOTP':
            yield TOTPAccount(account['label'], account['secret'], digits=account['digits'], period=account['period'], algorithm=account['algorithm'])
        elif account['type'] == 'HOTP':
            yield HOTPAccount(account['label'], account['secret'], digits=account['digits'], counter=account['counter'], algorithm=account['algorithm'])
        elif account['type'] == 'STEAM':
            yield SteamAccount(account['label'], account['secret'])
        else:
            logger.warning('Unknown AndOTP account type: %s', account['type'])


def read_steam_authenticator_accounts(data_root):
    accounts_folder = 'com.valvesoftware.android.steam.community/files'

    try:
        account_files = adb_list_dir(data_root/accounts_folder)
    except FileNotFoundError:
        return

    for account_file in account_files:
        account_json = json.load(adb_read_file(account_file))

        secret = base64.b32encode(base64.b64decode(account_json['shared_secret']))

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
    with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as handle:
        handle.write(accounts_html.encode('utf-8'))

    try:
        webbrowser.open(f'file:{pathname2url(handle.name)}')
        time.sleep(10)  # webbrowser.open exits immediately so we should wait before deleting the file
    finally:
        os.remove(handle.name)



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

    parser.add_argument('--no-show-uri', action='store_true', help='disable printing the accounts as otpauth:// URIs')
    parser.add_argument('--show-qr', action='store_true', help='displays the accounts as a local webpage with scannable QR codes')

    parser.add_argument('--prepend-issuer', action='store_true', help='adds the issuer to the token name')
    parser.add_argument('--andotp-backup', type=Path, help='saves the accounts as an AndOTP backup file')

    parser.add_argument('-v', '--verbose', dest='verbose', action='count', default=0, help='increases verbosity')

    args = parser.parse_args()

    logger.setLevel([logging.INFO, logging.DEBUG][min(args.verbose, 1)])


    logger.info('Checking for root by listing the contents of %s. You might have to grant ADB temporary root access.', args.data)

    if not adb_list_dir(args.data):
        logger.error('Root not found or data directory is incorrect!')
        sys.exit(1)

    logger.debug('Checking if files can be properly read by reading $ANDROID_ROOT/build.prop')

    if not adb_read_file('$ANDROID_ROOT/build.prop'):
        logger.error('Root not found or unable to dump file contents!')
        sys.exit(1)


    accounts = set()

    if not args.no_andotp:
        accounts.update(read_andotp_accounts(args.data))

    if not args.no_authy:
        accounts.update(read_authy_accounts(args.data))

    if not args.no_duo:
        accounts.update(read_duo_accounts(args.data))

    if not args.no_freeotp:
        accounts.update(read_freeotp_accounts(args.data))

    if not args.no_google_authenticator:
        accounts.update(read_google_authenticator_accounts(args.data))

    if not args.no_microsoft_authenticator:
        accounts.update(read_microsoft_authenticator_accounts(args.data))

    if not args.no_steam_authenticator:
        accounts.update(read_steam_authenticator_accounts(args.data))

    if not args.no_show_uri:
        for account in accounts:
            print(account.as_uri(args.prepend_issuer))

    if args.show_qr:
        display_qr_codes(accounts, args.prepend_issuer)

    if args.andotp_backup:
        with open(args.andotp_backup, 'w') as handle:
            handle.write(json.dumps([a.as_andotp() for a in accounts]))
