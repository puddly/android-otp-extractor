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

    def __init__(self, name, secret):
        self.name = name
        self.secret = normalize_secret(secret)

    def as_andotp(self):
        raise NotImplementedError()

    def uri_params(self):
        return {}

    def as_uri(self):
        params = self.uri_params()
        params['secret'] = self.secret

        return f'otpauth://{self.type}/{quote(self.name)}?' + urlencode(params)


class HOTPAccount(OTPAccount):
    type = 'hotp'

    def __init__(self, name, secret, counter, digits=6, algorithm='SHA1'):
        super().__init__(name, secret)
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

    def __init__(self, name, secret, digits=6, period=30, algorithm='SHA1'):
        super().__init__(name, secret)
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


def adb_list_dir(path):
    logger.debug('Listing directory %s', path)

    lines = adb_fast_run(f'su -c "ls -1 {shlex.quote(str(path))}"', prefix=b'ls: ')

    return [path/l[:-1].decode('utf-8') for l in lines]

def adb_read_file(path):
    logger.debug('Reading file %s', path)

    lines = adb_fast_run(f'su -c "su -c "toybox base64 {shlex.quote(str(path))}', prefix=b'base64: ')

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

        if account['type'] == 'TOTP':
            yield TOTPAccount(account['label'], secret, digits=account['digits'], period=account['period'], algorithm=account['algo'])
        elif account['type'] == 'HOTP':
            yield HOTPAccount(account['label'], secret, digits=account['digits'], counter=account['counter'], algorithm=account['algo'])
        else:
            logging.warning('Unknown FreeOTP account type: %s', account['type'])


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

    with NamedTemporaryFile(delete=False, suffix='.html') as temp_handle:       
        temp_handle.write(database.read())

    try:
        connection = sqlite3.connect(temp_handle.name)
        cursor = connection.cursor()
        cursor.execute('SELECT email, secret FROM accounts;')

        for name, secret in cursor.fetchall():
            yield TOTPAccount(name, secret)

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


def read_andotp_accounts(data_root, backup_path, auto_backup):
    try:
        from Crypto.Cipher import AES
    except:
        logging.error('Decrypting AndOTP backups requires PyCryptodome')
        return

    if auto_backup:
        adb_fast_run('am broadcast -a org.shadowice.flocke.andotp.broadcast.ENCRYPTED_BACKUP org.shadowice.flocke.andotp', prefix=b'am: ')

    backup_data = None

    for i in range(5):
        try:
            time.sleep(1.0)
            backup_data = adb_read_file(backup_path)
            break
        except FileNotFoundError:
            logging.warning('Could not read %s (attempt %d)', backup_path, i + 1)
    else:
        logging.error('Could not read the AndOTP backup file. Do you have a backup password set and is your path correct?')
        return

    # Structure of backup file (github.com/asmw/andOTP-decrypt)
    size = len(backup_data.getvalue())

    nonce = backup_data.read(12)
    ciphertext = backup_data.read(size - 12 - 16)
    tag = backup_data.read(16)

    backup_password = getpass.getpass('Enter the AndOTP backup password: ')
    key = hashlib.sha256(backup_password.encode('utf-8')).digest()

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        plaintext = cipher.decrypt(ciphertext)
        cipher.verify(tag)
    except ValueError:
        logging.error('Could not decrypt the AndOTP backup. Is your password correct?')
        return

    accounts = json.loads(plaintext)

    for account in accounts:
        if account['type'] == 'TOTP':
            yield TOTPAccount(account['label'], account['secret'], digits=account['digits'], period=account['period'], algorithm=account['algorithm'])
        elif account['type'] == 'HOTP':
            yield HOTPAccount(account['label'], account['secret'], digits=account['digits'], counter=account['counter'], algorithm=account['algorithm'])
        elif account['type'] == 'STEAM':
            yield SteamAccount(account['label'], account['secret'])
        else:
            logging.warning('Unknown AndOTP account type: %s', account['type'])


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


def display_qr_codes(accounts):
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
        </body>''' % json.dumps([a.as_uri() for a in accounts])

    # Temporary files are only readable by the current user (mode 0600)
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(accounts_html.encode('utf-8'))

    try:
        webbrowser.open(f'file:{pathname2url(handle.name)}')
        time.sleep(10)  # webbrowser.open exits immediately so we should wait before deleting the file
    finally:
        os.remove(handle.name)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extracts TOTP secrets from a rooted Android phone.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--andotp', action='store_true', help='parse an encrypted AndOTP backup')
    parser.add_argument('--andotp-backup-path', default='$EXTERNAL_STORAGE/andOTP/otp_accounts.json.aes', help='path to the AndOTP backup file')
    parser.add_argument('--no-create-andotp-backup', action='store_true', help='do not automatically create an encrypted AndOTP backup')

    parser.add_argument('--no-authy', action='store_true', help='no Authy codes')
    parser.add_argument('--no-duo', action='store_true', help='no Duo codes')
    parser.add_argument('--no-freeotp', action='store_true', help='no FreeOTP codes')
    parser.add_argument('--no-google-authenticator', action='store_true', help='no Google Authenticator codes')
    parser.add_argument('--no-microsoft-authenticator', action='store_true', help='no Microsoft Authenticator codes')
    parser.add_argument('--no-steam-authenticator', action='store_true', help='no Steam Authenticator codes')

    parser.add_argument('--data', type=PurePosixPath, default=PurePosixPath('/data/data/'), help='path to the app data folder')

    parser.add_argument('--no-show-uri', action='store_true', help='disable printing the accounts as otpauth:// URIs')
    parser.add_argument('--show-qr', action='store_true', help='displays the accounts as a local webpage with scannable QR codes')

    parser.add_argument('--andotp-backup', type=Path, help='saves the accounts as an AndOTP backup file')

    parser.add_argument('-v', '--verbose', dest='verbose', action='count', default=0, help='increases verbosity')

    args = parser.parse_args()

    logger.setLevel([logging.INFO, logging.DEBUG][min(args.verbose, 1)])


    logger.info('Checking for root by listing the contents of %s. You might have to grant ADB temporary root access.', args.data)

    if not adb_list_dir(args.data):
        logger.error('Root not found or data directory is incorrect!')
        sys.exit(1)

    if not adb_read_file('/system/build.prop'):
        logger.error('Root not found or unable to dump file contents!')
        sys.exit(1)


    accounts = set()

    if args.andotp:
        accounts.update(read_andotp_accounts(args.data, args.andotp_backup_path, auto_backup=not args.no_create_andotp_backup))

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
            print(account.as_uri())

    if args.show_qr:
        display_qr_codes(accounts)

    if args.andotp_backup:
        with open(args.andotp_backup, 'w') as handle:
            handle.write(json.dumps([a.as_andotp() for a in accounts]))
