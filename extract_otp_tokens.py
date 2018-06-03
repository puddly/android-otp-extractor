import os
import sys
import time
import json
import shlex
import base64
import sqlite3
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


def adb_list_dir(path):
    print('Listing directory', path, file=sys.stderr)

    # `adb exec-out` doesn't work properly on some devices. We have to fall back to `adb shell`,
    # which takes at least 600ms to exit even if the actual command runs quickly.
    # Reading a unique, non-existent file prints a predictable error message that delimits the end of
    # the stream, allowing us to let `adb shell` finish up its stuff in the background.
    lines = []
    process = subprocess.Popen(
        args=['adb', 'shell', f'su -c "ls -1 {shlex.quote(str(path))}; ls /3bb22bb739c29e435151cb38"'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )

    for line in process.stdout:
        if b'ls: ' not in line:
            lines.append(line)
            continue

        message = line.partition(b'ls: ')[2].strip()
        process.kill()

        if b'3bb22bb739c29e435151cb38' in message:
            return [path/l[:-1].decode('utf-8') for l in lines]
        elif b'No such file or directory' in message:
            raise FileNotFoundError(path)
        else:
            raise IOError(message)


def adb_read_file(path):
    print('Reading file', path, file=sys.stderr)

    # `adb exec-out` doesn't work properly on some devices. We have to fall back to `adb shell`,
    # which takes at least 600ms to exit even if the actual command runs quickly.
    # Reading a unique, non-existent file prints a predictable error message that delimits the end of
    # the stream, allowing us to let `adb shell` finish up its stuff in the background.
    lines = []
    process = subprocess.Popen(
        args=['adb', 'shell', f'su -c "toybox base64 {shlex.quote(str(path))} /3bb22bb739c29e435151cb38"'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )

    for line in process.stdout:
        if b'base64: ' not in line:
            lines.append(line)
            continue

        message = line.partition(b'base64: ')[2].strip()
        process.kill()

        if b'3bb22bb739c29e435151cb38' in message:
            return BytesIO(base64.b64decode(b''.join(lines)))
        elif b'No such file or directory' in message:
            raise FileNotFoundError(path)
        else:
            raise IOError(message)


def otpauth_encode_account(account):
    return f'otpauth://totp/{quote(account.name)}?' + urlencode({
        'secret': account.secret,
        'digits': account.digits,
        'period': account.period,
        'type': account.type,
        'algorithm': account.algorithm,
    })


def normalize_secret(secret):
    if set(secret.lower()) <= set('0123456789abcdef'):
        return base64.b32encode(bytes.fromhex(secret)).decode('ascii').rstrip('=')
    else:
        return secret.upper().rstrip('=')


def read_authy_accounts(data_root):
    for pref_file in ['com.authy.storage.tokens.authenticator.xml', 'com.authy.storage.tokens.authy.xml']:
        try:
            handle = adb_read_file(data_root/'com.authy.authy/shared_prefs'/pref_file)
        except FileNotFoundError:
            continue

        accounts = json.loads(ElementTree.parse(handle).find('string').text)

        for account in accounts:
            if 'decryptedSecret' in account:
                period = 30
                secret = account['decryptedSecret']
            else:
                period = 10
                secret = account['secretSeed']

            yield Account(account['name'], account['digits'], period, normalize_secret(secret), 'TOTP', 'SHA1')


def read_freeotp_accounts(data_root):
    try:
        handle = adb_read_file(data_root/'org.fedorahosted.freeotp/shared_prefs/tokens.xml')
    except FileNotFoundError:
        return

    for string in ElementTree.parse(handle).findall('string'):
        account = json.loads(string.text)

        if 'secret' not in account:
            continue

        if account['type'] != 'TOTP':
            raise ValueError('Only TOTP is supported.')

        secret = normalize_secret(bytes([b & 0xff for b in account['secret']]).hex())

        yield Account(account['label'], account['digits'], account['period'], secret, 'TOTP', 'SHA1')


def read_duo_accounts(data_root):
    try:
        handle = adb_read_file(data_root/'com.duosecurity.duomobile/files/duokit/accounts.json')
    except FileNotFoundError:
        return

    for account in json.load(handle):
        yield Account(account['name'], 6, 30, normalize_secret(account['otpGenerator']['otpSecret']), 'TOTP', 'SHA1')


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
            yield Account(name, 6, 30, normalize_secret(secret), 'TOTP', 'SHA1')
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
            yield Account(name, 6, 30, normalize_secret(secret), 'TOTP', 'SHA1')
    finally:
        os.unlink(temp_handle.name)


def read_andotp_accounts(data_root):
    print('''
AndOTP encrypts its database with a key stored in the Android Keystore.
There is currently no way to interface with the Android Keystore and decrypt its database using just `adb` commands.
You will have to manually create a backup with AndOTP, which I can then read.
''')

    subprocess.check_output(['adb', 'shell', 'su', '-c', "am start -n org.shadowice.flocke.andotp/.Activities.BackupActivity"])
    backup_path = input('Enter the backup path (default: /sdcard/Download/otp_accounts.json): ') or '/sdcard/Download/otp_accounts.json'

    delete = input('Do you want to delete the backup afterwards (default: no)? ').lower() in ('yes', 'y')

    try:
        backup_data = adb_read_file(backup_path)
    except FileNotFoundError:
        print('Invalid path!', file=sys.stderr)
        return

    backup = json.load(backup_data)

    for account in backup:
        yield Account(account['label'], account['digits'], account['period'], normalize_secret(account['secret']), account['type'], account['algorithm'])

    if delete:
        subprocess.check_output(['adb', 'shell', 'rm', backup])


def read_steam_authenticator_accounts(data_root):
    accounts_folder = 'com.valvesoftware.android.steam.community/files'
    try:
        account_files = adb_list_dir(data_root/accounts_folder)
    except FileNotFoundError:
        return

    for account_file in account_files:
        account_json = json.load(adb_read_file(account_file))

        secret = normalize_secret(base64.b32encode(base64.b64decode(account_json['shared_secret'])))

        yield Account(account_json['account_name'], 5, 30, secret, 'STEAM', 'SHA1')


def export_andotp(accounts):
    return json.dumps([{
        'secret': a.secret if not a.name.startswith('steam-') else a.secret.decode('utf-8'),
        'label': a.name,
        'digits': a.digits,
        'period': a.period,
        'type': a.type,
        'algorithm': 'SHA1'
    } for a in accounts])


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
                }
            </script>
        </body>''' % json.dumps([otpauth_encode_account(a) for a in accounts])

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
    parser.add_argument('--andotp', action='store_true', help='parse AndOTP codes from a backup')
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

    args = parser.parse_args()


    print(f'Checking for root by listing the contents of {args.data}. You might have to grant ADB temporary root access.', file=sys.stderr)

    if not adb_list_dir(args.data):
        print('Root not found or data directory is incorrect!', file=sys.stderr)
        sys.exit(1)


    accounts = set()

    if args.andotp:
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
            print(otpauth_encode_account(account))

    if args.show_qr:
        display_qr_codes(accounts)

    if args.andotp_backup:
        with open(args.andotp_backup, 'wb') as handle:
            handle.write(export_andotp(accounts).encode('utf-8'))
