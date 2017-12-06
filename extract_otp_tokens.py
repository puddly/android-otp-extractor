import os
import sys
import json
import shlex
import base64
import sqlite3
import argparse
import webbrowser
import subprocess

from io import BytesIO
from pathlib import Path
from tempfile import NamedTemporaryFile
from xml.etree import ElementTree
from collections import namedtuple
from urllib.parse import quote, urlencode

Account = namedtuple('Account', ['name', 'digits', 'period', 'secret'])


def parse_bool(value):
    return value.lower() in {'y', 'yes', 'true'}


def adb_read_file(path):
    print('Reading file', path, file=sys.stderr)

    process = subprocess.Popen(['adb', 'exec-out', 'su', '-c', 'cat "{}"'.format(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if stderr:
        raise IOError(stderr)

    if stdout.startswith(b'sh: '):
        error = stdout.partition(b'sh: ')[2].strip()

        if error.endswith(b'No such file or directory'):
            raise FileNotFoundError(path)
        else:
            raise IOError(error)

    return BytesIO(stdout)


def check_root():
    try:
        output = subprocess.check_output(['adb', 'exec-out', 'su', '-c', 'printf TEST'])
        return output.strip() == b'TEST'
    except subprocess.CalledProcessError:
        return False


def otpauth_encode_account(account):
    return f'otpauth://totp/{quote(account.name)}?' + urlencode({
        'secret': account.secret,
        'digits': account.digits,
        'period': account.period
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

            yield Account(account['name'], account['digits'], period, normalize_secret(secret))


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

        yield Account(account['label'], account['digits'], account['period'], secret)


def read_duo_accounts(data_root):
    try:
        handle = adb_read_file(data_root/'com.duosecurity.duomobile/files/duokit/accounts.json')
    except FileNotFoundError:
        return

    for account in json.load(handle):
        yield Account(account['name'], 6, 30, normalize_secret(account['otpGenerator']['otpSecret']))


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
        cursor.execute('SELECT email, secret FROM accounts;')

        for name, secret in cursor.fetchall():
            yield Account(name, 6, 30, normalize_secret(secret))
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
            yield Account(name, 6, 30, normalize_secret(secret))
    finally:
        os.unlink(temp_handle.name)


def export_andotp(accounts):
    return json.dumps([{
        'secret': a.secret,
        'label': a.name,
        'digits': a.digits,
        'period': a.period,
        'type': 'TOTP',
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
                let accounts = %s;

                for (let account of accounts) {
                    let heading = document.createElement('h2');
                    heading.textContent = decodeURIComponent(account.split('?')[0].split('/')[3]);
                    document.body.appendChild(heading);

                    let image = document.createElement('img');
                    image.style.width = '100%%';
                    image.style.maxWidth = '500px';
                    image.style.height = 'auto';
                    document.body.appendChild(image);

                    let qr_image = new QRious({
                        element: image,
                        value: account,
                        size: 500
                    });
                }
            </script>
        </body>''' % json.dumps([otpauth_encode_account(a) for a in accounts])

    accounts_encoded_html = b'data:text/html;base64,' + base64.b64encode(accounts_html.encode('utf-8'))
    webbrowser.open(accounts_encoded_html.decode('ascii'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extracts TOTP secrets from a rooted Android phone.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--no-authy', action='store_true', help='no Authy codes')
    parser.add_argument('--no-google-authenticator', action='store_true', help='no Google Authenticator codes')
    parser.add_argument('--no-microsoft-authenticator', action='store_true', help='no Microsoft Authenticator codes')
    parser.add_argument('--no-freeotp', action='store_true', help='no FreeOTP codes')
    parser.add_argument('--no-duo', action='store_true', help='no Duo codes')
    parser.add_argument('--data', type=Path, default=Path('/data/data/'), help='path to the app data folder')
    parser.add_argument('--show-uri', nargs='?', default=True, type=parse_bool, help='prints the accounts as otpauth:// URIs')
    parser.add_argument('--show-qr', nargs='?', default=False, const=True, type=parse_bool, help='displays the accounts as a local webpage with scannable QR codes')
    parser.add_argument('--andotp-backup', type=Path, help='saves the accounts as an AndOTP backup file')

    args = parser.parse_args()


    print('Checking for root. You might have to grant ADB temporary root access.', file=sys.stderr)

    if not check_root():
        print('Root not found!', file=sys.stderr)
        sys.exit(1)


    accounts = set()

    if not args.no_authy:
        accounts.update(read_authy_accounts(args.data))

    if not args.no_freeotp:
        accounts.update(read_freeotp_accounts(args.data))

    if not args.no_duo:
        accounts.update(read_duo_accounts(args.data))

    if not args.no_google_authenticator:
        accounts.update(read_google_authenticator_accounts(args.data))

    if not args.no_microsoft_authenticator:
        accounts.update(read_microsoft_authenticator_accounts(args.data))


    if args.show_uri:
        for account in accounts:
            print(otpauth_encode_account(account))

    if args.show_qr:
        display_qr_codes(accounts)

    if args.andotp_backup:
        with open(args.andotp_backup, 'wb') as handle:
            handle.write(export_andotp(accounts).encode('utf-8'))
