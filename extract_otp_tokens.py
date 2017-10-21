import os
import sys
import json
import base64
import webbrowser
import subprocess

from io import BytesIO
from tempfile import NamedTemporaryFile
from xml.etree import ElementTree
from collections import namedtuple
from urllib.parse import quote, urlencode

Account = namedtuple('Account', ['name', 'digits', 'period', 'secret'])


def adb_read_file(path):
    try:
        return BytesIO(subprocess.check_output(['adb', 'exec-out', f'su -c "cat {path}"']))
    except subprocess.CalledProcessError:
        raise FileNotFoundError(path)


def otpauth_encode_account(account):
    return f'otpauth://totp/{quote(account.name)}?' + urlencode({
        'secret': base64.b32encode(decode_secret(account.secret)).decode('ascii').rstrip('='),
        'digits': account.digits,
        'period': account.period
    })


def decode_secret(secret):
    if isinstance(secret, str):
        secret = secret.encode('ascii')

    if set(secret.lower()) <= set(b'0123456789abcdef'):
        return bytes.fromhex(secret.decode('ascii'))
    else:
        # some secrets are base32, but have stripped padding
        padding = b'=' * ((8 - (len(secret) % 8)) % 8)
        return base64.b32decode(secret + padding, casefold=True)


def read_authy_accounts(data_root):
    for path in [
        os.path.join(data_root, 'com.authy.authy/shared_prefs/com.authy.storage.tokens.authenticator.xml'),
        os.path.join(data_root, 'com.authy.authy/shared_prefs/com.authy.storage.tokens.authy.xml')
    ]:
        try:
            handle = adb_read_file(path)
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

            yield Account(account['name'], account['digits'], period, secret)


def read_authenticator_accounts(data_root):
    try:
        database = adb_read_file(os.path.join(data_root, 'com.google.android.apps.authenticator2/databases/databases'))
    except FileNotFoundError:
        return

    with NamedTemporaryFile(delete=False) as temp_handle:       
        temp_handle.write(database.read())

    try:
        connection = sqlite3.connect(temp_handle.name)
        cursor = connection.cursor()
        cursor.execute('SELECT email, secret FROM accounts;')

        for name, secret in cursor.fetchall():
            yield Account(name, 6, 30, secret)
    finally:
        os.unlink(temp_handle.name)


def display_qr_codes(accounts):
    accounts_html = '''
        <!doctype html>
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

    accounts_encoded_html = 'data:text/html;base64,' + base64.b64encode(accounts_html.encode('utf-8')).decode('ascii')
    webbrowser.open(accounts_encoded_html)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        data_root = '/data/data/'
    else:
        data_root = sys.argv[1]

    accounts = []
    accounts.extend(read_authy_accounts(data_root))
    accounts.extend(read_authenticator_accounts(data_root))

    for account in accounts:
        print(otpauth_encode_account(account))

    if input('Do you want to see the QR codes in your web browser?').lower() in {'yes', 'y'}:
        display_qr_codes(accounts)
