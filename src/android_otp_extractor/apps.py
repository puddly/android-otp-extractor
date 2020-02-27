import time
import json
import shlex
import base64
import hashlib
import getpass
import logging

from pathlib import PurePosixPath
from xml.etree import ElementTree
from collections import namedtuple

import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


from .contrib import open_remote_sqlite_database
from .otp import TOTPAccount, HOTPAccount, SteamAccount


logger = logging.getLogger(__name__)


SupportedApp = namedtuple('SupportedApp', ['name', 'simple_name', 'extractor'])
SUPPORTED_APPS = []


def supported_app(name):
    '''
    Simple decorator to populate the SUPPORTED_APPS list
    '''

    simple_name = name.lower().replace('+', '_plus').replace(' ', '_')

    def inner(extractor):
        SUPPORTED_APPS.append(SupportedApp(name, simple_name, extractor))

        return extractor

    return inner


@supported_app('Authy')
def read_authy_accounts(adb):
    for pref_file in ['com.authy.storage.tokens.authenticator.xml', 'com.authy.storage.tokens.authy.xml']:
        try:
            f = adb.read_file(adb.data_root/'com.authy.authy/shared_prefs'/pref_file)
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


def _read_freeotp_accounts(adb, *, package_name):
    try:
        f = adb.read_file(adb.data_root/package_name/'shared_prefs/tokens.xml')
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


@supported_app('FreeOTP')
def read_freeotp_accounts(adb):
    return _read_freeotp_accounts(adb, package_name='org.fedorahosted.freeotp')


@supported_app('FreeOTP+')
def read_freeotp_plus_accounts(adb):
    return _read_freeotp_accounts(adb, package_name='org.liberty.android.freeotpplus')


@supported_app('Duo')
def read_duo_accounts(adb):
    try:
        f = adb.read_file(adb.data_root/'com.duosecurity.duomobile/files/duokit/accounts.json')
    except FileNotFoundError:
        return

    for account in json.load(f):
        secret = account['otpGenerator']['otpSecret']

        if 'counter' in account['otpGenerator']:
            yield HOTPAccount(account['name'], secret, counter=account['otpGenerator']['counter'])
        else:
            yield TOTPAccount(account['name'], secret)


@supported_app('Google Authenticator')
def read_google_authenticator_accounts(adb):
    try:
        with open_remote_sqlite_database(adb, adb.data_root/'com.google.android.apps.authenticator2/databases/databases') as connection:
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


@supported_app('Microsoft Authenticator')
def read_microsoft_authenticator_accounts(adb):
    try:
        with open_remote_sqlite_database(adb, adb.data_root/'com.azure.authenticator/databases/PhoneFactor') as connection:
            cursor = connection.cursor()
            cursor.execute('SELECT name, oath_secret_key FROM accounts;')

            for name, secret in cursor.fetchall():
                yield TOTPAccount(name, secret)
    except FileNotFoundError:
        return


@supported_app('AndOTP')
def read_andotp_accounts(adb):
    # Parse the preferences file to determine what kind of backups we can have AndOTP generate and where they will reside
    try:
        f = adb.read_file(adb.data_root/'org.shadowice.flocke.andotp/shared_prefs/org.shadowice.flocke.andotp_preferences.xml')
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
        adb.run('am broadcast -a org.shadowice.flocke.andotp.broadcast.ENCRYPTED_BACKUP org.shadowice.flocke.andotp', prefix=b'am: ')
    elif 'plain' in allowed_backup_broadcasts:
        logger.error('Plaintext AndOTP backups are not supported. Please enable encrypted backups instead.')
        return
    else:
        logger.error('No AndOTP backup broadcasts are setup. Enable encrypted backups in the app settings, under "Backup Broadcasts".')
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

    while True:
        backup_password = getpass.getpass('Enter the AndOTP backup password: ')

        if not backup_password:
            logger.warning('Aborting AndOTP export because user did not enter a password!')
            return

        success = False

        # Try interpreting the data as both the old and new formats
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

            # The encrypted data at the end is the same for both formats
            nonce = backup_data.read(12)
            ciphertext_and_tag = backup_data.read()

            try:
                accounts_json = AESGCM(key).decrypt(nonce, ciphertext_and_tag, associated_data=None)
                success = True
                break
            except cryptography.exceptions.InvalidTag:
                if new_format:
                    # At this point we've tried both formats so the password is wrong
                    logger.error('Could not decrypt the AndOTP backup. Is your password correct?')

                continue

        if success:
            break

    logger.info('Deleting generated backup file: %s', backup_file)
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


@supported_app('Steam Authenticator')
def read_steam_authenticator_accounts(adb):
    try:
        account_files = adb.list_dir(adb.data_root/'com.valvesoftware.android.steam.community/files')
    except FileNotFoundError:
        return

    for account_file in account_files:
        account_json = json.load(adb.read_file(account_file))

        secret = base64.b32encode(base64.b64decode(account_json['shared_secret'])).decode('ascii')

        yield SteamAccount(account_json['account_name'], secret)


@supported_app('Aegis')
def read_aegis_accounts(adb):
    try:
        f = adb.read_file(adb.data_root/'com.beemdevelopment.aegis/files/aegis.json')
    except FileNotFoundError:
        return

    aegis = json.load(f)
    db = aegis['db']

    if db['version'] != 1:
        logger.error('Invalid Aegis DB version: %d. Only 1 is supported.', db['version'])
        return

    for entry in db['entries']:
        info = entry['info']

        if entry['type'] == 'totp':
            yield TOTPAccount(entry['name'], issuer=entry['issuer'], secret=info['secret'], algorithm=info['algo'], digits=info['digits'], period=info['period'])
        elif entry['type'] == 'hotp':
            yield HOTPAccount(entry['name'], issuer=entry['issuer'], secret=info['secret'], algorithm=info['algo'], digits=info['digits'], counter=info['counter'])
        elif entry['type'] == 'steam':
            yield SteamAccount(entry['name'], issuer=entry['issuer'], secret=info['secret'])
        else:
            logger.warning('Unknown Aegis account type: %s', entry['type'])


def read_accounts(adb, apps):
    '''
    Extracts accounts from multiple apps, removing duplicates.
    '''

    accounts = set()

    for app in apps:
        logger.info('Reading %s accounts', app.name)
        new = list(app.extractor(adb))
        old_count = len(accounts)

        for account in new:
            logger.debug('Found an account %s', account)

            # Only HOTP accounts need special treatment
            if not isinstance(account, HOTPAccount):
                accounts.add(account)
                continue

            try:
                duplicate = next(account for other in accounts if account.counterless_eq(other) and account != other)
            except StopIteration:
                accounts.add(account)
                continue

            logger.warning('Identical HOTP accounts exist with different counters: %s != %s', account, duplicate)
            logger.warning('Picking the one with the largest counter.')

            if duplicate.counter < account.counter:
                accounts.remove(duplicate)
                account.add(account)

        logger.info('Found %d accounts (%d new)', len(new), len(accounts) - old_count)

    return accounts
