#!/usr/bin/env python3

import sys
import json
import logging
import argparse

from pathlib import PurePosixPath, Path

from . import apps, TRACE
from .adb import SingleBinaryADBInterface, guess_adb_interface
from .contrib import display_qr_codes

import coloredlogs

LOGGER = logging.getLogger(__name__)


SUPPORTED_APP_NAMES = [a.simple_name for a in apps.SUPPORTED_APPS]


def main():
    logging.basicConfig(format='[%(asctime)s] %(levelname)8s [%(funcName)s:%(lineno)d] %(message)s')

    parser = argparse.ArgumentParser(
        prog='python -m android_otp_extractor',
        description='Extracts TOTP secrets from a rooted Android phone.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--include', action='append', choices=SUPPORTED_APP_NAMES, help='only export secrets from this app. Can be specified multiple times.')
    group.add_argument('--exclude', action='append', choices=SUPPORTED_APP_NAMES, help='do not export secrets from this app. Can be specified multiple times.')

    parser.add_argument('--data', type=PurePosixPath, default=PurePosixPath('$ANDROID_DATA/data/'), help='path to the app data folder')
    parser.add_argument('--busybox-path', type=PurePosixPath, default=None, help='path to {Busy,Toy}box supporting base64 and ls')

    parser.add_argument('--no-show-qr', action='store_true', help='do not display the accounts as a local webpage with scannable QR codes')

    parser.add_argument('--prepend-issuer', action='store_true', help='adds the issuer to the token name')
    parser.add_argument('--andotp-backup', type=Path, help='saves the accounts as an AndOTP backup file')

    parser.add_argument('-v', '--verbose', dest='verbose', action='count', default=0, help='increases verbosity')

    args = parser.parse_args()

    log_level = [logging.INFO, logging.DEBUG, TRACE][min(max(0, args.verbose), 2)]
    LOGGER.parent.setLevel(log_level)
    coloredlogs.install(level=log_level)

    if args.busybox_path is not None:
        adb = SingleBinaryADBInterface(args.data, args.busybox_path)
    else:
        adb = guess_adb_interface(args.data)

    if args.include:
        enabled_apps = [a for a in apps.SUPPORTED_APPS if a.simple_name in args.include]
    elif args.exclude:
        enabled_apps = [a for a in apps.SUPPORTED_APPS if a.simple_name not in args.exclude]
    else:
        enabled_apps = apps.SUPPORTED_APPS

    accounts = apps.read_accounts(adb, enabled_apps)

    for account in accounts:
        LOGGER.info('Found account: %s', account.as_uri(args.prepend_issuer))

    if not args.no_show_qr and accounts:
        display_qr_codes(accounts, args.prepend_issuer)

    if args.andotp_backup:
        args.andotp_backup.write_text(json.dumps([a.as_andotp() for a in accounts]))
