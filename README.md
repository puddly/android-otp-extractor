# Android OTP Extractor

Many OTP apps don't support exporting or backing up their OTP secrets. Switching apps would require you to regenerate all of your tokens, which can be tedious if you have a lot. This application can extract your tokens from popular Android OTP apps and export them in a standard format or just display them as QR codes for easy importing.

## Supports

 - Google Authenticator
 - Microsoft Authenticator
 - Authy
 - Duo Mobile
 - FreeOTP and FreeOTP+
 - Steam Authenticator
 - AndOTP (when backups are enabled)
 - Aegis
 - Battle.net Authenticator

## Installation

```bash
$ pip install git+https://github.com/puddly/android-otp-extractor
$ python -m android_otp_extractor
```

## Usage

Requires Python 3.6+ and a **rooted** Android phone.

```
usage: python -m android_otp_extractor [-h]
                                       [--include {authy,freeotp,freeotp_plus,duo,google_authenticator,microsoft_authenticator,andotp,steam_authenticator,aegis} | --exclude {authy,freeotp,freeotp_plus,duo,google_authenticator,microsoft_authenticator,andotp,steam_authenticator,aegis}]
                                       [--data DATA]
                                       [--busybox-path BUSYBOX_PATH]
                                       [--no-show-qr] [--prepend-issuer]
                                       [--andotp-backup ANDOTP_BACKUP] [-v]

Extracts OTP secrets from a rooted Android phone.

optional arguments:
  -h, --help            show this help message and exit
  --include {authy,freeotp,freeotp_plus,duo,google_authenticator,microsoft_authenticator,andotp,steam_authenticator,aegis}
                        only export secrets from this app. Can be specified
                        multiple times. (default: None)
  --exclude {authy,freeotp,freeotp_plus,duo,google_authenticator,microsoft_authenticator,andotp,steam_authenticator,aegis}
                        do not export secrets from this app. Can be specified
                        multiple times. (default: None)
  --data DATA           path to the app data folder (default:
                        $ANDROID_DATA/data)
  --busybox-path BUSYBOX_PATH
                        path to {Busy,Toy}box supporting base64 and ls
                        (default: None)
  --no-show-qr          do not display the accounts as a local webpage with
                        scannable QR codes (default: False)
  --prepend-issuer      adds the issuer to the token name (default: False)
  --andotp-backup ANDOTP_BACKUP
                        saves the accounts as an AndOTP backup file (default:
                        None)
  -v, --verbose         increases verbosity (default: 0)
```

The default action is to extract everything and display QR codes locally in your webbrowser. Export them as an AndOTP backup file with `--andotp-backup filename.json`.
