## Extract Android Authenticator Tokens

Many OTP apps don't support exporting their OTP secrets. Switching apps would require you to regenerate all of your tokens, which can be tedious if you have a lot. This Python application can extract the tokens from popular Android OTP apps and export them in a standard format.

## Supports

 - Google Authenticator
 - Microsoft Authenticator
 - Authy
 - Duo Mobile
 - FreeOTP
 - Steam Authenticator
 - AndOTP (when encrypted backups are enabled)

## Installation

 - Make sure Python3 is installed
   - on Mac, you can do so with `brew install python3` (provided [HomeBrew](https://brew.sh/) is already installed)
 - Clone the repo or just download [the main script](https://raw.githubusercontent.com/puddly/android-otp-extractor/master/extract_otp_tokens.py)
 - Make it executable with `chmod +x extract_otp_tokens.py`

## Usage

Requires Python 3.6+ and a **rooted** Android phone. Parsing encrypted AndOTP backups (recommended) requires [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/installation.html).

    usage: extract_otp_tokens.py [-h] [--no-andotp] [--no-authy] [--no-duo]
                                 [--no-freeotp] [--no-google-authenticator]
                                 [--no-microsoft-authenticator]
                                 [--no-steam-authenticator] [--data DATA]
                                 [--no-show-uri] [--show-qr] [--prepend-issuer]
                                 [--andotp-backup ANDOTP_BACKUP] [-v]

    Extracts TOTP secrets from a rooted Android phone.

    optional arguments:
      -h, --help            show this help message and exit
      --no-andotp           do not create and parse an AndOTP backup (default:
                            False)
      --no-authy            no Authy codes (default: False)
      --no-duo              no Duo codes (default: False)
      --no-freeotp          no FreeOTP codes (default: False)
      --no-google-authenticator
                            no Google Authenticator codes (default: False)
      --no-microsoft-authenticator
                            no Microsoft Authenticator codes (default: False)
      --no-steam-authenticator
                            no Steam Authenticator codes (default: False)
      --data DATA           path to the app data folder (default:
                            $ANDROID_DATA/data)
      --no-show-uri         disable printing the accounts as otpauth:// URIs
                            (default: False)
      --show-qr             displays the accounts as a local webpage with
                            scannable QR codes (default: False)
      --prepend-issuer      adds the issuer to the token name (default: False)
      --andotp-backup ANDOTP_BACKUP
                            saves the accounts as an AndOTP backup file (default:
                            None)
      -v, --verbose         increases verbosity (default: 0)

If your phone doesn't store app data in `$ANDROID_DATA/data/`, specify the correct path with the `--data` argument. The default action is to print the codes to STDOUT. If you want to display them locally in your webbrowser as QR codes or export them as an AndOTP backup file, see the above usage information.
