## Extract Android Authenticator Tokens

Many OTP apps don't support exporting their OTP secrets. Switching apps would require you to regenerate all of your tokens, which can be tedious if you have a lot. This Python application can extract the tokens from popular Android OTP apps and export them in a standard format.

## Supports

 - Google Authenticator
 - Authy
 - FreeOTP

## Usage

Requires Python 3.6+ and a **rooted** Android phone.

    usage: extract_otp_tokens.py [-h] [--no-authy] [--no-authenticator]
                                 [--data DATA] [--show-uri [SHOW_URI]]
                                 [--show-qr [SHOW_QR]]
                                 [--andotp-backup ANDOTP_BACKUP]

    Extracts TOTP secrets from a rooted Android phone.

    optional arguments:
      -h, --help            show this help message and exit
      --no-authy            no Authy codes (default: False)
      --no-authenticator    no Google Authenticator codes (default: False)
      --no-freeotp          no FreeOTP codes (default: False)
      --data DATA           path to the app data folder (default: /data/data)
      --show-uri [SHOW_URI]
                            prints the accounts as otpauth:// URIs (default: True)
      --show-qr [SHOW_QR]   displays the accounts as a local webpage with
                            scannable QR codes (default: False)
      --andotp-backup ANDOTP_BACKUP
                            saves the accounts as an AndOTP backup file (default:
                            None)

If your phone doesn't store app data in `/data/data/`, specify the correct path with the `--data` argument. The default action is to print the codes to STDOUT. If you want to display them in your webbrowser as QR codes or export them as an AndOTP backup file, see the above usage information.