## Extract Android Authenticator Tokens

Many OTP apps don't support exporting their OTP secrets. Switching apps would require you to regenerate all of your tokens, which can be tedious if you have a lot. This Python application can extract the tokens from popular Android OTP apps and export them in a standard format.

## Supports

 - Google Authenticator
 - Microsoft Authenticator
 - Authy
 - Duo Mobile
 - FreeOTP
 - AndOTP (user-assisted)

## Usage

Requires Python 3.6+ and a **rooted** Android phone.

    usage: extract_otp_tokens.py [-h] [--andotp] [--no-authy] [--no-duo]
                                 [--no-freeotp] [--no-google-authenticator]
                                 [--no-microsoft-authenticator] [--no-steam-authenticator]
                                 [--data DATA] [--no-show-uri] [--show-qr]
                                 [--andotp-backup ANDOTP_BACKUP]

    Extracts TOTP secrets from a rooted Android phone.

    optional arguments:
      -h, --help            show this help message and exit
      --andotp              parse AndOTP codes from a backup (default: False)
      --no-authy            no Authy codes (default: False)
      --no-duo              no Duo codes (default: False)
      --no-freeotp          no FreeOTP codes (default: False)
      --no-google-authenticator
                            no Google Authenticator codes (default: False)
      --no-microsoft-authenticator
                            no Microsoft Authenticator codes (default: False)
      --no-steam-authenticator
                            no Steam Authenticator codes (default: False)
                            
      --data DATA           path to the app data folder (default: /data/data)
      --no-show-uri         disables printing the accounts as otpauth:// URIs
      --show-qr             displays the accounts as a local webpage with
                            scannable QR codes (default: False)
      --andotp-backup ANDOTP_BACKUP
                            saves the accounts as an AndOTP backup file (default:
                            None)

If your phone doesn't store app data in `/data/data/`, specify the correct path with the `--data` argument. The default action is to print the codes to STDOUT. If you want to display them locally in your webbrowser as QR codes or export them as an AndOTP backup file, see the above usage information.
