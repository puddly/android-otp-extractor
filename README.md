## Extract Android Authenticator Tokens

Sick of Authy and Google Authenticator? Want to migrate or backup your tokens but frustrated that you can't? Now you can.

## Supports

 - Google Authenticator
 - Authy

## Usage

Requires Python 3 and a **rooted** Android phone.

    $ python extract_authenticator_tokens.py

If your phone doesn't store app data in `/data/data/`, pass the root folder as the first argument. Once all the tokens are pulled from your phone they will be printed and you can optionally open your webbrowser to display them all as QR codes for easy scanning (the QR codes are generated in your browser).
