import os
import json
import time
import sqlite3
import contextlib
import webbrowser

from pathlib import PurePosixPath, Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from urllib.request import pathname2url


@contextlib.contextmanager
def open_remote_sqlite_database(adb, database):
    database = PurePosixPath(database)

    with TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)

        for suffix in ['', '-journal', '-wal', '-shm']:
            remote_file = database.with_name(database.name + suffix)

            try:
                contents = adb.read_file(remote_file)
            except FileNotFoundError as e:
                # Throw the original exception if the actual db file cannot be read
                if suffix == '':
                    raise e
            else:
                (temp_dir / remote_file.name).write_bytes(contents.read())

        db_path = str(temp_dir / database.name)

        with contextlib.closing(sqlite3.connect(db_path)) as connection:
            connection.row_factory = sqlite3.Row

            yield connection


def display_qr_codes(accounts, prepend_issuer=False):
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

                    var label = document.createElement('pre');
                    label.textContent = account;
                    document.body.appendChild(label);
                }
            </script>
        </body>''' % json.dumps([a.as_uri(prepend_issuer) for a in accounts])

    # Temporary files are only readable by the current user (mode 0600)
    with NamedTemporaryFile(delete=False, suffix='.html') as temp_html_file:
        temp_html_file.write(accounts_html.encode('utf-8'))

    try:
        webbrowser.open(f'file:{pathname2url(temp_html_file.name)}')
        time.sleep(10)  # webbrowser.open exits immediately so we should wait before deleting the file
    finally:
        os.remove(temp_html_file.name)
