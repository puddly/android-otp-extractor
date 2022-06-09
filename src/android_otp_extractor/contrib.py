import os
import json
import time
import sqlite3
import contextlib
import webbrowser

from pathlib import PurePosixPath, Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from urllib.request import pathname2url

from .otp import HOTPAccount


# https://github.com/elouajib/sqlescapy/blob/master/sqlescapy/sqlescape.py
SQL_BACKSLASHED_CHARS = str.maketrans({
    "\x00": "\\0",
    "\x08": "\\b",
    "\x09": "\\t",
    "\x1a": "\\z",
    "\n": "\\n",
    "\r": "\\r",
    "\\": "\\\\",
    "%": "\\%",
    "'": "''",
})

def escape_sql_string(text):
    """
    SQLite cannot handle parameterized PRAGMA queries so manual string escaping must be used.
    """

    return "'" + text.translate(SQL_BACKSLASHED_CHARS) + "'"


@contextlib.contextmanager
def open_remote_sqlite_database(adb, database, *, sqlite3=sqlite3):
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
    account_dicts = []
    now = int(time.time())

    for account in accounts:
        d = {
            "uri": account.as_uri(prepend_issuer),
            **account.as_andotp(),
        }

        if isinstance(account, HOTPAccount):
            d["code"] = account.generate()
        else:
            # Generate 1000 codes per account
            d["codes"] = []

            for i in range(1000):
                d["codes"].append(account.generate(now=now + account.period * i))

        account_dicts.append(d)

    accounts_html = '''<!doctype html>

<head>
    <meta charset="UTF-8" />
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
    <meta http-equiv="Pragma" content="no-cache" />
    <meta http-equiv="Expires" content="0" />

    <title>OTP QR Codes</title>

    <style type="text/css">
        body {
            color: #444444;
            font-size: 18px;
            line-height: 1.6;

            margin: 0;
            padding: 0;

            font-family: sans-serif;
        }

        img.qr {
            max-width: 500px;
            height: auto;
            width: 100%%;
        }

        .info {
            background: #4D92CE;
            color: white;

            font-size: 1.5em;
            font-weight: bold;

            padding: 1em;
        }

        .item {
            padding: 1em;
        }

        pre.uri {
            word-break: break-all;
            white-space: pre-wrap;
        }

        .wrapper {
            max-width: 800px;
            margin-left: auto;
            margin-right: auto;
        }

        .item:nth-of-type(2n + 1) {
            background: rgb(240, 240, 240);
            border-top: 1px solid rgb(220, 220, 220);
            border-bottom: 1px solid rgb(220, 220, 220);
        }

        .left {
            color: rgb(170, 170, 170);
        }

        @media print {
            .item {
                page-break-before: always;
            }
        }
    </style>
</head>

<body>
    <script src="https://unpkg.com/qrious@4.0.2/dist/qrious.min.js" integrity="sha384-Dr98ddmUw2QkdCarNQ+OL7xLty7cSxgR0T7v1tq4UErS/qLV0132sBYTolRAFuOV" crossorigin="anonymous"></script>

    <template>
        <div class="item">
            <div class="wrapper">
                <h1 class="name"></h1>
                <h2 class="code-wrapper"><code class="code"></code> <code class="left"></code></h2>
                <img class="qr" />
                <pre class="uri"></pre>
            </div>
        </div>
    </template>

    <div class="info">
        <div class="wrapper">
            <u>Note</u>: Authy's 7-digit codes have a period of 10 seconds and <a href="https://github.com/puddly/android-otp-extractor/issues/34#issuecomment-634447781">may not match what's displayed in the app</a>. This is not a bug.
        </div>
    </div>

    <script>
        let time_start = %d;
        let accounts = %s;

        let template = document.querySelector('template');

        for (let account of accounts) {
            let element = template.content.cloneNode(true).querySelector('.item');
            account.element = element;
            account.last_update = 0;

            let image = account.element.querySelector('img');
            image.removeAttribute('width');
            image.removeAttribute('height');

            let qr_image = new QRious({
                element: account.element.querySelector('img'),
                value: account.uri,
                backgroundAlpha: 0,
                size: 500
            });

            element.querySelector('.name').textContent = account.label;
            element.querySelector('.uri').textContent = account.uri;

            // HOTP accounts show just one code
            if ('code' in account) {
                account.element.querySelector('.code').textContent = account.code;
                account.element.querySelector('.left').textContent = `(counter: ${account.counter})`;
            }

            document.body.appendChild(element);
        }

        function update() {
            let now = Date.now();

            for (let account of accounts) {
                if (!('codes' in account))  continue;

                let counter = Math.floor(now / (1000 * account.period));
                let start_counter = Math.floor(time_start / (1000 * account.period));

                let next_update = (1000 * account.period) * (counter + 1);
                let code = account.codes[counter - start_counter];

                account.element.querySelector('.code').textContent = code;
                account.element.querySelector('.left').textContent = `(${Math.round((next_update - now) / 1000)}s remaining)`;
            }

            let next_second = 1000 * (1 + Math.floor(now / 1000)) - now;
            setTimeout(update, next_second);
        }

        update();
    </script>
</body>''' % (now * 1000, json.dumps(sorted(account_dicts, key=lambda a: a['uri'])))

    # Temporary files are only readable by the current user (mode 0600)
    with NamedTemporaryFile(delete=False, suffix='.html') as temp_html_file:
        temp_html_file.write(accounts_html.encode('utf-8'))

    try:
        webbrowser.open(f'file:{pathname2url(temp_html_file.name)}')
        time.sleep(10)  # webbrowser.open exits immediately so we should wait before deleting the file
    finally:
        os.remove(temp_html_file.name)
