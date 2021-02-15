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

                    max-width: 800px;
                    margin-left: auto;
                    margin-right: auto;

                    padding: 2em;
                }

                img.qr {
                    max-width: 500px;
                    height: auto;
                    width: 100%%;
                }

                .info {
                    color: #4D92CE;
                    text-align: center;
                    margin-bottom: 10px;
                }

                pre.uri {
                    word-break: break-all;
                    white-space: pre-wrap;
                }

                .item:not(:last-of-type) {
                    margin-bottom: 50px;
                    padding-bottom: 50px;
                    border-bottom: 1px solid #EEEEEE;
                }

                .left {
                    color: rgb(170, 170, 170);
                }
                @media print {
                    .pagebreak { page-break-before: always; }
                }
            </style>
        </head>

        <body>
            <script src="https://unpkg.com/qrious@4.0.2/dist/qrious.min.js" integrity="sha384-Dr98ddmUw2QkdCarNQ+OL7xLty7cSxgR0T7v1tq4UErS/qLV0132sBYTolRAFuOV" crossorigin="anonymous"></script>
            <script src="https://unpkg.com/@otplib/preset-browser@12.0.1/buffer.js" integrity="sha384-NhS3AxwDg2QutVV/6mhT3YMDIi0COa3DMRrKJ28dASNnltnsL65lEMS+lfC5CKK9" crossorigin="anonymous"></script>
            <script src="https://unpkg.com/@otplib/preset-browser@12.0.1/index.js" integrity="sha384-d4ckAJIrPG6rCB/5gBX68DepjontMupkR+V6gIE38XtUX65BNJZV+wRYrzF0GDSG" crossorigin="anonymous"></script>

            <template>
                <div class="pagebreak"> </div>
                <div class="item">
                    <h1 class="name"></h1>
                    <h2 class="code-wrapper"><code class="code"></code> <code class="left"></code></h2>
                    <img class="qr" />
                    <pre class="uri"></pre>
                </div>
            </template>

            <h3 class="info">Note: Authy's 7-digit codes have a period of 10 seconds and will not match what's displayed in the app. This is not a bug.</h3>

            <script>
                var accounts = %s;
                var template = document.querySelector('template');

                for (var i = 0; i < accounts.length; i++) {
                    var account = accounts[i];
                    var url = new URL(account);
                    var element = template.content.cloneNode(true);
                    var params = new URLSearchParams(url.search);
                    var [type, name] = url.pathname.replace('//', '').split('/', 2);

                    element.querySelector('.name').textContent = decodeURIComponent(name);
                    element.querySelector('.uri').textContent = account;

                    var image = element.querySelector('img');

                    var qr_image = new QRious({
                        element: image,
                        value: account,
                        size: 500
                    });

                    image.removeAttribute('width');
                    image.removeAttribute('height');

                    var code = element.querySelector('.code')
                    var left = element.querySelector('.left')

                    if (type === 'hotp') {
                        window.otplib.hotp.options = {
                            digits: parseInt(params.get('digits'), 10),
                        };

                        var secret = window.otplib.authenticator.encode(params.get('secret'));

                        code.textContent = window.otplib.hotp.generate(
                            secret,
                            parseInt(params.get('counter'), 10)
                        );

                        left.textContent = '(counter: ' + params.get('counter') + ')';

                        window.otplib.hotp.resetOptions();
                    } else {
                        var callback = function(params, code, left) {
                            var secret = params.get('secret');
                            var period = parseInt(params.get('period'), 10);
                            var now = +(Date.now()) / 1000;
                            var next_period = Math.ceil(now / period) * period;

                            window.otplib.authenticator.options = {
                                digits: parseInt(params.get('digits'), 10),
                                step: period,
                            };

                            code.textContent = window.otplib.authenticator.generate(secret);
                            left.textContent = '(' + (next_period - now).toFixed(0) + 's)';

                            window.otplib.authenticator.resetOptions();
                        }

                        callback(params, code, left);
                        setInterval(callback, 1000, params, code, left);
                    }

                    document.body.appendChild(element);
                }
            </script>
        </body>''' % json.dumps(sorted([a.as_uri(prepend_issuer) for a in accounts]))

    # Temporary files are only readable by the current user (mode 0600)
    with NamedTemporaryFile(delete=False, suffix='.html') as temp_html_file:
        temp_html_file.write(accounts_html.encode('utf-8'))

    try:
        webbrowser.open(f'file:{pathname2url(temp_html_file.name)}')
        time.sleep(10)  # webbrowser.open exits immediately so we should wait before deleting the file
    finally:
        os.remove(temp_html_file.name)
