import shlex
import base64
import logging
import hashlib
import subprocess

from io import BytesIO
from pathlib import PurePosixPath


logger = logging.getLogger(__name__)


class ADBInterface:
    END_TAG = b'3bb22bb739c29e435151cb38'

    def __init__(self, data_root):
        self.data_root = data_root

    def run(self, command, *, prefix, root=False):
        command = f'{command}; echo ' + self.END_TAG.decode('ascii')

        if root:
            command = f'su -c "{command}"'

        # `adb exec-out` doesn't work properly on some devices. We have to fall back to `adb shell`,
        # which takes at least 600ms to exit with `su` even if the actual command runs quickly.
        # Echoing a unique, non-existent string (end_tag) marks the end of
        # the stream, allowing us to let `adb shell` finish up its stuff in the background.
        lines = []
        process = subprocess.Popen(
            args=['adb', 'shell', command],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL
        )
        logger.trace('Running %s', process.args)

        for line in process.stdout:
            logger.trace('Read: %s', line)

            if line.startswith(self.END_TAG):
                return lines
            elif b': not found' in line:
                raise RuntimeError('Binary not found')

            if prefix not in line:
                lines.append(line)
                continue

            message = line.partition(prefix)[2].strip()
            process.kill()

            if b'No such file or directory' in message:
                raise FileNotFoundError()
            else:
                raise IOError(message)

        raise ValueError(f'adb command failed: {lines}')

    def list_dir(self, path):
        raise NotImplementedError()

    def read_file(self, path):
        raise NotImplementedError()

    def hash_file(self, path):
        raise NotImplementedError()


class SingleBinaryADBInterface(ADBInterface):
    def __init__(self, data_root, binary):
        super().__init__(data_root)
        self.binary = binary

    def list_dir(self, path):
        path = PurePosixPath(path)
        logger.debug('Listing directory %s', path)

        lines = self.run(f'{self.binary} ls -1 {shlex.quote(str(path))}', prefix=b'ls: ', root=True)

        # There apparently exist phones that don't use just newlines (see pull #24)
        return [path/l.rstrip(b'\r\n').decode('utf-8') for l in lines]

    def read_file(self, path):
        path = PurePosixPath(path)

        logger.debug('Trying to read file %s', path)
        lines = self.run(f'{self.binary} base64 {shlex.quote(str(path))}', prefix=b'base64: ', root=True)
        contents = base64.b64decode(b''.join(lines))
        logger.debug('Successfully read %d bytes', len(contents))

        return BytesIO(contents)

    def hash_file(self, path):
        path = PurePosixPath(path)
        logger.debug('Hashing file %s', path)

        # Assume `ls -l` only changes when the file changes
        lines = self.run(f'{self.binary} ls -l {shlex.quote(str(path))}', prefix=b'ls: ', root=True)

        # Hash both the metadata and the file's contents
        key = repr((lines, self.read_file(path).read())).encode('ascii')

        return hashlib.sha256(key).hexdigest()


def guess_adb_interface(data_root):
    for binary in ['toybox', 'busybox', '']:
        logger.info('Testing if your phone uses binary: %r', binary)

        test = SingleBinaryADBInterface(data_root, binary)

        try:
            logger.info('Listing contents of / as root')

            if not test.list_dir('/'):
                raise IOError('Directory listing of / is empty')

            logger.info('Reading and hashing contents of build.prop as root')

            if test.hash_file('$ANDROID_ROOT/build.prop') != test.hash_file('$ANDROID_ROOT/build.prop'):
                raise RuntimeError('File hashing is not consistent')
        except (IOError, RuntimeError) as e:
            logger.warning('%r is not a functional ADB interface: %s', binary, e)
            continue

        logger.info('Using ADB binary: %r', binary)
        return test

    raise RuntimeError('No supported ADB interface could be found! Install Busybox (e.g. https://f-droid.org/en/packages/ru.meefik.busybox/)')
