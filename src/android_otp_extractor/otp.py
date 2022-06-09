"""
Implementations of common OTP algorithms.
"""

from __future__ import annotations

import time
import hmac
import base64
import hashlib

from urllib.parse import quote, urlencode

HASHING_ALGORITHMS = {
    'SHA1': hashlib.sha1,
    'SHA256': hashlib.sha256,
    'SHA512': hashlib.sha512,
}


def lenient_base32_decode(data: str) -> bytes:
    # Pad it to a multiple of 8
    data = data.rstrip('=') + '=' * ((8 - len(data) % 8) % 8)

    return base64.b32decode(data)


def _hotp_helper(key: bytes, msg: bytes, digits: int, algorithm: str, alphabet: str) -> str:
    digest = hmac.digest(
        key=key,
        msg=msg,
        digest=HASHING_ALGORITHMS[algorithm],
    )

    offset = digest[-1] & 0b1111
    extracted = int.from_bytes(digest[offset:offset + 4], 'big') & 0b01111111111111111111111111111111

    result = ''

    for i in range(digits):
        extracted, remainder = divmod(extracted, len(alphabet))
        result += alphabet[remainder]

    return result[::-1]


def rfc4226_hotp(secret: bytes, counter: int, digits: int, algorithm: str, alphabet: str) -> str:
    return _hotp_helper(
        key=secret,
        msg=counter.to_bytes(8, 'big'),
        digits=digits,
        algorithm=algorithm,
        alphabet=alphabet,
    )


def authy_hotp(secret: bytes, counter: int, digits: int, algorithm: str, alphabet: str) -> str:
    """
    Standards-violating HOTP algorithm used by Authy's Android app.
    """

    return _hotp_helper(
        key=secret.hex().encode('ascii'),  # The secret encoded as hex in ASCII is used as the key
        msg=str(counter).encode('ascii'),  # The counter is also encoded in ASCII as a base-10 number
        digits=digits,
        algorithm=algorithm,
        alphabet=alphabet,
    )


class OTPAccount:
    type = None
    alphabet = '0123456789'

    def __init__(self, name, secret, issuer=None):
        self.name = name
        self._secret = secret
        self.issuer = issuer

    @property
    def secret(self) -> str:
        return base64.b32encode(self._secret).decode('ascii').rstrip('=')

    def __hash__(self):
        return hash(self.as_uri())

    def __eq__(self, other) -> bool:
        return self.type == other.type and self.name == other.name and self.secret == other.secret

    def as_andotp(self):
        return {
            'secret': self.secret,
            'label': self.name,
            'type': self.type.upper()
        }

    def uri_params(self):
        raise NotImplementedError()

    def as_uri(self, prepend_issuer=False):
        params = {k: str(v) for k, v in self.uri_params().items()}
        params['secret'] = self.secret

        if self.issuer:
            params['issuer'] = self.issuer

        if prepend_issuer and self.issuer:
            name = f'{self.issuer}: {self.name}'
        else:
            name = self.name or 'Unknown'

        return f'otpauth://{self.type}/{quote(name)}?' + urlencode(sorted(params.items()))

    def generate(self):
        raise NotImplementedError()

    def __repr__(self):
        args = ', '.join(f'{k}={v!r}' for k, v in self.as_andotp().items() if k != 'type')

        return f'<{self.__class__.__name__}({args})>'


class HOTPAccount(OTPAccount):
    type = 'hotp'

    def __init__(self, name, secret, counter, issuer=None, digits=6, algorithm='SHA1'):
        super().__init__(name, secret, issuer)
        self.counter = counter
        self.digits = digits
        self.algorithm = algorithm

    def as_andotp(self):
        return {**super().as_andotp(), **self.uri_params()}

    def counterless_eq(self, other):
        return super().__eq__(other) and self.digits == other.digits and self.algorithm == other.algorithm

    def generate(self):
        return rfc4226_hotp(
            secret=self._secret,
            counter=self.counter,
            digits=self.digits,
            algorithm=self.algorithm,
            alphabet=self.alphabet,
        )

    def uri_params(self):
        return {
            'counter': self.counter,
            'digits': self.digits,
            'algorithm': self.algorithm
        }


class TOTPAccount(OTPAccount):
    type = 'totp'

    def __init__(self, name, secret, issuer=None, digits=6, period=30, algorithm='SHA1'):
        super().__init__(name, secret, issuer)
        self.digits = digits
        self.period = period
        self.algorithm = algorithm

    def as_andotp(self):
        return {**super().as_andotp(), **self.uri_params()}

    def generate(self, *, now=None):
        if now is None:
            now = time.time()

        return rfc4226_hotp(
            secret=self._secret,
            counter=int(now // self.period),
            digits=self.digits,
            algorithm=self.algorithm,
            alphabet=self.alphabet,
        )

    def uri_params(self):
        return {
            'digits': self.digits,
            'period': self.period,
            'algorithm': self.algorithm
        }


class SteamAccount(TOTPAccount):
    type = 'steam'
    alphabet = '23456789BCDFGHJKMNPQRTVWXY'

    def __init__(self, name, secret, issuer=None):
        super().__init__(name, secret, issuer, digits=5)


class AuthyAccount(TOTPAccount):
    type = 'authy'

    def generate(self, *, now=None):
        if now is None:
            now = time.time()

        return authy_hotp(
            secret=self._secret,
            counter=int(now // self.period),
            digits=self.digits,
            algorithm=self.algorithm,
            alphabet=self.alphabet,
        )