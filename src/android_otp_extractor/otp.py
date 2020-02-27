import base64

from urllib.parse import quote, urlencode


def normalize_secret(secret):
    if set(secret.lower()) <= set('0123456789abcdef'):
        return base64.b32encode(bytes.fromhex(secret)).decode('ascii').rstrip('=')
    else:
        return secret.upper().rstrip('=')


class OTPAccount:
    type = None

    def __init__(self, name, secret, issuer=None):
        self.name = name
        self.secret = normalize_secret(secret)
        self.issuer = issuer

    def __hash__(self):
        return hash(self.as_uri())

    def __eq__(self, other):
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

    def uri_params(self):
        return {
            'digits': self.digits,
            'period': self.period,
            'algorithm': self.algorithm
        }


class SteamAccount(TOTPAccount):
    type = 'steam'

    def __init__(self, name, secret, issuer=None):
        super().__init__(name, secret, issuer, digits=5)
