import pytest

from android_otp_extractor.otp import TOTPAccount, HOTPAccount, lenient_base32_decode

@pytest.mark.parametrize("unix_timestamp, expected_totp, mode", [
    # https://datatracker.ietf.org/doc/html/rfc6238, page 15
    (59,          '94287082', 'SHA1'),
    (59,          '46119246', 'SHA256'),
    (59,          '90693936', 'SHA512'),
    (1111111109,  '07081804', 'SHA1'),
    (1111111109,  '68084774', 'SHA256'),
    (1111111109,  '25091201', 'SHA512'),
    (1111111111,  '14050471', 'SHA1'),
    (1111111111,  '67062674', 'SHA256'),
    (1111111111,  '99943326', 'SHA512'),
    (1234567890,  '89005924', 'SHA1'),
    (1234567890,  '91819424', 'SHA256'),
    (1234567890,  '93441116', 'SHA512'),
    (2000000000,  '69279037', 'SHA1'),
    (2000000000,  '90698825', 'SHA256'),
    (2000000000,  '38618901', 'SHA512'),
    (20000000000, '65353130', 'SHA1'),
    (20000000000, '77737706', 'SHA256'),
    (20000000000, '47863826', 'SHA512'),
])
def test_totp(unix_timestamp, expected_totp, mode):
    # The secret depends on which algorithm is chosen
    secret = (b'1234567890' * 8)[:{
        "SHA1": 20,
        "SHA256": 32,
        "SHA512": 64,
    }[mode]]

    account = TOTPAccount(
        name='test',
        secret=secret,
        digits=8,
        period=30,
        algorithm=mode
    )

    assert account.generate(now=unix_timestamp) == expected_totp


@pytest.mark.parametrize("counter, expected_hotp", [
    # https://datatracker.ietf.org/doc/html/rfc4226, page 32
    (0, '755224'),
    (1, '287082'),
    (2, '359152'),
    (3, '969429'),
    (4, '338314'),
    (5, '254676'),
    (6, '287922'),
    (7, '162583'),
    (8, '399871'),
    (9, '520489'),
])
def test_hotp(counter, expected_hotp):
    account = HOTPAccount(
        name='test',
        secret=b"12345678901234567890",
        digits=6,
        counter=counter,
        algorithm="SHA1"
    )

    assert account.generate() == expected_hotp

@pytest.mark.parametrize("encoded, decoded", [
    ('JBSWY3DPEHPK3PXP', b'Hello!\xDE\xAD\xBE\xEF'),
])
def test_base32_parsing(encoded, decoded):
    assert lenient_base32_decode(encoded) == decoded
