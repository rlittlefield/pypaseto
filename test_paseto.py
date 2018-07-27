import json

import pytest
import paseto


def _set_unit_test_only_nonce(nonce):
    """
    If you are trying to figure out how to set a nonce, DONT!

    When calling parse/create, the nonce is automatically generated
    using the libsodium functions, which are likely more secure than another
    source.

    Even when accessing PasetoV2 directly (not recommended), you should never
    need to generate your own nonce.

    The tests set a nonce because the tests need a deterministic nonce because
    they have to compare the newly generated tokens with a pre-generated token.
    """
    paseto.PasetoV2.nonce_for_unit_testing = nonce  # don't do this in your code


def _encode(o):
    """Produce a stable, compact JSON encoding"""
    return json.dumps(o, sort_keys=True, separators=(',', ':')).encode('utf8')


sym_key = bytes.fromhex('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f')
null_key = b'\0'*32
full_key = b'\xff'*32
nonce = b'\0'*24
nonce2 = bytes.fromhex('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b')
private_key = bytes.fromhex(
    'b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741'
    'eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2')
public_key = bytes.fromhex(
    '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2'
)


@pytest.mark.parametrize("token", [
    {
        'name': 'Test Vector 2E-1-1',
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ',
        'message': b'',
        'key': null_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'name': 'Test Vector 2E-1-2',
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg',
        'message': b'',
        'key': full_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'name': 'Test Vector 2E-1-3',
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA',
        'message': b'',
        'key': sym_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'name': 'Test Vector 2E-2-1',
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz',
        'message': b'',
        'key': null_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce
    },
    {
        'name': 'Test Vector 2E-2-2',
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz',
        'message': b'',
        'key': full_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce
    },
    {
        'name': 'Test Vector 2E-2-3',
        'raw': b'v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz',
        'message': b'',
        'key': sym_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce
    },
    {
        'name': 'Test Vector 2E-3-1',
        'raw': b'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0',
        'message': b'Love is stronger than hate or fear',
        'key': null_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'name': 'Test Vector 2E-3-2',
        'raw': b'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw',
        'message': b'Love is stronger than hate or fear',
        'key': full_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'name': 'Test Vector 2E-3-3',
        'raw': b'v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U',
        'message': b'Love is stronger than hate or fear',
        'key': sym_key,
        'footer': b'',
        'nonce': nonce
    },
    {
        'name': 'Test Vector 2E-4-1',
        'raw': b'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz',
        'message': b'Love is stronger than hate or fear',
        'key': null_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce2
    },
    {
        'name': 'Test Vector 2E-4-2',
        'raw': b'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz',
        'message': b'Love is stronger than hate or fear',
        'key': full_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce2
    },
    {
        'name': 'Test Vector 2E-4-3',
        'raw': b'v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz',
        'message': b'Love is stronger than hate or fear',
        'key': sym_key,
        'footer': b'Cuon Alpinus',
        'nonce': nonce2
    },
    {
        'name': 'Test Vector 2E-5',
        'raw': b'v2.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqIIhOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz',
        'message': _encode({'data': 'this is a signed message', 'expires': '2019-01-01T00:00:00+00:00'}),
        'key': sym_key,
        'footer': b'Paragon Initiative Enterprises',
        'nonce': nonce2,
    },
    {
        'name': 'Test Vector 2E-6',
        'raw': b'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
        'message': _encode({'data': 'this is a signed message', 'exp': '2019-01-01T00:00:00+00:00'}),
        'key': sym_key,
        'footer': _encode({'kid': 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN'}),
        'nonce': nonce2,
    },

    # These are the "official" test vectors
    {
        'name': 'Test Vector 2-E-1',
        'raw': b'v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ',
        'message': _encode({'data': 'this is a signed message', 'exp': '2019-01-01T00:00:00+00:00'}),
        'key': sym_key,
        'footer': b'',
        'nonce': nonce,
    },
    {
        'name': 'Test Vector 2-E-2',
        'raw': b'v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w',
        'message': _encode({'data': 'this is a secret message', 'exp': '2019-01-01T00:00:00+00:00'}),
        'key': sym_key,
        'footer': b'',
        'nonce': nonce,
    },
    {
        'name': 'Test Vector 2-E-3',
        'raw': b'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA',
        'message': _encode({'data': 'this is a signed message', 'exp': '2019-01-01T00:00:00+00:00'}),
        'key': sym_key,
        'footer': b'',
        'nonce': nonce2,
    },
    {
        'name': 'Test Vector 2-E-4',
        'raw': b'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ',
        'message': _encode({'data': 'this is a secret message', 'exp': '2019-01-01T00:00:00+00:00'}),
        'key': sym_key,
        'footer': b'',
        'nonce': nonce2,
    },
    {
        'name': 'Test Vector 2-E-5',
        'raw': b'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
        'message': _encode({'data': 'this is a signed message', 'exp': '2019-01-01T00:00:00+00:00'}),
        'key': sym_key,
        'footer': _encode({'kid': 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN'}),
        'nonce': nonce2,
    },
    {
        'name': 'Test Vector 2-E-6',
        'raw': b'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
        'message': _encode({'data': 'this is a secret message', 'exp': '2019-01-01T00:00:00+00:00'}),
        'key': sym_key,
        'footer': _encode({'kid': 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN'}),
        'nonce': nonce2,
    },
])
def test_encrypt(token):
    _set_unit_test_only_nonce(token['nonce'])
    output_token = paseto.PasetoV2.encrypt(
        plaintext=token['message'],
        key=token['key'],
        footer=token['footer'],
    )
    assert output_token == token['raw'], f"{token['name']} did not produce matching token"

    decrypted = paseto.PasetoV2.decrypt(
        token=token['raw'],
        key=token['key'],
    )
    assert decrypted['message'] == token['message'], f"{token['name']} decryption did not produce original message"
    if decrypted['footer']:
        assert decrypted['footer']== token['footer'], f"{token['name']} decryption did not produce original footer"


@pytest.mark.parametrize("token", [
    {
        'name': 'Test Vector S-1',
        'raw': b'v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA',
        'message': b'',
        'key': private_key,
        'footer': b''
    },
    {
        'name': 'Test Vector S-2',
        'raw': b'v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz',
        'message': b'',
        'key': private_key,
        'footer': b'Cuon Alpinus'
    },
    {
        'name': 'Test Vector S-3',
        'raw': b'v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM',
        'message': b'Frank Denis rocks',
        'key': private_key,
        'footer': b''
    },
    {
        'name': 'Test Vector S-4',
        'raw': b'v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML',
        'message': b'Frank Denis rockz',
        'key': private_key,
        'footer': b''
    },
    {
        'name': 'Test Vector S-5',
        'raw': b'v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz',
        'message': b'Frank Denis rocks',
        'key': private_key,
        'footer': b'Cuon Alpinus'
    },
    {
        'name': 'Test Vector S-6',
        'raw': b'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifSUGY_L1YtOvo1JeNVAWQkOBILGSjtkX_9-g2pVPad7_SAyejb6Q2TDOvfCOpWYH5DaFeLOwwpTnaTXeg8YbUwI',
        'message': _encode({'data': 'this is a signed message', 'expires': '2019-01-01T00:00:00+00:00'}),
        'key': private_key,
        'footer': b'',
    },
    {
        'name': 'Test Vector S-6',  # duplicated test vector name, see issue paragonie/paseto#85
        'raw': b'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz',
        'message': _encode({'data': 'this is a signed message', 'expires': '2019-01-01T00:00:00+00:00'}),
        'key': private_key,
        'footer': b'Paragon Initiative Enterprises',
    },
    {
        'name': 'Test Vector 2E-6',  # almost certainly the wrong name, see paragonie/paseto#85
        'raw': b'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
        'message': _encode({'data': 'this is a signed message', 'exp': '2019-01-01T00:00:00+00:00'}),
        'key': private_key,
        'footer': _encode({'kid': 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN'}),
    },

    # These are the "official" test vectors
    {
        'name': 'Test Vector 2-S-1',
        'raw': b'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw',
        'message': _encode({'data': 'this is a signed message', 'exp': '2019-01-01T00:00:00+00:00'}),
        'key': private_key,
        'footer': b'',
    },
    {
        'name': 'Test Vector 2-S-2',
        'raw': b'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
        'message': _encode({'data': 'this is a signed message', 'exp': '2019-01-01T00:00:00+00:00'}),
        'key': private_key,
        'footer': _encode({'kid': 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN'}),
    },
])
def test_sign(token):
    result = paseto.PasetoV2.sign(
        token['message'],
        token['key'],
        token['footer']
    )
    assert result == token['raw'], f"{token['name']} did not produce matching token"
    verify = paseto.PasetoV2.verify(result, public_key)
    assert verify['message'] == token['message'], f"{token['name']} verifycation did not produce original message"
    assert verify['footer'] == token['footer'], f"{token['name']} verifycation did not produce original footer"


@pytest.mark.parametrize("options", [
    {
        'claims': {
            'claim1': True,
            'claim2': 999,
            'claim3': {'nested': 'this is a string', 'array': [1, 2, 3]},
            'claim4': 'string2'
        },
        'footer': {
            'footer field': False
        },
        'key': sym_key,
        'purpose': 'local',
        'expected_header': 'v2.local',
    },
    {
        'claims': {
            'claim1': True,
            'claim2': 999,
            'claim3': {'nested': 'this is a string', 'array': [1, 2, 3]},
            'claim4': 'string2'
        },
        'footer': {
            'footer field': False
        },
        'key': private_key,
        'public_key': public_key,
        'purpose': 'public',
        'expected_header': 'v2.public',
    },
    {
        'claims': {
            'claim1': True,
            'claim2': 999,
            'claim3': {'nested': 'this is a string', 'array': [1, 2, 3]},
            'claim4': 'string2'
        },
        'footer': {
            'footer field': False
        },
        'key': sym_key,
        'purpose': 'local',
        'expected_header': 'v2.local'
    },
])
def test_create(options):
    create_params = {
        'key': options['key'],
        'purpose': options['purpose'],
        'claims': options['claims'],
        'footer': options['footer'],
    }

    token = paseto.create(**create_params)
    assert token.startswith(options['expected_header'].encode())
    parse_key = options.get('public_key', options['key'])
    parsed = paseto.parse(
        key=parse_key,
        purpose=options['purpose'],
        token=token,
    )
    assert parsed['message'] == options['claims']
    assert parsed['footer'] == options['footer']


def test_exp_claim():
    token = paseto.create(
        key=private_key,
        purpose='public',
        claims={'my claims': [1, 2, 3]},
        exp_seconds=300
    )
    parsed = paseto.parse(
        key=public_key,
        purpose='public',
        token=token,
    )
    assert parsed


def test_claim_is_expired():
    token = paseto.create(
        key=private_key,
        purpose='public',
        claims={'my claims': [1, 2, 3]},
        exp_seconds=-300
    )
    with pytest.raises(paseto.PasetoTokenExpired):
        paseto.parse(
            key=public_key,
            purpose='public',
            token=token,
        )


def test_skip_validation_on_expired():
    token = paseto.create(
        key=private_key,
        purpose='public',
        claims={'my claims': [1, 2, 3]},
        exp_seconds=-300
    )
    parsed = paseto.parse(
        key=public_key,
        purpose='public',
        token=token,
        validate=False
    )
    assert parsed


def test_required_claims():
    token = paseto.create(
        key=private_key,
        purpose='public',
        claims={'my claims': [1, 2, 3]},
        exp_seconds=-300
    )
    parsed = paseto.parse(
        key=public_key,
        purpose='public',
        token=token,
        validate=False,
        required_claims=['exp', 'my claims']
    )
    assert 'exp' in parsed['message']
    assert 'my claims' in parsed['message']

    with pytest.raises(paseto.PasetoValidationError):
        paseto.parse(
            key=public_key,
            purpose='public',
            token=token,
            validate=False,
            required_claims=['exp', 'missing']
        )
