#!/usr/bin/env python3

import base64
import struct
import secrets
import json
import pysodium
import pendulum


class PasetoException(Exception): pass
class InvalidVersionException(PasetoException): pass
class InvalidPurposeException(PasetoException): pass
class InvalidTokenException(PasetoException): pass
class PasetoValidationError(PasetoException): pass
class PasetoTokenExpired(PasetoValidationError): pass


DEFAULT_RULES = {'exp'}


def pre_auth_encode(*parts):
    accumulator = struct.pack('<Q', len(parts))
    for part in parts:
        accumulator += struct.pack('<Q', len(part))
        accumulator += part
    return accumulator


def b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def b64decode(data):
    return base64.urlsafe_b64decode(data + b'=' * (-len(data) % 4))


class PasetoV2:
    """
    This class provides the basic encrypt/decrypt, sign/verify functionality
    for the underlying v2 protocol of paseto. It doesn't handle verification
    of claims, just the cryptographic verification and base64 decoding.

    Please use the "create" and "parse" functions, which will handle parsing
    and validating registered claims, as well as JSON encode/decode for you.
    """
    version = b'v2'
    valid_purposes = [b'local', b'public']
    local_header = b'v2.local.'
    public_header = b'v2.public.'
    nonce_for_unit_testing = None

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes,
        key: bytes,
        footer=b'',
    ) -> bytes:
        if cls.nonce_for_unit_testing:
            nonce = cls.nonce_for_unit_testing
            cls.nonce_for_unit_testing = None
        else:
            nonce = pysodium.randombytes(pysodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
        nonce = pysodium.crypto_generichash(
            plaintext,
            k=nonce,
            outlen=pysodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
        )
        ciphertext = pysodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            message=plaintext,
            ad=pre_auth_encode(cls.local_header, nonce, footer),
            nonce=nonce,
            key=key
        )
        token = cls.local_header + b64encode(nonce + ciphertext)
        if footer:
            token += b'.' + b64encode(footer)
        return token

    @classmethod
    def decrypt(cls, token: bytes, key: bytes) -> dict:
        parts = token.split(b'.')
        footer = b''
        if len(parts) == 4:
            encoded_footer = parts[-1]
            footer = b64decode(encoded_footer)
        header_len = len(cls.local_header)
        header = token[:header_len]
        token_version = token[:2]
        if not secrets.compare_digest(token_version, cls.version):
            raise InvalidVersionException('not a v2 token')
        if not secrets.compare_digest(header, cls.local_header):
            raise InvalidPurposeException('not a v2.local token')
        decoded = b64decode(parts[2])
        nonce = decoded[:pysodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]
        ciphertext = decoded[pysodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:]
        plaintext = pysodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext=ciphertext,
            ad=pre_auth_encode(header, nonce, footer),
            nonce=nonce,
            key=key
        )
        return {
            'message': plaintext,
            'footer': footer if footer else None
        }

    @classmethod
    def sign(cls, data, key, footer=b''):
        signature = pysodium.crypto_sign_detached(
            m=pre_auth_encode(cls.public_header, data, footer),
            sk=key
        )
        token = cls.public_header + b64encode(data + signature)
        if footer:
            token += b'.' + b64encode(footer)
        return token

    @classmethod
    def verify(cls, token, key):
        token_header = token[:len(cls.public_header)]
        token_version = token[:2]
        if not secrets.compare_digest(token_version, cls.version):
            raise InvalidVersionException('not a v2 token')
        if not secrets.compare_digest(token_header, cls.public_header):
            raise InvalidPurposeException('not a v2.public token')
        parts = token.split(b'.')
        footer = b''
        if len(parts) == 4:
            encoded_footer = parts[-1]
            footer = b64decode(encoded_footer)
        decoded = b64decode(parts[2])
        message = decoded[:-pysodium.crypto_sign_BYTES]
        signature = decoded[-pysodium.crypto_sign_BYTES:]
        try:
            pysodium.crypto_sign_verify_detached(
                sig=signature,
                msg=pre_auth_encode(token_header, message, footer),
                pk=key
            )
        except ValueError as e:
            raise InvalidTokenException('invalid signature') from e
        return {'message': message, 'footer': footer}


class JsonEncoder(object):
    @classmethod
    def dumps(cls, var):
        return json.dumps(var).encode('utf8')

    @classmethod
    def loads(cls, var):
        return json.loads(var)


def create(
    key,
    purpose: str,
    claims: dict,
    exp_seconds=None,
    footer=None,
    encoder=JsonEncoder,
):
    """
    Creates a new paseto token using the provided key, purpose, and claims.

    The exp claim is registered. To set it manually, leave the `exp_seconds`
    parameter as None, and manually put it into your claims dict. Otherwise,
    it acts as a number-of-seconds-from-now and is dynamically calculated when
    the token is made.

    You may pass an alternative encoder if you don't want to use JSON. It
    should have loads/dumps methods available, and output a bytes object (not
    a str).
    :param key:
    :param purpose:
    :param claims: dict of the claims to include in the token
    :param exp_seconds: number of seconds from now before expiration
    :param footer: dict of the footer that will be authenticated but not encrypted
    :param encoder: encoder to use if you don't want the default JSON encoder
    :return:
    """
    if purpose not in {'local', 'public'}:
        raise InvalidPurposeException('invalid purpose')
    if not key:
        raise ValueError('key is required')

    if exp_seconds:
        then = pendulum.now().add(seconds=exp_seconds).to_atom_string()
        claims['exp'] = then

    encoded = encoder.dumps(claims)
    encoded_footer = encoder.dumps(footer) if footer else b''

    if purpose == 'local':
        token = PasetoV2.encrypt(
            plaintext=encoded,
            key=key,
            footer=encoded_footer,
        )
    elif purpose == 'public':
        token = PasetoV2.sign(
            data=encoded,
            key=key,
            footer=encoded_footer,
        )
    else:
        raise InvalidPurposeException('invalid purpose')
    return token


def _extract_footer_unsafe(token):
    """
    Gets the footer out of a token. Useful if you need to use the footer to
    determine which key to load up, for example. This is performed on the
    UNVALIDATED FOOTER. So you shouldn't use this in place of actually
    validating the token afterwards:

        token = '...'
        footer = paseto.extract_footer_unvalidated(token)
        # json decode manually here if you need to
        key_id = json.loads(footer)['key_id']
        key = key_system.get_key_by_id(key_id) # fetch the key here
        parsed = paseto.parse(
            key=key,
            purpose='local',
            token=token,
        )

    If for some reason you are putting claims in the footer, do not use this!
    You still need to call "parse" so the signature can be verified.

    You should also never use this function to get the key itself out of the
    footer. Even if the key is the public key, you should NEVER load a key
    out of the footer through this function. It is only suitable to read a
    key-id from the footer, and to then perform a lookup to find the right key.

    :param token:
    :return:
    """
    parts = token.split(b'.')
    if len(parts) < 4:
        return None
    return b64decode(parts[3])


def parse(
    key,
    purpose: str,
    token: bytes,
    encoder=JsonEncoder,
    validate: bool = True,
    rules=None,
    required_claims=None
):
    """
    Parse a paseto token.
    Takes a key, a purpose (which must be either 'local' or 'public'), and
    a `token`, which must be a bytes object.

    By default, it validates known registered claims (currently just 'exp').
    To disable validation, set "validate" to False. Cryptographic validity
    cannot be turned off (decryption and authentication are still performed).

    You can also turn on/off validation of specific rules by passing a list to
    "rules". If you pass an empty list to "rules", you must also specify
    "validate=False" or it will raise an exception.

    You may pass an alternative encoder if you don't want to use JSON. It
    should have loads/dumps methods available, and output a bytes object (not
    a str).
    :param key: decryption/validation key. Must match the purpose type
    :param purpose: one of 'local', 'public'
    :param token: bytes object with the raw paseto token
    :param encoder: optional encoder to use instead of JSON
    :param validate: bool indicating if claims should be validated with rules
    :param rules: list of rule names to apply to override the default rules
    :param required_claims: list of claim names that must be present (like exp)
    :return:
    """
    if purpose not in {'local', 'public'}:
        raise InvalidPurposeException('invalid purpose')
    if not key:
        raise ValueError('key is required')
    if purpose == 'local':
        result = PasetoV2.decrypt(token, key)
    else:
        result = PasetoV2.verify(token, key)
    decoded_message = encoder.loads(result['message'])
    decoded_footer = encoder.loads(result['footer']) if result['footer'] else None

    if required_claims:
        missing_claims = set(required_claims).difference(set(decoded_message.keys()))
        if missing_claims:
            raise PasetoValidationError(f'required claims missing {missing_claims}')

    rules = DEFAULT_RULES if not rules else set(rules)
    if validate and not rules:
        raise ValueError('must set validate=False to use no rules')

    rule_set = {'exp'}
    unknown_rules = rules.difference(rule_set)
    if unknown_rules:
        raise ValueError(f'unknown rules: {unknown_rules}')

    if validate:
        # validate all the claims
        if 'exp' in rules and 'exp' in decoded_message:
            # validate expiration
            exp = decoded_message['exp']
            when = pendulum.parse(exp)
            if pendulum.now() > when:
                raise PasetoTokenExpired('token expired')
    return {'message': decoded_message, 'footer': decoded_footer}

