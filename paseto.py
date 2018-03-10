#!/usr/bin/env python3

import base64
import struct
import secrets

import pysodium

class PasetoException(Exception): pass
class InvalidVersionException(PasetoException): pass
class InvalidPurposeException(PasetoException): pass
class InvalidTokenException(PasetoException): pass


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
    version = b'v2'
    valid_purposes = [b'local', b'public']
    local_header = b'v2.local.'
    public_header = b'v2.public.'

    @classmethod
    def encrypt(cls, plaintext: bytes, key: bytes, footer=b'', nonce_for_unit_testing='') -> bytes:
        if nonce_for_unit_testing:
            nonce = nonce_for_unit_testing
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
