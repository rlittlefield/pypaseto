#!/usr/bin/env python3

import base64
import struct
import secrets

import pysodium

class PasetoException(Exception): pass
class InvalidVersionException(PasetoException): pass
class InvalidPurposeException(PasetoException): pass


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
    header = b'v2.local.'

    @classmethod
    def encrypt(cls, plaintext, key, footer='', nonce_for_unit_testing=''):
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
            ad=pre_auth_encode(cls.header, nonce, footer),
            nonce=nonce,
            key=key
        )
        token = cls.header + b64encode(nonce + ciphertext)
        if footer:
            token += b'.' + b64encode(footer)
        return token

    @classmethod
    def decrypt(cls, token, key):
        parts = token.split(b'.')
        footer = b''
        if len(parts) == 4:
            encoded_footer = parts[-1]
            footer = b64decode(encoded_footer)
        header_len = len(cls.header)
        header = token[:header_len]
        if not secrets.compare_digest(header, cls.header):
            raise InvalidVersionException()
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
