#!/usr/bin/env python3

import base64
import struct

import libnacl


class PastException(Exception): pass
class InvalidVersionException(PastException): pass
class InvalidPurposeException(PastException): pass


def pre_auth_encode(parts):
    accumulator = struct.pack('<Q', len(parts))
    for part in parts:
        accumulator += struct.pack('<Q', len(part))
        accumulator += part
    return accumulator


class PastV2:
    version = b'v2'
    valid_purposes = [b'auth', b'enc', b'sign']

    @classmethod
    def encode_auth(cls, message, key, footer=b''):
        prefix = cls.version + b'.auth.'
        mac = libnacl.crypto_auth(pre_auth_encode([prefix, message, footer]), key)
        without_footer = prefix + base64.urlsafe_b64encode(message + mac)
        if footer:
            return without_footer + b'.' + base64.urlsafe_b64encode(footer)
        else:
            return without_footer

    @classmethod
    def decode(cls, token, key):
        version, purpose, *extra = token.split(b'.')

        if version != cls.version: raise InvalidVersionException(version)
        if purpose not in cls.valid_purposes: raise InvalidPurposeException(purpose)

        method = getattr(cls, 'decode_' + purpose.decode('ascii'))
        return method(token, key, extra)

    @classmethod
    def decode_auth(cls, token, key, extra):
        payload = base64.urlsafe_b64decode(extra[0])
        message = payload[:-32]
        mac = payload[-32:]
        footer = b''
        if len(extra) > 1:
            footer = base64.b64decode(extra[1], validate=True)

        libnacl.crypto_auth_verify(mac, pre_auth_encode([b'v2.auth.', message, footer]), key)

        return message, footer


def encode_auth(message, key, footer):
    return PastV2.encode_auth(message, key, footer)

def decode(token, key):
    return PastV2.decode(token, key)
