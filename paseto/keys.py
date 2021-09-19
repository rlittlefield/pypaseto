import base64
import secrets
from enum import Enum
from .helpers import b64decode, b64encode, pre_auth_encode, PasetoMessage
import pysodium
from .exceptions import PasetoException, PasetoValidationError
from typing import Optional, List
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from hashlib import sha384
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import hmac


class Protocol:
    symmetric_key_byte_length: int = None
    nonce_size: int = None
    mac_size: int = None
    header: str = None
    supports_implicit_assertions = False


class Paserk:
    type = None
    paseto_compatibility = None
    wrap = False

    def __init__(self, version: int, data: bytes):
        self.version = version
        self.data = data

    def get_data(self):
        return b64encode(self.data)

    def get_id(self):
        if self.version == 3:
            pass
        elif self.version == 4:
            pass
        else:
            raise PasetoException("invalid paserk version")

    def is_key_valid_for(self, version: int, purpose: str):
        return self.version == version and purpose == self.paseto_compatibility

    def __str__(self):
        parts = ["k" + str(self.version), self.type]
        if self.prefix:
            parts.append(self.prefix)
        parts.append(self.get_data())


class PaserkLid(Paserk):
    """Unique Identifier for a separate PASERK for local PASETOs."""

    paseto_compatibility = "local"
    type = "lid"
    pass


class PaserkLocal(Paserk):
    """Symmetric key for local tokens."""

    paseto_compatibility = "local"
    type = "local"
    pass


class PaserkSeal(Paserk):
    """Symmetric key wrapped using asymmetric encryption."""

    paseto_compatibility = "local"
    type = "seal"
    pass


class PaserkLocalWrap(Paserk):
    """Symmetric key wrapped by another symmetric key."""

    paseto_compatibility = "local"
    type = "local-wrap"
    wrap = True
    prefix = "pie"
    pass


class PaserkLocalPw(Paserk):
    """Symmetric key wrapped using password-based encryption."""

    paseto_compatibility = "local"
    type = "local-pw"
    pass


class PaserkPid(Paserk):
    """Unique Identifier for a separate PASERK for public PASETOs. (Public Key)"""

    paseto_compatibility = "public"
    type = "pid"
    pass


class PaserkSid(Paserk):
    """Unique Identifier for a separate PASERK for public PASETOs. (Secret Key)"""

    paseto_compatibility = "public"
    type = "sid"
    pass


class PaserkPublic(Paserk):
    """Public key for verifying public tokens."""

    paseto_compatibility = "public"
    type = "public"
    pass


class PaserkSecret(Paserk):
    """Secret key for signing public tokens."""

    paseto_compatibility = "public"
    type = "secret"
    pass


class PaserkSecretWrap(Paserk):
    """Asymmetric secret key wrapped by another symmetric key."""

    paseto_compatibility = "public"
    type = "secret-wrap"
    wrap = True
    prefix = "pie"
    pass


class PaserkSecretPw(Paserk):
    """Asymmetric secret key wrapped using password-based encryption."""

    paseto_compatibility = "public"
    type = "secret-pw"
    pass
