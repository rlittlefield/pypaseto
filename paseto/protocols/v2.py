import pysodium
from paseto.helpers import (
    pre_auth_encode,
    b64decode,
    b64encode,
    validate_and_remove_footer,
    remove_footer,
    PasetoMessage,
)
from paseto.exceptions import *
from .protocol import Protocol
from typing import Optional
import secrets


class ProtocolVersion2(Protocol):
    symmetric_key_byte_length = 32
    nonce_size = pysodium.crypto_aead_xchacha20poly1305_ietf_NONCEBYTES
    mac_size = 32
    sign_size = 64
    header = b"v2"

    @classmethod
    def generate_asymmetric_secret_key(cls):
        from paseto.keys.asymmetric_key import AsymmetricSecretKey

        return AsymmetricSecretKey.generate(protocol=cls)

    @classmethod
    def generate_symmetric_key(cls):
        from paseto.keys.symmetric_key import SymmetricKey

        return SymmetricKey.generate(protocol=cls)

    @classmethod
    def encrypt(cls, data: bytes, key, footer="", implicit=""):
        return cls._encrypt(data, key, footer, implicit)

    @classmethod
    def _encrypt(
        cls, data: bytes, key, footer="", implicit="", _nonce_for_unit_testing=""
    ):
        if key.protocol is not cls:
            raise InvalidVersionException(
                "The given key is not intended for this version of PASETO."
            )

        return cls.aead_encrypt(
            data=data,
            header=cls.header + b".local.",
            key=key,
            footer=footer,
            implicit=implicit,
            _nonce_for_unit_testing=_nonce_for_unit_testing,
        )

    @classmethod
    def decrypt(
        cls,
        data: bytes,
        key,
        footer: Optional[bytes] = None,
        implicit: bytes = "",
    ):
        if key.protocol is not cls:
            raise InvalidVersionException(
                "The given key is not intended for this version of PASETO."
            )
        if key.key_type != "local":
            raise InvalidPurposeException(
                "The given key is not intended for this purpose."
            )

        if footer is None:
            data, footer = extract_footer(data)
        else:
            data = validate_and_remove_footer(data, footer)

        return cls.aead_decrypt(
            message=data,
            header=cls.header + b".local.",
            key=key,
            footer=footer,
            implicit=implicit,
        )

    @classmethod
    def sign(cls, data: bytes, key, footer: bytes = "", implicit=""):
        if key.protocol is not cls:
            raise PasetoException(
                "The given key is not intended for this version of PASETO."
            )

        header = cls.header + b".public."

        signature = pysodium.crypto_sign_detached(
            pre_auth_encode(header, data, footer), key.key
        )

        return bytes(
            PasetoMessage(header=header, payload=data + signature, footer=footer)
        )

    @classmethod
    def verify(cls, sign_msg: bytes, key, footer: Optional[bytes] = None, implicit=""):
        if key.protocol is not cls:
            raise PasetoException(
                "The given key is not intended for this version of PASETO."
            )
        if footer is None:
            footer = extract_footer(sign_msg)
        else:
            sign_msg = validate_and_remove_footer(sign_msg, footer)

        sign_msg = remove_footer(sign_msg)

        expect_header = cls.header + b".public."
        header_length = len(expect_header)
        given_header = sign_msg[:header_length]
        if not secrets.compare_digest(expect_header, given_header):
            raise PasetoException("Invalid message header.")

        decoded = b64decode(sign_msg[header_length:])
        decoded_len = len(decoded)
        message = decoded[: decoded_len - cls.sign_size]
        signature = decoded[decoded_len - cls.sign_size :]

        try:
            pysodium.crypto_sign_verify_detached(
                signature, pre_auth_encode(given_header, message, footer), key.key
            )
            return message
        except:
            raise PasetoException("Invalid signature for this message")

    @classmethod
    def aead_encrypt(
        cls,
        data,
        header: bytes,
        key,
        footer: bytes = b"",
        implicit: bytes = b"",
        _nonce_for_unit_testing: bytes = b"",
    ):
        if _nonce_for_unit_testing:
            nonce = _nonce_for_unit_testing
        else:
            nonce = secrets.token_bytes(cls.nonce_size)

        nonce = pysodium.crypto_generichash(
            data,
            k=nonce,
            outlen=pysodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
        )

        ciphertext = pysodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            message=data,
            ad=pre_auth_encode(header, nonce, footer),
            nonce=nonce,
            key=key.key,
        )

        return bytes(
            PasetoMessage(header=header, payload=nonce + ciphertext, footer=footer)
        )

    @classmethod
    def aead_decrypt(cls, message, header, key, footer="", implicit=""):
        expected_len = len(header)
        given_header = message[:expected_len]
        if not secrets.compare_digest(header, given_header):
            raise PasetoException("Invalid message header.")

        try:
            decoded = b64decode(message[expected_len:])
        except:
            raise PasetoException("Invalid encoding detected")

        nonce = decoded[: pysodium.crypto_aead_xchacha20poly1305_ietf_NONCEBYTES]
        ciphertext = decoded[pysodium.crypto_aead_xchacha20poly1305_ietf_NONCEBYTES :]
        plaintext = pysodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext=ciphertext,
            ad=pre_auth_encode(header, nonce, footer),
            nonce=nonce,
            key=key.key,
        )
        return plaintext
