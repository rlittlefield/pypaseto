import pysodium
from paseto.helpers import (
    pre_auth_encode,
    b64decode,
    b64encode,
    validate_and_remove_footer,
    PasetoMessage,
    _extract_footer_unsafe,
    remove_footer,
)
from paseto.exceptions import *
from .protocol import Protocol
from typing import Optional
import secrets

x = pysodium.crypto_stream_xchacha20_NONCEBYTES


class ProtocolVersion4(Protocol):
    symmetric_key_byte_length = 32
    nonce_size = 32
    mac_size = 32
    sign_size = pysodium.crypto_sign_BYTES
    header = b"v4"

    @classmethod
    def generate_asymmetric_secret_key(cls):
        from paseto.keys.asymmetric_key import AsymmetricSecretKey

        return AsymmetricSecretKey.generate(protocol=cls)

    @classmethod
    def generate_symmetric_key(cls):
        from paseto.keys.symmetric_key import SymmetricKey

        return SymmetricKey.generate(protocol=cls)

    @classmethod
    def encrypt(cls, data, key, footer=b"", implicit=b""):
        return cls._encrypt(data, key, footer, implicit)

    @classmethod
    def _encrypt(cls, data, key, footer=b"", implicit=b"", _nonce_for_unit_testing=b""):
        if key.protocol is not cls:
            raise InvalidVersionException(
                "The given key is not intended for this version of PASETO."
            )
        return cls.aead_encrypt(
            plaintext=data,
            header=cls.header + b".local.",
            key=key,
            footer=footer,
            implicit=implicit,
            _nonce_for_unit_testing=_nonce_for_unit_testing,
        )

    @classmethod
    def decrypt(cls, data, key, footer: Optional[bytes] = None, implicit: bytes = b""):
        if key.protocol is not cls:
            raise InvalidVersionException(
                "The given key is not intended for this version of PASETO."
            )
        if key.key_type != "local":
            raise InvalidPurposeException(
                "The given key is not intended for this purpose."
            )

        if footer is None:
            footer = _extract_footer_unsafe(data)
            data = remove_footer(data)
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
    def aead_encrypt(
        cls,
        plaintext: bytes,
        header: bytes,
        key,
        footer=b"",
        implicit=b"",
        _nonce_for_unit_testing=b"",
    ):
        if _nonce_for_unit_testing:
            nonce = _nonce_for_unit_testing
        else:
            nonce = secrets.token_bytes(cls.nonce_size)

        enc_key, auth_key, nonce2 = key.splitV4(nonce)
        ciphertext = pysodium.crypto_stream_xchacha20_xor(plaintext, nonce2, enc_key)
        if not ciphertext:
            raise PasetoException("Encryption failed")
        mac = pysodium.crypto_generichash(
            pre_auth_encode(header, nonce, ciphertext, footer, implicit), auth_key
        )

        return bytes(
            PasetoMessage(
                header=header, payload=nonce + ciphertext + mac, footer=footer
            )
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

        decoded_len = len(decoded)
        nonce = decoded[: cls.nonce_size]
        ciphertext = decoded[cls.nonce_size : -cls.mac_size]
        mac = decoded[-cls.mac_size :]
        enc_key, auth_key, nonce2 = key.splitV4(nonce)
        calc = pysodium.crypto_generichash(
            pre_auth_encode(header, nonce, ciphertext, footer, implicit), auth_key
        )
        if not secrets.compare_digest(calc, mac):
            raise PasetoException("Invalid MAC for given ciphertext.")

        plaintext = pysodium.crypto_stream_xchacha20_xor(ciphertext, nonce2, enc_key)
        if not plaintext:
            raise PasetoException("Encryption failed.")
        return plaintext

    @classmethod
    def sign(cls, data: bytes, key, footer: bytes = b"", implicit: bytes = b""):
        if key.protocol is not cls:
            raise PasetoException(
                "The given key is not intended for this version of PASETO."
            )

        header = cls.header + b".public."

        signature = pysodium.crypto_sign_detached(
            pre_auth_encode(header, data, footer, implicit), key.key
        )

        return bytes(
            PasetoMessage(header=header, payload=data + signature, footer=footer)
        )

    @classmethod
    def verify(
        cls, sign_msg: bytes, key, footer: Optional[bytes] = None, implicit: bytes = b""
    ):
        if key.protocol is not cls:
            raise PasetoException(
                "The given key is not intended for this version of PASETO."
            )
        key = key.get_public_key()
        if footer is None:
            footer = _extract_footer_unsafe(sign_msg)
            sign_msg = remove_footer(sign_msg)
        else:
            sign_msg = validate_and_remove_footer(sign_msg, footer)
            sign_msg = remove_footer(sign_msg)

        expected_header = cls.header + b".public."
        header_length = len(expected_header)
        given_header = sign_msg[:header_length]
        if not secrets.compare_digest(expected_header, given_header):
            raise PasetoException("Invalid message header.")

        decoded = b64decode(sign_msg[header_length:])
        decoded_len = len(decoded)
        message = decoded[: decoded_len - cls.sign_size]
        signature = decoded[decoded_len - cls.sign_size :]

        try:
            pysodium.crypto_sign_verify_detached(
                signature,
                pre_auth_encode(given_header, message, footer, implicit),
                key.key,
            )
        except ValueError:
            raise PasetoException("Invalid signature for this message")
        return message
