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
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from hashlib import sha384
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import hmac
from typing import Optional
import secrets
from Cryptodome.Hash import SHA384

DER_PREFIX = b"""0F0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00"\x032\x00"""


class ProtocolVersion3(Protocol):
    symmetric_key_byte_length = 32
    nonce_size = 32
    mac_size = 48
    sign_size = 96
    header = b"v3"
    supports_implicit_assertions = True
    cipher_mode = AES.MODE_CTR
    hash_algorithm = sha384

    @classmethod
    def generate_asymmetric_secret_key(cls):
        from paseto.keys.asymmetric_key import AsymmetricSecretKey

        return AsymmetricSecretKey.generate(protocol=cls)

    @classmethod
    def generate_symmetric_key(cls):
        from paseto.keys.symmetric_key import SymmetricKey

        return SymmetricKey.generate(protocol=cls)

    @classmethod
    def encrypt(cls, data, key, footer: bytes = b"", implicit: bytes = b""):
        return cls._encrypt(data=data, key=key, footer=footer, implicit=implicit)

    @classmethod
    def _encrypt(
        cls,
        data,
        key,
        footer: bytes = b"",
        implicit: bytes = b"",
        _nonce_for_unit_testing=None,
    ):
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
    def sign(cls, data: bytes, key, footer: bytes = b"", implicit: bytes = b""):
        if key.protocol is not cls:
            raise PasetoException(
                "The given key is not intended for this version of PASETO."
            )

        header = cls.header + b".public."
        signer = DSS.new(
            key=key.ecc_key, mode="deterministic-rfc6979", encoding="binary"
        )
        verifier = DSS.new(
            key=key.ecc_key.public_key(),
            mode="deterministic-rfc6979",
            encoding="binary",
        )
        pubkey = key.get_public_key().key
        hash_obj = SHA384.new(pre_auth_encode(pubkey, header, data, footer, implicit))
        signature = signer.sign(hash_obj)
        if len(signature) != 96:
            raise PasetoException("Invalid signature length")
        return bytes(
            PasetoMessage(header=header, payload=data + signature, footer=footer)
        )

    @classmethod
    def verify(cls, sign_msg: bytes, key, footer: Optional[bytes] = None, implicit=b""):
        if key.protocol is not cls:
            raise PasetoException(
                "The given key is not intended for this version of PASETO."
            )
        if footer is None:
            footer = _extract_footer_unsafe(sign_msg)
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
        pubkey = key.get_public_key()
        if len(pubkey.key) != 49:
            raise PasetoException("Invalid public key length")
        ecc_key = ECC.import_key(DER_PREFIX + pubkey.key)
        verifier = DSS.new(key=ecc_key, mode="deterministic-rfc6979", encoding="binary")
        hash_obj = SHA384.new(
            pre_auth_encode(pubkey.key, given_header, message, footer, implicit)
        )
        try:
            verifier.verify(
                hash_obj,
                signature,
            )
            return message
        except ValueError as e:
            raise PasetoValidationError("Invalid signature for this message") from e
        raise PasetoValidationError("Invalid signature for this message")

    @classmethod
    def aead_encrypt(
        cls,
        plaintext,
        header,
        key,
        footer: bytes = b"",
        implicit=b"",
        _nonce_for_unit_testing=b"",
    ):
        if _nonce_for_unit_testing:
            nonce = _nonce_for_unit_testing
        else:
            nonce = secrets.token_bytes(cls.nonce_size)

        enc_key, auth_key, nonce2 = key.splitV3(nonce)
        cipher = AES.new(enc_key, cls.cipher_mode, initial_value=nonce2, nonce=b"")
        ciphertext = cipher.encrypt(plaintext)
        if not ciphertext:
            raise PasetoException("Encryption failed.")
        mac = hmac.new(
            key=auth_key,
            msg=pre_auth_encode(header, nonce, ciphertext, footer, implicit),
            digestmod=cls.hash_algorithm,
        ).digest()
        return bytes(
            PasetoMessage(
                header=header, payload=nonce + ciphertext + mac, footer=footer
            )
        )

    @classmethod
    def aead_decrypt(cls, message, header, key, footer=b"", implicit=b""):
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
        enc_key, auth_key, nonce2 = key.splitV3(nonce)
        calc = hmac.new(
            key=auth_key,
            msg=pre_auth_encode(header, nonce, ciphertext, footer, implicit),
            digestmod=cls.hash_algorithm,
        ).digest()
        if not secrets.compare_digest(calc, mac):
            raise PasetoException("Invalid MAC for given ciphertext.")

        cipher = AES.new(enc_key, cls.cipher_mode, initial_value=nonce2, nonce=b"")
        try:
            plaintext = cipher.decrypt(ciphertext)
            return plaintext
        except:
            raise PasetoException("Encryption failed.")
