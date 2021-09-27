import pysodium
from paseto.helpers import (
    pre_auth_encode,
    b64decode,
    b64encode,
    validate_and_remove_footer,
    PasetoMessage,
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
    def encrypt(cls, data, key, footer: str = b"", implicit: str = b""):
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
            raise PasetoException(
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
    def decrypt(cls, data, key, footer: Optional[str] = None, implicit: str = ""):
        if key.protocol is not cls:
            raise PasetoException(
                "The given key is not intended for this version of PASETO."
            )

        if footer is None:
            data, footer = extract_footer(data)
        else:
            data = validate_and_remove_footer(data, footer)

        return cls.aead_decrypt(
            data=data,
            header=cls.header + b".local.",
            key=key,
            footer=footer,
            implicit=implicit,
        )

    @classmethod
    def sign(cls, data: str, key, footer: str = "", implicit=""):
        if key.protocol is not cls:
            raise PasetoException(
                "The given key is not intended for this version of PASETO."
            )

        header = cls.header + b".public."
        ecc_key = ECC.import_key(key.key)
        signer = DSS.new(key=ecc_key, mode="deterministic-rfc6979", encoding="binary")
        pubkey = key.get_public_key()
        if len(pubkey.key) != 49:
            raise PasetoException("Invalid public key length")

        signature = signer.sign(pre_auth_encode(pubkey, header, data, footer, implicit))
        if len(signature) != 96:
            raise PasetoException("Invalid signature length")
        return str(
            PasetoMessage(header=header, payload=data + signature, footer=footer)
        )

    @classmethod
    def verify(cls, sign_msg: str, key, footer: Optional[str] = None, implicit=""):
        if key.protocol is not cls:
            raise PasetoException(
                "The given key is not intended for this version of PASETO."
            )
        if footer is None:
            footer = extract_footer(sign_msg)
        else:
            sign_msg = validate_and_remove_footer(sign_msg)

        sign_msg = remove_footer(sign_msg)

        expect_header = cls.header + ".public."
        header_length = len(expect_header)
        given_header = sign_msg[:header_length]
        if not secrets.compare_digest(expected_header, given_header):
            raise PasetoException("Invalid message header.")
        decoded = b64decode(sign_msg[header_length:])
        decoded_len = len(decoded)
        message = decoded[: decoded_len - cls.sign_size]
        signature = decoded[decoded_len - cls.sign_size :]
        ecc_key = ECC.import_key(key.key)
        pubkey = key.get_public_key()
        if len(pubkey.key) != 49:
            raise PasetoException("Invalid public key length")
        verifier = DSS.new(pubkey, mode="deterministic-rfc6979", encoding="binary")
        try:
            valid = verifier.verify(sha384(sign_msg), signature)
            if valid:
                return message
        except ValueError:
            raise PasetoValidationError("Invalid signature for this message")
        raise PasetoValidationError("Invalid signature for this message")

    @classmethod
    def aead_encrypt(
        cls,
        plaintext,
        header,
        key,
        footer: str = b"",
        implicit=b"",
        _nonce_for_unit_testing=b"",
    ):
        if _nonce_for_unit_testing:
            nonce = _nonce_for_unit_testing
        else:
            nonce = secrets.token_bytes(cls.nonce_size)

        enc_key, auth_key, nonce2 = key.splitV3(nonce)
        cipher = AES.new(enc_key, cls.cipher_mode, nonce=nonce2)
        ciphertext = cipher.encrypt(plaintext)
        if not ciphertext:
            raise PasetoException("Encryption failed.")
        mac = hmac.new(
            pre_auth_encode(header, nonce, ciphertext, footer, implicit),
            digestmod=cls.hash_algorithm,
        ).digest()
        return str(
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
            decoded = b64decode(data[expected_len:])
        except:
            raise PasetoException("Invalid encoding detected")

        decoded_len = len(decoded)
        nonce = decoded[: self.nonce_size]
        ciphertext = decoded[
            self.nonce_size : decoded_len - (self.nonce_size + self.mac_size)
        ]
        mac = decoded[-self.mac_size :]
        enc_key, auth_key, nonce2 = key.splitV3(nonce)
        calc = hmac.new(
            pre_auth_encode(header, nonce, ciphertext, footer, implicit),
            digestmod=cls.hash_algorithm,
        )
        if not secrets.compare_digest(calc, mac):
            raise PasetoException("Invalid MAC for given ciphertext.")

        cipher = AES.new(enc_key, cls.cipher_mode, nonce=nonce2)
        try:
            plaintext = cipher.decrypt(ciphertext)
            return plaintext
        except:
            raise PasetoException("Encryption failed.")
