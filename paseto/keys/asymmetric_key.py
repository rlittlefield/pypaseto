from paseto.protocols.v2 import ProtocolVersion2
from paseto.protocols.v3 import ProtocolVersion3
from paseto.protocols.v4 import ProtocolVersion4
from paseto.protocols.protocol import Protocol
from paseto.helpers import b64encode, b64decode

import binascii
import pysodium
import secrets
from typing import Optional
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from hashlib import sha384
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import hmac
from paseto.exceptions import *
from Cryptodome.Util.py3compat import bchr
from Cryptodome.PublicKey.ECC import EccKey


class AsymmetricSecretKey:
    key_type = "public_sk"

    def __init__(self, key_material: bytes, protocol: Protocol):
        if not protocol:
            protocol = ProtocolVersion4

        if secrets.compare_digest(
            protocol.header, ProtocolVersion2.header
        ) or secrets.compare_digest(protocol.header, ProtocolVersion4.header):
            key_length = len(key_material)
            if (
                key_length
                == pysodium.crypto_sign_PUBLICKEYBYTES
                + pysodium.crypto_sign_SECRETKEYBYTES
            ):
                key_material = key_material[:64]
            elif key_length != pysodium.crypto_sign_SECRETKEYBYTES:
                if key_length != pysodium.crypto_sign_SEEDBYTES:
                    raise PasetoException(
                        "Secret keys must be 32 or 64 bytes long; "
                        + str(key_length)
                        + " given"
                    )
                keypair = pysodium.crypto_sign_seed_keypair(key_material)
                key_material = keypair[0]
        elif secrets.compare_digest(protocol.header, ProtocolVersion3.header):
            if len(key_material) == 48:
                self.ecc_key = EccKey(
                    curve="NIST P-384",
                    d=int.from_bytes(key_material, byteorder="little"),
                )
            else:
                self.ecc_key = ECC.import_key(encoded=key_material)

        self.key = key_material
        self.protocol = protocol

    @classmethod
    def v2(cls, key_material):
        return cls(key_material=key_material, protocol=ProtocolVersion2)

    @classmethod
    def v3(cls, key_material):
        return cls(key_material=key_material, protocol=ProtocolVersion3)

    @classmethod
    def v4(cls, key_material):
        return cls(key_material=key_material, protocol=ProtocolVersion4)

    @classmethod
    def generate(cls, protocol: Optional[Protocol] = None):
        protocol = protocol if protocol else ProtocolVersion4
        if protocol is ProtocolVersion3:
            key_obj = ECC.generate(curve="NIST P-384")
            return cls(
                key_material=key_obj.export_key(format="PEM").encode(),
                protocol=protocol,
            )
        return cls(
            key_material=pysodium.crypto_sign_keypair()[1],
            protocol=protocol,
        )

    def encode(self):
        return b64encode(binascii.unhexlify(self.key))

    @classmethod
    def from_encoded_string(cls, encoded, protocol: Optional[Protocol] = None):
        return cls(key_material=decoded, protocol=protocol)

    def get_public_key(self):
        if self.protocol is ProtocolVersion3:
            pk = self.ecc_key.public_key()
            der = pk.export_key(format="DER", compress=True)
            public_key = der[23:]
            return AsymmetricPublicKey(key_material=public_key, protocol=self.protocol)
        else:
            return AsymmetricPublicKey(
                key_material=pysodium.crypto_sign_sk_to_pk(sk=self.key),
                protocol=self.protocol,
            )


class AsymmetricPublicKey:
    key_type = "public_pk"

    def __init__(self, key_material: bytes, protocol: Optional[Protocol] = None):
        if not protocol:
            protocol = ProtocolVersion4

        key_length = len(key_material)
        if secrets.compare_digest(
            protocol.header, ProtocolVersion2.header
        ) or secrets.compare_digest(protocol.header, ProtocolVersion4.header):
            if key_length == pysodium.crypto_sign_PUBLICKEYBYTES << 1:
                key_material = binascii.decode(key_material)
            elif key_length != pysodium.crypto_sign_PUBLICKEYBYTES:
                raise PasetoException(
                    "Secret keys must be 32 or 64 bytes long;" + key_length + " given"
                )

        self.key = key_material
        self.protocol = protocol

    @classmethod
    def v2(cls, key_material):
        return cls(key_material=key_material, protocol=ProtocolVersion2)

    @classmethod
    def v3(cls, key_material):
        return cls(key_material=key_material, protocol=ProtocolVersion3)

    @classmethod
    def v4(cls, key_material):
        return cls(key_material=key_material, protocol=ProtocolVersion4)

    def encode(self):
        if self.protocol is ProtocolVersion3:
            return b64encode(
                binascii.unhexlify(ProtovolVersion3.get_public_key_compressed(self.key))
            )

    def get_public_key(self):
        return self

    @classmethod
    def from_encoded_string(cls, encoded, protocol: Optional[Protocol] = None):
        if not protocol:
            protocol = ProtocolVersion4
        decoded = b64decode(encoded)
        return cls(key_material=decoded, protocol=protocol)
