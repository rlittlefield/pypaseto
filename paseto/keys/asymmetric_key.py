class AsymmetricSecretKey:
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
                raise PasetoException(
                    "Secret keys must be 32 or 64 bytes long;" + key_length + " given"
                )

        self.key = key_material
        self.protocol = protocol
