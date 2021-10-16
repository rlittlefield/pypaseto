import pytest
import json
import os
from binascii import unhexlify
from paseto.keys.symmetric_key import SymmetricKey
from paseto.keys.asymmetric_key import AsymmetricSecretKey, AsymmetricPublicKey


def cache_key(protocol, hex: str, public: bool):
    if public:
        return AsymmetricPublicKey(key_material=unhexlify(hex), protocol=protocol)
    return SymmetricKey(key_material=unhexlify(hex), protocol=protocol)


def vector_test(protocol, vector):
    decoded = None
    try:
        if "public-key" in vector:
            decoded = protocol.verify(
                sign_msg=vector["token"].encode(),
                key=cache_key(protocol, hex=vector["public-key"], public=True),
                footer=vector["footer"].encode(),
                implicit=vector["implicit-assertion"].encode(),
            )
        elif "key" in vector:
            decoded = protocol.decrypt(
                data=vector["token"].encode(),
                key=cache_key(protocol, hex=vector["key"], public=False),
                footer=vector["footer"].encode(),
                implicit=vector["implicit-assertion"].encode(),
            )
        else:
            pytest.fail("No key provided for vector")
    except:
        assert vector.get("expect-fail")
        return

    assert not vector.get("expect-fail")
    assert decoded == vector["payload"].encode()

    if vector.get("key"):
        encoded = protocol._encrypt(
            data=vector["payload"].encode(),
            key=cache_key(protocol, vector["key"], public=False),
            footer=vector["footer"].encode(),
            implicit=vector["implicit-assertion"].encode(),
            _nonce_for_unit_testing=unhexlify(vector["nonce"]),
        )
        vector_token = vector["token"].encode()
        assert encoded == vector_token
