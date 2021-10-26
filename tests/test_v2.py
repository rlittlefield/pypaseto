import json

import pytest
import paseto
from unittest import mock
from paseto.protocols.v2 import ProtocolVersion2
from paseto.keys.asymmetric_key import AsymmetricSecretKey, AsymmetricPublicKey
from paseto.keys.symmetric_key import SymmetricKey


def test_v2_local_keygen():
    test_v2_local_key = ProtocolVersion2.generate_symmetric_key()
    assert test_v2_local_key.protocol is ProtocolVersion2


def test_v2_public_keygen():
    test_v2_public_secret_key = ProtocolVersion2.generate_asymmetric_secret_key()
    assert test_v2_public_secret_key.protocol is ProtocolVersion2
    test_v2_public_public_key = test_v2_public_secret_key.get_public_key()
    assert test_v2_public_public_key.protocol is ProtocolVersion2


def test_create_local():
    test_v2_local_key = ProtocolVersion2.generate_symmetric_key()
    token = paseto.create(
        key=test_v2_local_key,
        claims={"test": [1, 2, 3]},
        purpose="local",
        exp_seconds=100,
        footer="hello",
    )
    assert token is not None


def test_key_gen():
    symmetric = ProtocolVersion2.generate_symmetric_key()
    secret = ProtocolVersion2.generate_asymmetric_secret_key()

    assert isinstance(symmetric, SymmetricKey)
    assert isinstance(secret, AsymmetricSecretKey)
    assert isinstance(secret.get_public_key(), AsymmetricPublicKey)

    assert ProtocolVersion2.symmetric_key_byte_length == len(symmetric.key)
    assert 64 == len(secret.key)
