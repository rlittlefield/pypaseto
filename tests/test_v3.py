import json

import pytest
import paseto
from unittest import mock
from paseto.protocols.v3 import ProtocolVersion3
from paseto.keys.asymmetric_key import AsymmetricSecretKey, AsymmetricPublicKey
from paseto.keys.symmetric_key import SymmetricKey
import secrets


def test_v3_local_keygen():
    test_v3_local_key = ProtocolVersion3.generate_symmetric_key()
    assert test_v3_local_key.protocol is ProtocolVersion3


def test_v3_public_keygen():
    test_v3_public_secret_key = ProtocolVersion3.generate_asymmetric_secret_key()
    assert test_v3_public_secret_key.protocol is ProtocolVersion3
    test_v3_public_public_key = test_v3_public_secret_key.get_public_key()
    assert test_v3_public_public_key.protocol is ProtocolVersion3


def test_create_local():
    test_v3_local_key = ProtocolVersion3.generate_symmetric_key()
    token = paseto.create(
        key=test_v3_local_key,
        claims={"test": [1, 2, 3]},
        purpose="local",
        exp_seconds=100,
        footer="hello",
    )
    assert token is not None
    assert token.startswith("v3.")

    parsed = paseto.parse(test_v3_local_key, token)
    assert parsed


def test_create_public():
    test_v3_public_secret_key = ProtocolVersion3.generate_asymmetric_secret_key()
    test_v3_public_public_key = test_v3_public_secret_key.get_public_key()

    token = paseto.create(
        key=test_v3_public_secret_key,
        claims={"test": [1, 2, 3]},
        purpose="public",
        exp_seconds=100,
        footer="hello",
    )
    assert token is not None

    assert token.startswith("v3.")
    parsed = paseto.parse(key=test_v3_public_public_key, token=token)
    assert parsed


def test_key_gen():
    symmetric = ProtocolVersion3.generate_symmetric_key()
    secret = ProtocolVersion3.generate_asymmetric_secret_key()

    assert isinstance(symmetric, SymmetricKey)
    assert isinstance(secret, AsymmetricSecretKey)
    assert isinstance(secret.get_public_key(), AsymmetricPublicKey)

    assert ProtocolVersion3.symmetric_key_byte_length == len(symmetric.key)
    assert len(secret.key) >= 48

    # TODO: support importing secret key from this format
    asymmmetric2 = AsymmetricSecretKey(
        key_material=b"\x7f" + secrets.token_bytes(47), protocol=ProtocolVersion3
    )

    pk = asymmmetric2.get_public_key()
    assert isinstance(pk, AsymmetricPublicKey)
