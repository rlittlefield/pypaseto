import json

import pytest
import paseto
from unittest import mock
from paseto.protocols.v4 import ProtocolVersion4
from paseto.protocols.v3 import ProtocolVersion3
from paseto.exceptions import *
from paseto.keys.asymmetric_key import AsymmetricSecretKey, AsymmetricPublicKey
from paseto.keys.symmetric_key import SymmetricKey
import secrets
import pendulum


def test_v4_local_keygen():
    test_v4_local_key = ProtocolVersion4.generate_symmetric_key()
    assert test_v4_local_key.protocol is ProtocolVersion4


def test_v4_public_keygen():
    test_v4_public_secret_key = ProtocolVersion4.generate_asymmetric_secret_key()
    assert test_v4_public_secret_key.protocol is ProtocolVersion4
    test_v4_public_public_key = test_v4_public_secret_key.get_public_key()
    assert test_v4_public_public_key.protocol is ProtocolVersion4


def test_create_local():
    test_v4_local_key = ProtocolVersion4.generate_symmetric_key()
    token = paseto.create(
        key=test_v4_local_key,
        claims={"test": [1, 2, 3]},
        purpose="local",
        exp_seconds=100,
        footer="hello",
    )
    assert token is not None

    assert token.startswith("v4.")
    parsed = paseto.parse(test_v4_local_key, token)
    assert parsed


def test_create_local_no_v3_key():
    test_v4_local_key = ProtocolVersion4.generate_symmetric_key()
    test_v3_local_key = ProtocolVersion3.generate_symmetric_key()
    token = paseto.create(
        key=test_v4_local_key,
        claims={"test": [1, 2, 3]},
        purpose="local",
        exp_seconds=100,
        footer="hello",
    )
    assert token is not None

    assert token.startswith("v4.")
    with pytest.raises(PasetoException):
        parsed = paseto.parse(test_v3_local_key, token)


def test_create_public():
    test_v4_public_secret_key = ProtocolVersion4.generate_asymmetric_secret_key()
    test_v4_public_public_key = test_v4_public_secret_key.get_public_key()

    token = paseto.create(
        key=test_v4_public_secret_key,
        claims={"test": [1, 2, 3]},
        purpose="public",
        exp_seconds=100,
        footer="hello",
    )
    assert token is not None

    assert token.startswith("v4.")
    parsed = paseto.parse(test_v4_public_public_key, token)
    assert parsed


def test_key_gen():
    symmetric = ProtocolVersion4.generate_symmetric_key()
    secret = ProtocolVersion4.generate_asymmetric_secret_key()

    assert isinstance(symmetric, SymmetricKey)
    assert isinstance(secret, AsymmetricSecretKey)
    assert isinstance(secret.get_public_key(), AsymmetricPublicKey)

    assert ProtocolVersion4.symmetric_key_byte_length == len(symmetric.key)
    assert len(secret.key) >= 48


def test_encrypt():
    key = ProtocolVersion4.generate_symmetric_key()
    exp = pendulum.now().add(years=1).isoformat()
    messages = ["test", json.dumps({"data": "this is a signed message", "exp": exp})]
    for message in messages:
        encrypted = ProtocolVersion4.encrypt(data=message.encode(), key=key)
        assert isinstance(encrypted, bytes)
        assert b"v4.local." == encrypted[:9]
        decode = ProtocolVersion4.decrypt(data=encrypted, key=key)
        assert isinstance(decode, bytes)

        with pytest.raises(PasetoException):
            ProtocolVersion4.decrypt(message.encode(), key)

        with pytest.raises(PasetoException):
            ProtocolVersion4().decrypt(encrypted, key=key, footer=b"footer")

        encrypted = ProtocolVersion4.encrypt(message.encode(), key, b"footer")
        assert isinstance(encrypted, bytes)
        assert b"v4.local." == encrypted[:9]

        decode = ProtocolVersion4.decrypt(data=encrypted, key=key)
        assert isinstance(decode, bytes)

        with pytest.raises(PasetoException):
            ProtocolVersion4.decrypt(encrypted, key=key, footer=b"")

    with pytest.raises(InvalidVersionException):
        ProtocolVersion3.encrypt(b"test", key=key)
    encrypted = ProtocolVersion4.encrypt(b"test", key)
    with pytest.raises(InvalidVersionException):
        ProtocolVersion3.decrypt(encrypted, key)
