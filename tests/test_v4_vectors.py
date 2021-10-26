import pytest
import json
import os
from binascii import unhexlify
from paseto.protocols.v4 import ProtocolVersion4
from paseto.keys.symmetric_key import SymmetricKey
from paseto.keys.asymmetric_key import AsymmetricSecretKey, AsymmetricPublicKey
from .vector import vector_test


script_dir = os.path.dirname(__file__)
file_path = os.path.join(script_dir, "v4_raw_vectors.json")
with open(file_path) as fh:
    vectors = json.load(fh)


@pytest.mark.parametrize("vector", vectors["tests"])
def test_v4_vectors(vector):
    return vector_test(protocol=ProtocolVersion4, vector=vector)
