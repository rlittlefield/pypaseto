import pytest
import json
import os
from binascii import unhexlify
from paseto.protocols.v3 import ProtocolVersion3
from paseto.keys.symmetric_key import SymmetricKey
from paseto.keys.asymmetric_key import AsymmetricSecretKey, AsymmetricPublicKey
from .vector import vector_test


script_dir = os.path.dirname(__file__)
file_path = os.path.join(script_dir, "v3_raw_vectors.json")
with open(file_path) as fh:
    vectors = json.load(fh)


@pytest.mark.parametrize("vector", vectors["tests"])
def test_v3_vectors(vector):
    return vector_test(protocol=ProtocolVersion3, vector=vector)
