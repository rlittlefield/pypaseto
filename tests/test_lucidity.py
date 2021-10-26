import pytest
from paseto.protocols.protocol import Protocol
from paseto.protocols.v4 import ProtocolVersion4
from paseto.protocols.v3 import ProtocolVersion3
from paseto.protocols.v2 import ProtocolVersion2
from paseto.keys.symmetric_key import SymmetricKey
from paseto.exceptions import *


v4_lk = ProtocolVersion4.generate_symmetric_key()
v4_sk = ProtocolVersion4.generate_asymmetric_secret_key()

v4_pk = v4_sk.get_public_key()

v2_lk = SymmetricKey(key_material=v4_lk.key, protocol=ProtocolVersion2)
v3_lk = SymmetricKey(key_material=v4_lk.key, protocol=ProtocolVersion3)


@pytest.mark.parametrize(
    "protocol,valid_key,invalid_key",
    [
        [ProtocolVersion4, v4_lk, v4_pk],
        [ProtocolVersion4, v4_lk, v4_sk],
        [ProtocolVersion4, v4_lk, v2_lk],
        [ProtocolVersion4, v4_lk, v3_lk],
    ],
)
def test_lucidity(protocol: Protocol, valid_key, invalid_key):
    dummy = b'{"test":true}'
    encode = protocol.encrypt(data=dummy, key=valid_key)
    decode = protocol.decrypt(data=encode, key=valid_key)

    assert decode == dummy

    with pytest.raises(PasetoException):
        protocol.decrypt(data=encode, key=invalid_key)
