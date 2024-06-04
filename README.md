PASETO Tokens for Python
============================================
[![PyPI](https://img.shields.io/pypi/v/paseto.svg)](https://pypi.python.org/pypi/paseto)
[![PyPI - License](https://img.shields.io/pypi/l/paseto.svg)](https://pypi.python.org/pypi/paseto)
[![CI](https://github.com/rlittlefield/pypaseto/actions/workflows/main.yml/badge.svg)](https://github.com/rlittlefield/pypaseto/actions/workflows/main.yml)

This is an unofficial implementation of
![PASETO: Platform-Agnostic Security Tokens](https://paseto.io/) for Python.

PASETO versions supported: v2, v3, and v4

Please note that the v2 token type standard is expected to be deprecated in 2022, so new development should be done ideally on versions 3 or 4.

Installation
------------

    pip install paseto


Usage
-----

To create/parse paseto tokens, use the create/parse functions. These will
automatically handle encoding/decoding the JSON payload for you, and validate
claims (currently just the 'exp' expiration registered claim).

```python
import paseto
from paseto.keys.symmetric_key import SymmetricKey
from paseto.protocols.v4 import ProtocolVersion4
my_key = SymmetricKey.generate(protocol=ProtocolVersion4)

# create a paseto token that expires in 5 minutes (300 seconds)
token = paseto.create(
    key=my_key,
    purpose='local',
    claims={'my claims': [1, 2, 3]},
    exp_seconds=300
)

parsed = paseto.parse(
    key=my_key,
    purpose='local',
    token=token,
)
print(parsed)
# {'message': {'exp': '2021-10-25T22:43:20-06:00', 'my claims': [1, 2, 3]}, 'footer': None}
```

You can also make and verify "public" tokens, which are signed but not
encrypted:

```python
import paseto
from paseto.keys.asymmetric_key import AsymmetricSecretKey
from paseto.protocols.v4 import ProtocolVersion4
my_key = AsymmetricSecretKey.generate(protocol=ProtocolVersion4)

# create a paseto token that expires in 5 minutes (300 seconds)
token = paseto.create(
    key=my_key,
    purpose='public',
    claims={'my claims': [1, 2, 3]},
    exp_seconds=300
)

parsed = paseto.parse(
    key=my_key,
    purpose='public',
    token=token,
)
print(parsed)
# {'message': {'exp': '2021-10-25T22:43:20-06:00', 'my claims': [1, 2, 3]}, 'footer': None}
```


Changelog
---------

### v2.0.0
* Dropping support for python 3.7
* Adding support for python 3.11 and 3.12
* Dependency updates for pendulum, pysodium, pycryptodomex