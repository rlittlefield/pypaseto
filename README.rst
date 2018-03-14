Platform-Agnostic Security Tokens for Python
============================================
.. image:: https://img.shields.io/pypi/v/paseto.svg
   :alt: PyPI
   :target: https://pypi.python.org/pypi/paseto
.. image:: https://img.shields.io/pypi/l/paseto.svg
   :alt: PyPI - License
   :target: https://pypi.python.org/pypi/paseto


.. image:: https://travis-ci.org/rlittlefield/pypaseto.svg?branch=master
    :target: https://travis-ci.org/rlittlefield/pypaseto

This is an unofficial initial implementation of
`PASETO: Platform-Agnostic Security Tokens <https://github.com/paragonie/past/>`_ for Python.

This is not yet production-ready; use at your own risk.

Forked from `https://github.com/JimDabell/pypast <https://github.com/JimDabell/pypast>`_,
which was originally designed for an earlier spec of PASETO when it was still
PAST.

Installation
------------

.. code-block:: bash

	pip install paseto


Usage
-----

This is still in early development. It has not been reviewed in a security
audit yet, so please be aware that it is not expected to be ready for use in
production systems.

It currently only supports basic encrypt/decrypt of the "local" token type, V2.
V1 is not as nice as V2, but we will accept a functional, clean, secure pull
request for a V1 if you are interested.

To create/parse paseto tokens, use the create/parse functions. These will
automatically handle encoding/decoding the JSON payload for you, and validate
claims (currently just the 'exp' expiration registered claim).


.. code-block:: python

	import paseto
	import secrets
	my_key = secrets.token_bytes(32)
	# > b'M\xd48b\xe2\x9f\x1e\x01[T\xeaA1{Y\xd1y\xfdx\xb5\xb7\xbedi\xa3\x96!`\x88\xc2n\xaf'

	# create a paseto token that expires in 5 minutes (300 seconds)
	token = paseto.create(
		key=my_key,
		purpose='local',
		claims={'my claims': [1, 2, 3]},
		exp_seconds=300
	)
	# > b'v2.local.g7qPkRXfUVSxx3jDw6qbAVDvehtz_mwawYsCd5IQ7VmxuRFIHxY9djMaR8M7LWvCSvCZu8NUk-Ta8zFC5MpUXldBCKq8NtCG31wsoKv8zCKwDs9LuWy4NX3Te6rvlnjDMcI_Iw'

	parsed = paseto.parse(
		key=my_key,
		purpose='local',
		token=token,
	)
	print(parsed['message'])


You can also make and verify v2.public tokens, which are signed but not
encrypted:

.. code-block:: python

	import paseto
	import pysodium
	pubkey, privkey = pysodium.crypto_sign_keypair()
	# pubkey > b'\xa7\x0b\x14\xec\x03\x97\x90\x86\x14\x12\xa0x:)\x97\xed\xdf\x81\xc3\xe4\x95\xd7R\xfe\x9bT\xba,\x92\x0c\xb9P'
	# privkey > b'@\x1fg\x9b\x83b$\xcdJP{\x93\xe8[\xae\x05.\xe9\xcb\x13\xe7`v\xa67\xd6\xb47\x7f\x96\xdf0\xa7\x0b\x14\xec\x03\x97\x90\x86\x14\x12\xa0x:)\x97\xed\xdf\x81\xc3\xe4\x95\xd7R\xfe\x9bT\xba,\x92\x0c\xb9P'

	token = paseto.create(
		key=privkey,
		purpose='public',
		claims={'my claims': [1, 2, 3]},
		exp_seconds=300
	)
	# > b'v2.public.eyJteSBjbGFpbXMiOiBbMSwgMiwgM10sICJleHAiOiAiMjAxOC0wMy0xM1QxNDo0MzozNC0wNjowMCJ9vjeSnGkfEk7tkHg5gj07vFo-YYBMTYEuSG00SqQ6iaYMeLMcc9puiOOUsu0buTziYeEmE9Fahtm1pi2PSPZpDA'

	parsed = paseto.parse(
		key=pubkey,
		purpose='public',
		token=token,
	)
	# > {'message': {'my claims': [1, 2, 3], 'exp': '2018-03-13T14:43:34-06:00'}, 'footer': None}
	print(parsed['message'])
