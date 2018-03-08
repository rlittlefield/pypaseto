Platform-Agnostic Security Tokens for Python
============================================

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

No claims are processed yet. This means you have to implement json encode/decode
yourself, as well as checking expiration.

.. code-block:: python

	from paseto import PasetoV2
	import secrets
	my_key = secrets.token_bytes(32)
	# > b'M\xd48b\xe2\x9f\x1e\x01[T\xeaA1{Y\xd1y\xfdx\xb5\xb7\xbedi\xa3\x96!`\x88\xc2n\xaf'
	token = PasetoV2.encrypt(
        plaintext=b'plaintext is a bytes object that is encrypted',
        key=my_key,
        footer=b'footer is authenticated but not encrypted'
    )
    # > b'v2.local.ORiY6F6_uy391wB1my1LA9ANYgh7rih1bcAqswLqmuiKVaZmfmUfxB5off7gLwdHVwxc-QKIEAfEdzRNU5pHcrnefFO_aA4QQV15i_yKLyyOF9oURg.Zm9vdGVyIGlzIGF1dGhlbnRpY2F0ZWQgYnV0IG5vdCBlbmNyeXB0ZWQ'

	parsed = PasetoV2.decrypt(
		token, my_key
	)
	print(parsed['message'])
	print(parsed['footer'])
