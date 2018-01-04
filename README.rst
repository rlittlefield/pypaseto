Platform-Agnostic Security Tokens for Python
============================================

This is an initial implementation of `PAST: Platform-Agnostic Security
Tokens <https://github.com/paragonie/past/>`_ for Python.

This is not yet production-ready; use at your own risk.


Encoding Example
----------------

.. code-block:: python

    from pypast import encode_auth
    token = encode_auth(payload, key, footer)


Decoding Example
----------------

.. code-block:: python

    from pypast import decode
    payload, footer = decode(token, key)
