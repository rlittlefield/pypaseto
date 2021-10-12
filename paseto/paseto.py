#!/usr/bin/env python3

import base64
import struct
import secrets
import json
import pysodium
import pendulum

from .helpers import pre_auth_encode, b64decode, b64encode, _extract_footer_unsafe

from .exceptions import *
from typing import Union, Optional, List
from .keys.symmetric_key import SymmetricKey
from .keys.asymmetric_key import AsymmetricSecretKey, AsymmetricPublicKey
from .protocols.v2 import ProtocolVersion2
from .protocols.v3 import ProtocolVersion3
from .protocols.v4 import ProtocolVersion4


DEFAULT_RULES = {"exp"}


class JsonEncoder(object):
    @classmethod
    def dumps(cls, var):
        return json.dumps(var, sort_keys=True, separators=(",", ":")).encode("utf8")

    @classmethod
    def loads(cls, var):
        return json.loads(var)


def create(
    key: Union[AsymmetricSecretKey, SymmetricKey],
    claims: dict,
    purpose: Optional[str] = None,
    exp_seconds: Optional[int] = None,
    footer: Optional[str] = None,
    _encoder=JsonEncoder,
):
    """
    Creates a new paseto token using the provided key, purpose, and claims.

    The exp claim is registered. To set it manually, leave the `exp_seconds`
    parameter as None, and manually put it into your claims dict. Otherwise,
    it acts as a number-of-seconds-from-now and is dynamically calculated when
    the token is made.

    The purpose will be validated against the type of key. This is partially
    because this is how it was done in earlier versions, but also to make
    sure we don't infer from the `key` property and silently change behavior.

    :param key: Union[AsymmetricSecretKey, SymmetricKey]
    :param purpose: local or public
    :param claims: dict of the claims to include in the token
    :param exp_seconds: number of seconds from now before expiration
    :param footer: dict of the footer that will be authenticated but not encrypted
    :param encoder: encoder to use if you don't want the default JSON encoder
    :return:
    """

    if not key:
        raise ValueError("key is required")

    if isinstance(key, AsymmetricSecretKey):
        if purpose and purpose != "public":
            raise InvalidPurposeException("purpose does not match provided key")
        purpose = "public"
    elif isinstance(key, SymmetricKey):
        if purpose and purpose != "local":
            raise InvalidPurposeException("purpose does not match provided key")
        purpose = "local"
    else:
        raise ValueError("invalid key")

    if exp_seconds:
        then = pendulum.now().add(seconds=exp_seconds).to_atom_string()
        claims["exp"] = then

    encoded = _encoder.dumps(claims)
    encoded_footer = _encoder.dumps(footer) if footer else b""

    if purpose == "local":
        token = key.protocol.encrypt(data=encoded, key=key, footer=encoded_footer)
    elif purpose == "public":
        token = key.protocol.sign(data=encoded, key=key, footer=encoded_footer)
    return token.decode()


def parse(
    key: Union[AsymmetricSecretKey, SymmetricKey],
    token: str,
    purpose: Optional[str] = None,
    validate: bool = True,
    rules: List[str] = None,
    required_claims=None,
    _encoder=JsonEncoder,
):
    """
    Parse a paseto token.
    Takes a key, a purpose (which must be either 'local' or 'public'), and
    a `token`, which must be a bytes object.

    By default, it validates known registered claims (currently just 'exp').
    To disable validation, set "validate" to False. Cryptographic validity
    cannot be turned off (decryption and authentication are still performed).

    You can also turn on/off validation of specific rules by passing a list to
    "rules". If you pass an empty list to "rules", you must also specify
    "validate=False" or it will raise an exception.

    You may pass an alternative encoder if you don't want to use JSON. It
    should have loads/dumps methods available, and output a bytes object (not
    a str).
    :param key: decryption/validation key. Must match the purpose type
    :param purpose: one of 'local', 'public'
    :param token: bytes object with the raw paseto token
    :param encoder: optional encoder to use instead of JSON
    :param validate: bool indicating if claims should be validated with rules
    :param rules: list of rule names to apply to override the default rules
    :param required_claims: list of claim names that must be present (like exp)
    :return:
    """

    if isinstance(token, str):
        token = token.encode()

    if not key:
        raise ValueError("key is required")

    if isinstance(key, AsymmetricSecretKey) or isinstance(key, AsymmetricPublicKey):
        if purpose and purpose != "public":
            raise InvalidPurposeException("purpose does not match provided key")
        purpose = "public"
    elif isinstance(key, SymmetricKey):
        if purpose and purpose != "local":
            raise InvalidPurposeException("purpose does not match provided key")
        purpose = "local"
    else:
        raise ValueError("invalid key")

    if purpose == "local":
        result = key.protocol.decrypt(data=token, key=key)
    else:
        result = key.protocol.verify(sign_msg=token, key=key)
    decoded_message = _encoder.loads(result)
    footer = _extract_footer_unsafe(
        token
    )  # this should only be called after the verify/decrypt succeeds
    decoded_footer = _encoder.loads(footer) if footer else None

    if required_claims:
        missing_claims = set(required_claims).difference(set(decoded_message.keys()))
        if missing_claims:
            raise PasetoValidationError(f"required claims missing {missing_claims}")

    rules = DEFAULT_RULES if not rules else set(rules)
    if validate and not rules:
        raise ValueError("must set validate=False to use no rules")

    rule_set = {"exp"}
    unknown_rules = rules.difference(rule_set)
    if unknown_rules:
        raise ValueError(f"unknown rules: {unknown_rules}")

    if validate:
        # validate all the claims
        if "exp" in rules and "exp" in decoded_message:
            # validate expiration
            exp = decoded_message["exp"]
            when = pendulum.parse(exp)
            if pendulum.now() > when:
                raise PasetoTokenExpired("token expired")
    return {"message": decoded_message, "footer": decoded_footer}
