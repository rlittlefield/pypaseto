from .exceptions import *
import secrets
import struct
import base64


def pre_auth_encode(*parts):
    accumulator = struct.pack("<Q", len(parts))
    for part in parts:
        accumulator += struct.pack("<Q", len(part))
        accumulator += part
    return accumulator


def b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def b64decode(data):
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


class PasetoMessage:
    def __init__(self, header, payload, footer):
        self.header = header
        self.payload = payload
        self.footer = footer

    @classmethod
    def from_string(cls, tainted: str) -> "PasetoMessage":
        pieces = tainted.split(".")
        count = len(pieces)
        if count < 3 or count > 4:
            raise PasetoException("Truncated or invalid token")

        header = ".".join(pieces[:2])
        payload = b64decode(pieces[2])
        footer = b64decode(pieces[3]) if count > 3 else ""
        return cls(header, payload, footer)

    def __str__(self):
        message = self.header + b64encode(self.payload)
        if self.footer == b"":
            return message.decode()
        return (message + b"." + b64encode(self.footer)).decode()

    def __bytes__(self):
        message = self.header + b64encode(self.payload)
        if self.footer == b"":
            return message
        return message + b"." + b64encode(self.footer)


def _extract_footer_unsafe(token):
    """
    Gets the footer out of a token. Useful if you need to use the footer to
    determine which key to load up, for example. This is performed on the
    UNVALIDATED FOOTER. So you shouldn't use this in place of actually
    validating the token afterwards:

        token = '...'
        footer = paseto.extract_footer_unvalidated(token)
        # json decode manually here if you need to
        key_id = json.loads(footer)['key_id']
        key = key_system.get_key_by_id(key_id) # fetch the key here
        parsed = paseto.parse(
            key=key,
            purpose='local',
            token=token,
        )

    If for some reason you are putting claims in the footer, do not use this!
    You still need to call "parse" so the signature can be verified.

    You should also never use this function to get the key itself out of the
    footer. Even if the key is the public key, you should NEVER load a key
    out of the footer through this function. It is only suitable to read a
    key-id from the footer, and to then perform a lookup to find the right key.

    :param token:
    :return:
    """
    if isinstance(token, str):
        token = token.encode()
    parts = token.split(b".")
    if len(parts) > 3:
        return b64decode(parts[-1])
    return b""


def remove_footer(token):
    parts = token.split(b".")
    if len(parts) > 3:
        return b".".join(parts[:-1])
    return token


def validate_and_remove_footer(payload, footer=b""):
    if not footer:
        return payload
    footer = b64encode(footer)
    footer_len = len(footer)
    trailing = payload[-footer_len - 1 :]
    if not secrets.compare_digest(b"." + footer, trailing):
        raise PasetoException("Invalid message footer")
    return payload[: -footer_len - 1]
