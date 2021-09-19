from .exceptions import *


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

    @classmethod
    def __str__(self):
        message = self.header + b64encode(self.payload)
        if self.footer == "":
            return message
        return message + "." + b64encode(footer)
