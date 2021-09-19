class PasetoException(Exception):
    pass


class InvalidVersionException(PasetoException):
    pass


class InvalidPurposeException(PasetoException):
    pass


class InvalidTokenException(PasetoException):
    pass


class PasetoValidationError(PasetoException):
    pass


class PasetoTokenExpired(PasetoValidationError):
    pass
