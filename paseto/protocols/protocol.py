class Protocol:
    symmetric_key_byte_length: int = None
    nonce_size: int = None
    mac_size: int = None
    header: str = None
    supports_implicit_assertions = False
