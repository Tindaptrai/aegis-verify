"""Pure helpers for evidence integrity; these do not establish authenticity."""

from hashlib import sha256


def hash_raw_event(raw_record: bytes) -> str:
    """Hash exact sanitized record bytes, including any retained line terminator.

    The caller owns sanitization and record boundaries. This function does not
    read paths, parse JSON, strip whitespace, or normalize encodings/newlines.
    """
    if not isinstance(raw_record, bytes):
        raise TypeError("raw_record must be bytes; encode sanitized data explicitly")
    return sha256(raw_record).hexdigest()
