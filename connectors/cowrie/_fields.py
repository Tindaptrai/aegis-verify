"""Strict source-field validators for the Cowrie Wazuh profile."""

from ipaddress import ip_address
import re

from .errors import CowrieParseError


_ASCII_DECIMAL = re.compile(r"[0-9]{1,128}", re.ASCII)


def object_field(value: object, path: str, *, optional: bool = False) -> dict:
    if value is None and optional:
        return {}
    if type(value) is not dict:
        raise CowrieParseError("invalid_field", path) from None
    return value


def text(value: object, path: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str:
        raise CowrieParseError("invalid_field", path) from None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise CowrieParseError("invalid_field", path) from None
    return value


def required_text(value: object, path: str) -> str:
    if value is None:
        raise CowrieParseError("missing_field", path) from None
    result = text(value, path)
    assert result is not None
    return result


def decimal_id(value: object, path: str) -> str | None:
    if value is None:
        return None
    if type(value) is int and 0 <= value < 10**128:
        return str(value)
    if type(value) is str and _ASCII_DECIMAL.fullmatch(value) is not None:
        return value
    raise CowrieParseError("invalid_field", path) from None


def nonnegative_integer(value: object, path: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise CowrieParseError("invalid_field", path) from None
    return value


def port(value: object, path: str) -> int | None:
    if value is None:
        return None
    if type(value) is int:
        number = value
    elif type(value) is str and _ASCII_DECIMAL.fullmatch(value) is not None:
        number = int(value)
    else:
        raise CowrieParseError("invalid_field", path) from None
    if not 0 <= number <= 65535:
        raise CowrieParseError("invalid_field", path) from None
    return number


def address(value: object, path: str):
    value = text(value, path)
    if value is None:
        return None
    try:
        if "%" in value:
            raise ValueError
        return ip_address(value)
    except ValueError:
        raise CowrieParseError("invalid_field", path) from None


def protocol(value: object, path: str) -> str | None:
    value = text(value, path)
    if value is not None and value not in {"ssh", "telnet"}:
        raise CowrieParseError("invalid_field", path) from None
    return value
