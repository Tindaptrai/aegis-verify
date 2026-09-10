"""Small strict source validators; empty optional cells are never zero."""

from ipaddress import IPv4Address
import re

from .errors import PfSenseParseError


_DECIMAL = re.compile(r"[0-9]+", re.ASCII)
_HEX = re.compile(r"0[xX][0-9a-fA-F]+", re.ASCII)
_MAX_NUMERIC_TOKEN = 128


def unsigned(
    text: str,
    field: str,
    maximum: int | None = None,
    *,
    optional: bool = True,
    allow_hex: bool = False,
) -> int | None:
    """Validate ASCII syntax and size before integer conversion."""
    if text == "":
        if optional:
            return None
        raise PfSenseParseError("missing_field", field) from None
    if len(text) > _MAX_NUMERIC_TOKEN:
        raise PfSenseParseError("invalid_field", field) from None
    base = 10
    if allow_hex and _HEX.fullmatch(text):
        base = 16
    elif not _DECIMAL.fullmatch(text):
        raise PfSenseParseError("invalid_field", field) from None
    value = int(text, base)
    if maximum is not None and value > maximum:
        raise PfSenseParseError("invalid_field", field) from None
    return value


def source_text(text: str, field: str, *, optional: bool = True) -> str | None:
    """Preserve source spelling, refusing whitespace in common field tokens."""
    if text == "":
        if optional:
            return None
        raise PfSenseParseError("missing_field", field) from None
    if any(character.isspace() for character in text):
        raise PfSenseParseError("invalid_field", field) from None
    return text


def ipv4(text: str, field: str) -> str | None:
    """Require an actual dotted IPv4 address and retain its source text."""
    if text == "":
        return None
    try:
        IPv4Address(text)
    except ValueError:
        raise PfSenseParseError("invalid_field", field) from None
    return text


def sequence(text: str) -> None:
    """TCP sequence is uint32 or start:end; wraparound imposes no ordering."""
    if len(text) > _MAX_NUMERIC_TOKEN:
        raise PfSenseParseError("invalid_field", "sequence") from None
    if ":" not in text:
        unsigned(text, "sequence", 2**32 - 1)
        return
    endpoints = text.split(":")
    if len(endpoints) != 2 or not all(endpoints):
        raise PfSenseParseError("invalid_field", "sequence") from None
    for endpoint in endpoints:
        unsigned(endpoint, "sequence", 2**32 - 1, optional=False)
