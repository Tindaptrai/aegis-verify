"""Small strict source validators; empty optional cells are never zero."""

from ipaddress import IPv4Address, IPv6Address
import re

from .errors import OpnSenseParseError


_DECIMAL = re.compile(r"[0-9]+", re.ASCII)
_HEX = re.compile(r"0[xX][0-9a-fA-F]+", re.ASCII)
# OPNsense labels user rules with a UUID and automatic rules with an MD5 hex digest.
_LABEL = re.compile(
    r"[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.ASCII,
)
_DATALENGTH = re.compile(r"datalength=([0-9]{1,128})", re.ASCII)
_TCP_FLAGS = frozenset("FSRPAUEW")
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
        raise OpnSenseParseError("missing_field", field) from None
    if len(text) > _MAX_NUMERIC_TOKEN:
        raise OpnSenseParseError("invalid_field", field) from None
    base = 10
    if allow_hex and _HEX.fullmatch(text):
        base = 16
    elif not _DECIMAL.fullmatch(text):
        raise OpnSenseParseError("invalid_field", field) from None
    value = int(text, base)
    if maximum is not None and value > maximum:
        raise OpnSenseParseError("invalid_field", field) from None
    return value


def source_text(text: str, field: str, *, optional: bool = True) -> str | None:
    """Preserve source spelling, refusing whitespace in common field tokens."""
    if text == "":
        if optional:
            return None
        raise OpnSenseParseError("missing_field", field) from None
    if any(character.isspace() for character in text):
        raise OpnSenseParseError("invalid_field", field) from None
    return text


def address(text: str, field: str, version: int) -> str:
    """Require an address of the record's IP version and keep its source text."""
    if text == "":
        raise OpnSenseParseError("missing_field", field) from None
    # IPv6Address accepts a %scope suffix; a scope is interface-local, not a host.
    if "%" in text:
        raise OpnSenseParseError("invalid_field", field) from None
    parse = IPv4Address if version == 4 else IPv6Address
    try:
        parse(text)
    except ValueError:
        raise OpnSenseParseError("invalid_field", field) from None
    return text


def label(text: str) -> str | None:
    """Return the stable rule label, or None when the rule has no label."""
    if text == "":
        return None
    if _LABEL.fullmatch(text) is None:
        raise OpnSenseParseError("invalid_field", "label") from None
    return text


def tcp_flags(text: str) -> None:
    """pf prints each set flag once from the letters F, S, R, P, A, U, E, W."""
    if text == "":
        return
    if len(text) > len(_TCP_FLAGS) or len(set(text)) != len(text) or not set(text) <= _TCP_FLAGS:
        raise OpnSenseParseError("invalid_field", "tcp_flags") from None


def data_length_token(text: str) -> None:
    """ICMP and ICMPv6 records end in one datalength=N cell."""
    match = _DATALENGTH.fullmatch(text)
    if match is None:
        code = "missing_field" if text == "" else "invalid_field"
        raise OpnSenseParseError(code, "data_length") from None
    if int(match.group(1)) > 65535:
        raise OpnSenseParseError("invalid_field", "data_length") from None


def sequence(text: str) -> None:
    """TCP sequence is uint32 or start:end; wraparound imposes no ordering."""
    if len(text) > _MAX_NUMERIC_TOKEN:
        raise OpnSenseParseError("invalid_field", "sequence") from None
    if ":" not in text:
        unsigned(text, "sequence", 2**32 - 1)
        return
    endpoints = text.split(":")
    if len(endpoints) != 2 or not all(endpoints):
        raise OpnSenseParseError("invalid_field", "sequence") from None
    for endpoint in endpoints:
        unsigned(endpoint, "sequence", 2**32 - 1, optional=False)
