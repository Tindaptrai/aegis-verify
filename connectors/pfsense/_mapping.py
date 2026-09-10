"""Bounded BSD filterlog source mapping, independent of evidence framing."""

import re
import unicodedata

from ._context import source_timestamp
from ._fields import ipv4, sequence, source_text, unsigned
from .errors import PfSenseParseError
from .models import PfSenseContext


_HEADER = re.compile(
    r"(?P<timestamp>[A-Za-z]{3} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}) "
    r"(?P<hostname>[A-Za-z0-9_.-]+) "
    r"(?P<program>filterlog|newsyslog)(?:\[(?P<pid>[0-9]{1,128})\])?: "
    r"(?P<payload>.*)",
    re.ASCII,
)
_ROTATION = re.compile(r"logfile turned over due to size>[1-9][0-9]{0,127}[KMG]?")
_ACTIONS = {"pass": "allowed", "block": "blocked"}
_PROTOCOLS = {6: "tcp", 17: "udp"}


def _common(cells: list[str]) -> tuple[dict, int]:
    if len(cells) < 9:
        raise PfSenseParseError("missing_field") from None
    for index, field in ((0, "rule_number"), (1, "subrule"), (3, "tracker")):
        unsigned(cells[index], field, optional=index != 0)
    metadata = {
        "rule_number": cells[0],
        "subrule": cells[1] or None,
        "anchor": source_text(cells[2], "anchor"),
        "tracker": cells[3] or None,
        "interface": source_text(cells[4], "interface", optional=False),
        "reason": source_text(cells[5], "reason", optional=False),
        "direction": cells[7],
    }
    if cells[6] not in _ACTIONS:
        raise PfSenseParseError("unsupported_value", "action") from None
    if cells[7] not in {"in", "out"}:
        raise PfSenseParseError("unsupported_value", "direction") from None
    version = unsigned(cells[8], "ip_version", 255, optional=False)
    return metadata, version


def map_filterlog_line(
    text: str, context: PfSenseContext
) -> tuple[dict | None, dict, str | None]:
    """Return canonical source fields, provenance additions, and a skip reason.

    Framing owns UTF-8 decoding, newline/BOM removal, byte limits and identity.
    Unsupported payloads are classified only, not protocol-specific validation.
    """
    if type(text) is not str:
        raise PfSenseParseError("input_type") from None
    if not isinstance(context, PfSenseContext):
        raise PfSenseParseError("invalid_context") from None
    if any(
        character in "\"'\u2028\u2029" or unicodedata.category(character).startswith("C")
        for character in text
    ):
        raise PfSenseParseError("invalid_field") from None
    if not text or text.isspace():
        return None, {}, "blank_line"
    header = _HEADER.fullmatch(text)
    if header is None:
        raise PfSenseParseError("malformed_header") from None
    timestamp_text = header["timestamp"]
    timestamp = source_timestamp(timestamp_text, context)
    metadata = {
        "timestamp_text": timestamp_text,
        "timestamp_basis": "bsd_syslog_with_caller_context",
        "source_year": context.source_year,
        "source_utc_offset": context.source_utc_offset,
        "warnings": ("year_and_offset_supplied_by_caller",),
        "nat_context": None,
    }
    payload = header["payload"]
    if header["program"] == "newsyslog":
        if _ROTATION.fullmatch(payload) is None:
            raise PfSenseParseError("malformed_header", "program") from None
        return None, metadata, "rotation_notice"

    # Empty cells retain their source indexes; trailing spaces belong to payload.
    cells = payload.split(",")
    common, version = _common(cells)
    metadata.update(common)
    if version != 4:
        return None, metadata, "unsupported_ip_version"
    if len(cells) < 17:
        raise PfSenseParseError("missing_field") from None
    protocol_id = unsigned(cells[15], "protocol_id", 255, optional=False)
    protocol_text = source_text(cells[16], "protocol_text", optional=False)
    protocol = protocol_text.lower()
    metadata.update(protocol_id=cells[15], protocol_text=protocol_text)
    # Either supported identifier commits the record to strict pair validation.
    if protocol_id in _PROTOCOLS or protocol in _PROTOCOLS.values():
        if _PROTOCOLS.get(protocol_id) != protocol:
            raise PfSenseParseError("invalid_field", "protocol_text") from None
    else:
        return None, metadata, "unsupported_protocol"

    expected_count = 29 if protocol == "tcp" else 23
    if len(cells) != expected_count:
        code = "missing_field" if len(cells) < expected_count else "invalid_field"
        raise PfSenseParseError(code) from None
    for index, field, maximum, allow_hex in (
        (9, "tos", 255, True), (10, "ecn", 255, True), (11, "ttl", 255, False),
        (12, "ip_id", 65535, False), (13, "offset", None, False),
        (17, "length", 65535, False), (22, "data_length", 65535, False),
    ):
        unsigned(cells[index], field, maximum, allow_hex=allow_hex)
    if protocol == "tcp":
        sequence(cells[24])
        unsigned(cells[25], "ack", 2**32 - 1)
        unsigned(cells[26], "window", 65535)
        unsigned(cells[27], "urg", 65535)
    fields = dict(
        source_type="pfsense",
        event_provider="pfSense-filterlog",
        timestamp=timestamp,
        hostname=header["hostname"],
        event_action=_ACTIONS[cells[6]],
        protocol=protocol,
        src_ip=ipv4(cells[18], "src_ip"),
        dst_ip=ipv4(cells[19], "dst_ip"),
        src_port=unsigned(cells[20], "src_port", 65535),
        dst_port=unsigned(cells[21], "dst_port", 65535),
        rule_id=metadata["tracker"],
    )
    return fields, metadata, None
