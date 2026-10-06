"""Bounded OPNsense filterlog mapping, independent of evidence framing.

OPNsense 26.7 writes the same CSV skeleton as pfSense with a different column 4
(a rule label, not a numeric tracker) and its own tails: ICMP and ICMPv6 end in
one ``datalength=N`` cell. Layouts without a real lab sample are skipped.
"""

import re
import unicodedata

from ._context import source_timestamp
from ._fields import (
    address, data_length_token, label, sequence, source_text, tcp_flags, unsigned,
)
from .errors import OpnSenseParseError
from .models import OpnSenseContext


_HEADER = re.compile(
    r"(?:<(?P<pri>[0-9]{1,3})>)?"
    r"(?P<timestamp>[A-Za-z]{3} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}) "
    r"(?:(?P<hostname>[A-Za-z0-9_.-]+) )?"
    r"filterlog(?:\[(?P<pid>[0-9]{1,128})\])?: "
    r"(?P<payload>.*)",
    re.ASCII,
)
_ACTIONS = {"pass": "allowed", "block": "blocked"}
_KNOWN_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp"}
# Column count of each layout seen in Lab C; anything else is not guessed.
_LAYOUTS = {
    (4, "tcp"): 29,
    (4, "udp"): 23,
    (4, "icmp"): 21,
    (6, "udp"): 20,
    (6, "ipv6-icmp"): 18,
}
# Column positions differ by IP version; IPv6 prints the protocol name first.
_IP = {
    4: dict(protocol_id=15, protocol_text=16, src=18, dst=19, tail=20),
    6: dict(protocol_id=13, protocol_text=12, src=15, dst=16, tail=17),
}


def _common(cells: list[str]) -> tuple[dict, int]:
    if len(cells) < 9:
        raise OpnSenseParseError("missing_field") from None
    unsigned(cells[0], "rule_number", optional=False)
    unsigned(cells[1], "subrule")
    metadata = {
        "rule_number": cells[0],
        "subrule": cells[1] or None,
        "anchor": source_text(cells[2], "anchor"),
        "label": label(cells[3]),
        "interface": source_text(cells[4], "interface", optional=False),
        "reason": source_text(cells[5], "reason", optional=False),
        "direction": cells[7],
        "ip_version": cells[8],
    }
    if cells[6] not in _ACTIONS:
        raise OpnSenseParseError("unsupported_value", "action") from None
    if cells[7] not in {"in", "out"}:
        raise OpnSenseParseError("unsupported_value", "direction") from None
    version = unsigned(cells[8], "ip_version", 255, optional=False)
    return metadata, version


def _protocol(cells: list[str], columns: dict) -> tuple[str, str]:
    if len(cells) <= max(columns["protocol_id"], columns["protocol_text"]):
        raise OpnSenseParseError("missing_field") from None
    protocol_id = unsigned(
        cells[columns["protocol_id"]], "protocol_id", 255, optional=False
    )
    protocol_text = source_text(
        cells[columns["protocol_text"]], "protocol_text", optional=False
    )
    protocol = protocol_text.lower()
    # Either known identifier commits the record to a matching number/name pair.
    if protocol_id in _KNOWN_PROTOCOLS or protocol in _KNOWN_PROTOCOLS.values():
        if _KNOWN_PROTOCOLS.get(protocol_id) != protocol:
            raise OpnSenseParseError("invalid_field", "protocol_text") from None
    return protocol_text, protocol


def _ip_header(cells: list[str], version: int) -> None:
    if version == 4:
        for index, field, maximum, allow_hex in (
            (9, "tos", 255, True), (10, "ecn", 255, True), (11, "ttl", 255, False),
            (12, "ip_id", 65535, False), (13, "offset", None, False),
            (17, "length", 65535, False),
        ):
            unsigned(cells[index], field, maximum, allow_hex=allow_hex)
        source_text(cells[14], "ip_flags")
        return
    for index, field, maximum, allow_hex in (
        (9, "traffic_class", 255, True), (10, "flow_label", 0xFFFFF, True),
        (11, "hop_limit", 255, False), (14, "length", 65535, False),
    ):
        unsigned(cells[index], field, maximum, allow_hex=allow_hex)


def _ports(cells: list[str], tail: int, protocol: str) -> tuple[int | None, int | None]:
    if protocol not in {"tcp", "udp"}:
        data_length_token(cells[tail])
        return None, None
    src_port = unsigned(cells[tail], "src_port", 65535, optional=False)
    dst_port = unsigned(cells[tail + 1], "dst_port", 65535, optional=False)
    unsigned(cells[tail + 2], "data_length", 65535)
    if protocol == "tcp":
        tcp_flags(cells[tail + 3])
        sequence(cells[tail + 4])
        unsigned(cells[tail + 5], "ack", 2**32 - 1)
        unsigned(cells[tail + 6], "window", 65535)
        unsigned(cells[tail + 7], "urg", 65535)
        source_text(cells[tail + 8], "tcp_options")
    return src_port, dst_port


def map_filterlog_line(
    text: str, context: OpnSenseContext
) -> tuple[dict | None, dict, str | None]:
    """Return canonical source fields, provenance additions, and a skip reason.

    Framing owns UTF-8 decoding, newline/BOM removal, byte limits and identity.
    Unsupported versions and protocols are classified only, never guessed.
    """
    if type(text) is not str:
        raise OpnSenseParseError("input_type") from None
    if not isinstance(context, OpnSenseContext):
        raise OpnSenseParseError("invalid_context") from None
    if any(
        character in "\"'  " or unicodedata.category(character).startswith("C")
        for character in text
    ):
        raise OpnSenseParseError("invalid_field") from None
    if not text or text.isspace():
        return None, {}, "blank_line"
    header = _HEADER.fullmatch(text)
    if header is None:
        raise OpnSenseParseError("malformed_header") from None
    pri = header["pri"]
    if pri is not None and (int(pri) > 191 or (len(pri) > 1 and pri[0] == "0")):
        raise OpnSenseParseError("invalid_field", "pri") from None
    timestamp_text = header["timestamp"]
    timestamp = source_timestamp(timestamp_text, context)
    metadata = {
        "syslog_pri": pri,
        "timestamp_text": timestamp_text,
        "timestamp_basis": "bsd_syslog_with_caller_context",
        "source_year": context.source_year,
        "source_utc_offset": context.source_utc_offset,
        "warnings": ("year_and_offset_supplied_by_caller",),
        "nat_context": None,
    }

    # Empty cells keep their source indexes; nothing is trimmed.
    cells = header["payload"].split(",")
    common, version = _common(cells)
    metadata.update(common)
    if version not in _IP:
        return None, metadata, "unsupported_ip_version"
    columns = _IP[version]
    protocol_text, protocol = _protocol(cells, columns)
    metadata.update(
        protocol_id=cells[columns["protocol_id"]], protocol_text=protocol_text
    )
    expected_count = _LAYOUTS.get((version, protocol))
    if expected_count is None:
        return None, metadata, "unsupported_protocol"
    if len(cells) != expected_count:
        code = "missing_field" if len(cells) < expected_count else "invalid_field"
        raise OpnSenseParseError(code) from None
    _ip_header(cells, version)
    src_ip = address(cells[columns["src"]], "src_ip", version)
    dst_ip = address(cells[columns["dst"]], "dst_ip", version)
    src_port, dst_port = _ports(cells, columns["tail"], protocol)
    fields = dict(
        source_type="opnsense",
        event_provider="OPNsense-filterlog",
        timestamp=timestamp,
        hostname=header["hostname"],
        event_action=_ACTIONS[cells[6]],
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        rule_id=metadata["label"],
    )
    return fields, metadata, None
