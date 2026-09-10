"""Cowrie source mapping independent of Wazuh evidence framing."""

import re

from aegis_verify.models import PreciseTimestamp

from ._fields import address, port, protocol, required_text, text
from .errors import CowrieParseError


_KINDS = {
    "cowrie.session.params": ("observed", None),
    "cowrie.session.connect": ("observed", None),
    "cowrie.session.closed": ("observed", None),
    "cowrie.login.success": ("login", "success"),
    "cowrie.login.failed": ("login", "failure"),
    "cowrie.command.input": ("command", None),
}
_COMPACT_OFFSET = re.compile(r"([+-][0-9]{2})([0-9]{2})$")


def source_time(value: object, path: str, *, required: bool = True) -> PreciseTimestamp | None:
    if value is None:
        if required:
            raise CowrieParseError("missing_event_time", path) from None
        return None
    if type(value) is not str:
        raise CowrieParseError("invalid_event_time", path) from None
    try:
        normalized = _COMPACT_OFFSET.sub(r"\1:\2", value)
        return PreciseTimestamp.parse(normalized)
    except (TypeError, ValueError, OverflowError):
        raise CowrieParseError("invalid_event_time", path) from None


def map_cowrie_event(data: dict) -> tuple[dict, dict]:
    prefix = "_source.data."
    kind = required_text(data.get("eventid"), prefix + "eventid")
    if kind not in _KINDS:
        raise CowrieParseError("unsupported_profile", prefix + "eventid") from None
    action, outcome = _KINDS[kind]
    timestamp = source_time(data.get("timestamp"), prefix + "timestamp")
    session = text(data.get("session"), prefix + "session")
    if session is not None and not session.strip():
        raise CowrieParseError("invalid_field", prefix + "session") from None
    username = text(data.get("username"), prefix + "username")
    command = text(data.get("input"), prefix + "input")

    fields = {
        "source_type": "cowrie",
        "event_provider": "cowrie",
        "timestamp": timestamp,
        "event_action": action,
        "src_ip": address(data.get("src_ip"), prefix + "src_ip"),
        "src_port": port(data.get("src_port"), prefix + "src_port"),
        "dst_ip": address(data.get("dst_ip"), prefix + "dst_ip"),
        "dst_port": port(data.get("dst_port"), prefix + "dst_port"),
        "protocol": protocol(data.get("protocol"), prefix + "protocol"),
        "username": username if action == "login" else None,
        "command_line": command if action == "command" else None,
    }
    metadata = {
        "source_event_type": kind,
        "session": session,
        "source_sensor": text(data.get("sensor"), prefix + "sensor"),
        "source_uuid": text(data.get("uuid"), prefix + "uuid"),
        "arch": text(data.get("arch"), prefix + "arch"),
        "source_fraction_digits": timestamp.fractional_digits,
        "authentication_outcome": outcome,
    }
    return fields, metadata
