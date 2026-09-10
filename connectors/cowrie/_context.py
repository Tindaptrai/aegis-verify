"""Caller context and deterministic Cowrie evidence/session namespaces."""

from hashlib import sha256
import json
import re

from aegis_verify.models import PreciseTimestamp

from .errors import CowrieParseError


_SAFE_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", re.ASCII)


def validate_context(
    source_ref: object,
    environment_id: object,
    sensor_id: object,
    ingested_at: object,
) -> PreciseTimestamp:
    """Validate explicit caller facts without rewriting accepted values."""

    for value, field in ((source_ref, "source_ref"), (sensor_id, "sensor_id")):
        if type(value) is not str or _SAFE_LABEL.fullmatch(value) is None:
            raise CowrieParseError("invalid_context", field) from None
    try:
        if (
            type(environment_id) is not str
            or not environment_id.strip()
            or len(environment_id.encode("utf-8")) > 128
        ):
            raise ValueError
    except (UnicodeEncodeError, ValueError):
        raise CowrieParseError("invalid_context", "environment_id") from None
    try:
        return PreciseTimestamp.parse(ingested_at)
    except (TypeError, ValueError, OverflowError):
        raise CowrieParseError("invalid_context", "ingested_at") from None


def _compact_hash(values: list[object]) -> str:
    wire = json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return sha256(wire).hexdigest()


def evidence_id(
    environment_id: str, sensor_id: str, source_ref: str, raw_event_hash: str
) -> str:
    digest = _compact_hash(
        [
            "cowrie-wazuh-evidence-v1",
            environment_id,
            sensor_id,
            source_ref,
            1,
            raw_event_hash,
        ]
    )
    return "cowrie:wazuh-evidence-v1:" + digest


def session_key(environment_id: str, sensor_id: str, session: str) -> str:
    digest = _compact_hash(["cowrie-session-v1", environment_id, sensor_id, session])
    return "cowrie:session-v1:" + digest
