"""Bounded offline parser for one Wazuh search-hit containing Cowrie data."""

from datetime import datetime
from pathlib import Path
import re

from pydantic import ValidationError

from aegis_verify.connectors.wazuh._json import MAX_BYTES, decode_document
from aegis_verify.connectors.wazuh.errors import WazuhParseError
from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp

from ._context import evidence_id, session_key, validate_context
from ._fields import decimal_id, nonnegative_integer, object_field, text
from ._mapping import map_cowrie_event, source_time
from .errors import CowrieParseError
from .models import CowrieParseResult, CowrieProvenance


def _decode(raw: bytes) -> dict:
    try:
        return decode_document(raw)
    except WazuhParseError as error:
        diagnostic = error.diagnostic
        raise CowrieParseError(
            diagnostic.code,
            line=diagnostic.line,
            column=diagnostic.column,
            record_index=diagnostic.record_index,
        ) from None


def _line_end(raw: bytes) -> int:
    physical = re.split(rb"\r\n|\r|\n", raw)
    return len(physical) - (1 if physical[-1] == b"" else 0)


def parse_cowrie_wazuh_document(
    raw: bytes,
    *,
    source_ref: str,
    environment_id: str,
    sensor_id: str,
    ingested_at: datetime | str | PreciseTimestamp,
) -> CowrieParseResult:
    """Parse one exact-byte Wazuh search-hit using only ``_source.data`` facts."""

    ingestion = validate_context(source_ref, environment_id, sensor_id, ingested_at)
    document = _decode(raw)
    if document.get("_source") is None:
        raise CowrieParseError("missing_source", "_source") from None
    source = object_field(document["_source"], "_source")
    data = object_field(source.get("data"), "_source.data")
    rule = object_field(source.get("rule"), "_source.rule")
    groups = rule.get("groups")
    if type(groups) is not list or any(type(group) is not str for group in groups):
        raise CowrieParseError("invalid_field", "_source.rule.groups") from None
    if "cowrie" not in groups:
        raise CowrieParseError("unsupported_profile", "_source.rule.groups") from None

    fields, metadata = map_cowrie_event(data)
    agent = object_field(source.get("agent"), "_source.agent", optional=True)
    manager = object_field(source.get("manager"), "_source.manager", optional=True)
    fields["source_record_id"] = text(source.get("id"), "_source.id")
    metadata.update(
        wazuh_timestamp=source_time(
            source.get("timestamp"), "_source.timestamp", required=False
        ),
        wazuh_rule_id=decimal_id(rule.get("id"), "_source.rule.id"),
        wazuh_rule_level=nonnegative_integer(rule.get("level"), "_source.rule.level"),
        collector_agent_id=text(agent.get("id"), "_source.agent.id"),
        collector_agent_name=text(agent.get("name"), "_source.agent.name"),
        collector_agent_ip=text(agent.get("ip"), "_source.agent.ip"),
        collector_manager_name=text(manager.get("name"), "_source.manager.name"),
    )

    raw_hash = hash_raw_event(raw)
    event_identifier = evidence_id(environment_id, sensor_id, source_ref, raw_hash)
    last_line = _line_end(raw)
    raw_ref = f"{source_ref}#L1-L{last_line}"
    try:
        event = CanonicalEventV2(
            **fields,
            event_id=event_identifier,
            environment_id=environment_id,
            ingested_at=ingestion,
            raw_event_hash=raw_hash,
            raw_event_ref=raw_ref,
        )
    except ValidationError as error:
        location = error.errors(
            include_input=False, include_context=False, include_url=False
        )[0]["loc"]
        field_path = "canonical." + str(location[0]) if location else None
        raise CowrieParseError("canonical_validation", field_path) from None

    source_session = metadata["session"]
    provenance = CowrieProvenance(
        **metadata,
        environment_id=environment_id,
        sensor_id=sensor_id,
        source_ref=source_ref,
        line_end=last_line,
        event_id=event_identifier,
        raw_event_hash=raw_hash,
        raw_event_ref=raw_ref,
        session_key=(
            session_key(environment_id, sensor_id, source_session)
            if source_session is not None
            else None
        ),
    )
    return CowrieParseResult(event=event, provenance=provenance)


def load_cowrie_wazuh_document(
    path: str | Path,
    *,
    source_ref: str,
    environment_id: str,
    sensor_id: str,
    ingested_at: datetime | str | PreciseTimestamp,
) -> CowrieParseResult:
    """Read at most the document limit plus one without exposing the path."""

    validate_context(source_ref, environment_id, sensor_id, ingested_at)
    if not isinstance(path, (str, Path)):
        raise CowrieParseError("io_error") from None
    try:
        with open(path, "rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except (OSError, ValueError):
        raise CowrieParseError("io_error") from None
    return parse_cowrie_wazuh_document(
        raw,
        source_ref=source_ref,
        environment_id=environment_id,
        sensor_id=sensor_id,
        ingested_at=ingested_at,
    )
