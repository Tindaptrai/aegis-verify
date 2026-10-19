"""Four explicit offline search-hit profiles; no live collection or execution."""

from datetime import datetime
from ipaddress import ip_address
import json
import re

from pydantic import ValidationError

from aegis_verify.connectors.wazuh._json import decode_document
from aegis_verify.connectors.wazuh.errors import WazuhParseError
from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp

from ._native import parse_native, timestamp
from .errors import ElasticParseError
from .models import ElasticAncestor, ElasticParseResult, ElasticProvenance


def _context(source_ref, environment_id, ingested_at):
    if type(source_ref) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", source_ref) is None:
        raise ElasticParseError("invalid_context", "source_ref")
    if type(environment_id) is not str or not environment_id.strip():
        raise ElasticParseError("invalid_context", "environment_id")
    try:
        if len(environment_id.encode("utf-8")) > 128:
            raise ElasticParseError("invalid_context", "environment_id")
    except UnicodeEncodeError:
        raise ElasticParseError("invalid_context", "environment_id") from None
    try:
        return PreciseTimestamp.parse(ingested_at)
    except (TypeError, ValueError):
        raise ElasticParseError("invalid_context", "ingested_at") from None


def _object(parent, key, field, *, required=False):
    value = parent.get(key)
    if value is None and not required:
        return {}
    if type(value) is not dict:
        raise ElasticParseError("invalid_field", field)
    return value


def _string(parent, key, field, *, required=False):
    value = parent.get(key)
    if value is None and not required:
        return None
    if type(value) is not str or (required and not value.strip()):
        raise ElasticParseError("invalid_field", field)
    return value


def _integer(parent, key, field):
    value = parent.get(key)
    if value is not None and (type(value) is not int or value < 0):
        raise ElasticParseError("invalid_field", field)
    return value


def _alias(parent, key, expected, field, *, kind="text", hostname=False):
    if key not in parent:
        return
    value = _integer(parent, key, field) if kind == "integer" else _string(parent, key, field)
    # Missing native optional facts stay null. An alias is not permission to
    # synthesize that fact; still validate its type even when no comparison exists.
    if expected is None or value is None:
        return
    if kind == "address":
        try:
            equal = ip_address(value) == expected
        except ValueError:
            raise ElasticParseError("invalid_field", field) from None
    elif hostname and type(value) is str and type(expected) is str:
        # Windows DNS computer identity is case insensitive. Preserve XML spelling.
        equal = value.casefold() == expected.casefold()
    else:
        equal = value == expected
    if not equal:
        raise ElasticParseError("identity_conflict", field)


def _optional_time(parent, key, field):
    value = _string(parent, key, field)
    if value is not None:
        timestamp(value, field)
    return value


def _script_text_alias(file, expected, metadata):
    key = "script_block_text"
    if key not in file:
        return
    value = _string(file, key, "powershell.file.script_block_text")
    if value is None or value == expected:
        return
    # The reviewed Winlogbeat powershell_operational pipeline trims this one
    # noncanonical field. XML 1.0 also normalizes literal line endings. Compare
    # only that explicit transform, keep original bytes, and expose a warning.
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    if normalized != expected.strip(" \t\r\n\v\f"):
        raise ElasticParseError("identity_conflict", "powershell.file.script_block_text")
    metadata["warnings"] = ("powershell_script_text_xml_newlines_ascii_trim",)


def _identity_aliases(source, mapped, metadata, data, execution_pid):
    event = _object(source, "event", "event", required=True)
    winlog = _object(source, "winlog", "winlog")
    host = _object(source, "host", "host")
    # These profiles review nested ECS identity objects, not arbitrary flattening.
    reviewed_roots = ("event.", "winlog.", "host.", "process.", "source.", "destination.", "network.", "powershell.", "fields.")
    if any(key.startswith(reviewed_roots) and key != "event.kind" for key in source):
        raise ElasticParseError("unsupported_profile")
    for parent, key, expected, path in (
        (event, "code", metadata["windows_event_id"], "event.code"),
        (event, "provider", metadata["windows_provider"], "event.provider"),
        (winlog, "event_id", metadata["windows_event_id"], "winlog.event_id"),
        (winlog, "provider_name", metadata["windows_provider"], "winlog.provider_name"),
        (winlog, "channel", metadata["windows_channel"], "winlog.channel"),
        (winlog, "record_id", metadata["windows_record_id"], "winlog.record_id"),
    ):
        _alias(parent, key, expected, path)
    for parent, key, path in ((host, "hostname", "host.hostname"), (host, "name", "host.name"),
                              (winlog, "computer_name", "winlog.computer_name")):
        _alias(parent, key, mapped["hostname"], path, hostname=True)
    win_process = _object(winlog, "process", "winlog.process.pid")
    _alias(win_process, "pid", execution_pid, "winlog.process.pid", kind="integer")
    if metadata["windows_event_id"] in {"1", "3"}:
        process = _object(source, "process", "process")
        _alias(process, "pid", mapped.get("process_id"), "process.pid", kind="integer")
        _alias(process, "executable", mapped.get("process_name"), "process.executable")
        _alias(process, "entity_id", metadata.get("process_guid"), "process.entity_id")
        if metadata["windows_event_id"] == "1":
            _alias(process, "command_line", mapped.get("command_line"), "process.command_line")
            parent = _object(process, "parent", "process.parent")
            _alias(parent, "pid", metadata.get("parent_process_id"), "process.parent.pid", kind="integer")
            _alias(parent, "executable", mapped.get("parent_process_name"), "process.parent.executable")
            _alias(parent, "entity_id", metadata.get("parent_process_guid"), "process.parent.entity_id")
        else:
            for root, ip_field, port_field in (("source", "src_ip", "src_port"), ("destination", "dst_ip", "dst_port")):
                endpoint = _object(source, root, root)
                address = mapped.get(ip_field)
                _alias(endpoint, "ip", address, root + ".ip", kind="address")
                _alias(endpoint, "port", mapped.get(port_field), root + ".port", kind="integer")
            network = _object(source, "network", "network")
            _alias(network, "transport", mapped.get("protocol"), "network.transport")
    else:
        powershell = _object(source, "powershell", "powershell")
        _alias(powershell, "sequence", 1, "powershell.sequence", kind="integer")
        _alias(powershell, "total", 1, "powershell.total", kind="integer")
        file = _object(powershell, "file", "powershell.file")
        _alias(file, "script_block_id", data.get("ScriptBlockId"), "powershell.file.script_block_id")
        _script_text_alias(file, data["ScriptBlockText"], metadata)


def _alert_metadata(source):
    if source.get("event.kind") != "signal" or "kind" in source.get("event", {}) or "kibana" in source:
        raise ElasticParseError("unsupported_profile", "event.kind")
    # A nested duplicate of a dotted object would make its meaning ambiguous.
    if any(key in source for key in ("kibana.alert", "kibana.alert.rule", "kibana.alert.original_event")):
        raise ElasticParseError("unsupported_profile", "kibana.alert")
    event_time = timestamp(source.get("kibana.alert.start"), "kibana.alert.start")
    rule_id = _string(source, "kibana.alert.rule.rule_id", "kibana.alert.rule.rule_id", required=True)
    parameters = _object(source, "kibana.alert.rule.parameters", "kibana.alert.rule.parameters")
    _alias(parameters, "rule_id", rule_id, "kibana.alert.rule.parameters.rule_id")
    _alias(source, "kibana.alert.original_event.kind", "event", "kibana.alert.original_event.kind")
    metadata = dict(
        alert_original_time=_optional_time(source, "kibana.alert.original_time", "kibana.alert.original_time"),
        alert_uuid=_string(source, "kibana.alert.uuid", "kibana.alert.uuid"),
        rule_revision=_integer(source, "kibana.alert.rule.revision", "kibana.alert.rule.revision"),
        alert_severity=_string(source, "kibana.alert.severity", "kibana.alert.severity"),
        risk_score=_integer(source, "kibana.alert.risk_score", "kibana.alert.risk_score"),
    )
    ancestors = source.get("kibana.alert.ancestors")
    if type(ancestors) is not list or not ancestors or len(ancestors) > 100:
        raise ElasticParseError("invalid_field", "kibana.alert.ancestors")
    parsed = []
    for ancestor in ancestors:
        if type(ancestor) is not dict:
            raise ElasticParseError("invalid_field", "kibana.alert.ancestors")
        index = _string(ancestor, "index", "kibana.alert.ancestors.index", required=True)
        document_id = _string(ancestor, "id", "kibana.alert.ancestors.id", required=True)
        kind = _string(ancestor, "type", "kibana.alert.ancestors.type", required=True)
        depth = _integer(ancestor, "depth", "kibana.alert.ancestors.depth")
        if depth is None:
            raise ElasticParseError("invalid_field", "kibana.alert.ancestors.depth")
        parsed.append(ElasticAncestor(source_index=index, source_document_id=document_id,
                                      ancestor_type=kind, depth=depth))
    metadata["ancestors"] = tuple(parsed)
    return event_time, rule_id, metadata


def _parse(raw, *, kind, source_ref, environment_id, ingested_at):
    ingestion = _context(source_ref, environment_id, ingested_at)
    try:
        document = decode_document(raw)
    except WazuhParseError as error:
        diagnostic = error.diagnostic
        raise ElasticParseError(diagnostic.code, line=diagnostic.line, column=diagnostic.column) from None
    source_index = _string(document, "_index", "_index", required=True)
    source_document_id = _string(document, "_id", "_id", required=True)
    if document.get("_source") is None:
        raise ElasticParseError("missing_source", "_source")
    source = _object(document, "_source", "_source", required=True)
    source_event = _object(source, "event", "event", required=True)
    is_alert = kind == "alert"
    if not is_alert:
        if ("event.kind" in source or "kibana" in source or
                any(key.startswith("kibana.alert") for key in source) or source_event.get("kind") != "event"):
            raise ElasticParseError("unsupported_profile", "event.kind")
    code = "4104" if is_alert else kind
    mapped, metadata, native_data, execution_pid = parse_native(source_event.get("original"), code)
    _identity_aliases(source, mapped, metadata, native_data, execution_pid)
    fields = _object(source, "fields", "fields")
    _alias(fields, "environment_id", environment_id, "fields.environment_id")
    host = _object(source, "host", "host")
    agent = _object(source, "agent", "agent")
    mapped.update(asset_id=_string(host, "id", "host.id"), source_type="elastic",
                  source_record_id=source_document_id, environment_id=environment_id,
                  ingested_at=ingestion)
    metadata.update(
        normalized_timestamp=_optional_time(source, "@timestamp", "@timestamp"),
        source_ingested_at=_optional_time(source_event, "ingested", "event.ingested"),
        collector_agent_id=_string(agent, "id", "agent.id"),
        collector_agent_name=_string(agent, "name", "agent.name"),
        collector_agent_type=_string(agent, "type", "agent.type"),
    )
    if is_alert:
        for key, expected in (("code", metadata["windows_event_id"]),
                              ("provider", metadata["windows_provider"]),
                              ("original", source_event["original"])):
            field = "kibana.alert.original_event." + key
            _alias(source, field, expected, field)
        alert_time, rule_id, alert_metadata = _alert_metadata(source)
        mapped.update(timestamp=alert_time, rule_id=rule_id, event_provider="elastic-security")
        metadata.update(alert_metadata)
    raw_hash = hash_raw_event(raw)
    identity = ["elastic-evidence-v1", environment_id, source_ref, 1, raw_hash]
    event_id = "elastic:evidence-v1:" + hash_raw_event(json.dumps(
        identity, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))
    raw_ref = source_ref + "#record=1"
    mapped.update(event_id=event_id, raw_event_hash=raw_hash, raw_event_ref=raw_ref)
    try:
        event = CanonicalEventV2.model_validate(mapped)
    except ValidationError as error:
        location = error.errors(include_input=False, include_context=False, include_url=False)[0]["loc"]
        raise ElasticParseError("canonical_validation", "canonical." + str(location[0]) if location else None) from None
    mapping = {"1": "elastic-sysmon1-v1", "3": "elastic-sysmon3-v1",
               "4104": "elastic-powershell4104-v1", "alert": "elastic-security-alert-v1"}[kind]
    provenance = ElasticProvenance(
        mapping_version=mapping, timestamp_basis="kibana.alert.start" if is_alert else "windows.systemTime",
        source_fraction_digits=event.timestamp.fractional_digits,
        source_ref=source_ref, line_end=raw.count(b"\n") + int(bool(raw) and not raw.endswith(b"\n")),
        raw_event_ref=raw_ref, raw_event_hash=raw_hash, event_id=event_id,
        source_index=source_index, source_document_id=source_document_id, **metadata,
    )
    return ElasticParseResult(event=event, provenance=provenance)


def parse_elastic_sysmon1_document(raw: bytes, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp) -> ElasticParseResult:
    """Parse one exported Sysmon process-creation hit using native System.TimeCreated."""
    return _parse(raw, kind="1", source_ref=source_ref, environment_id=environment_id, ingested_at=ingested_at)


def parse_elastic_sysmon3_document(raw: bytes, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp) -> ElasticParseResult:
    """Parse one exported Sysmon TCP/UDP observation hit; never infer prevention."""
    return _parse(raw, kind="3", source_ref=source_ref, environment_id=environment_id, ingested_at=ingested_at)


def parse_elastic_powershell4104_document(raw: bytes, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp) -> ElasticParseResult:
    """Parse one native complete 1/1 script block; never execute or assemble text."""
    return _parse(raw, kind="4104", source_ref=source_ref, environment_id=environment_id, ingested_at=ingested_at)


def parse_elastic_security_alert_document(raw: bytes, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp) -> ElasticParseResult:
    """Parse the explicit dotted-key Elastic Security alert for a copied 4104 hit."""
    return _parse(raw, kind="alert", source_ref=source_ref, environment_id=environment_id, ingested_at=ingested_at)
