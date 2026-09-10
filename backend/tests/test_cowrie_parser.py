"""Bounded Cowrie Wazuh document tests using synthetic unit records only."""

from datetime import datetime
import hashlib
import importlib
import json

import pytest
from pydantic import ValidationError

from aegis_verify.models import CanonicalEventV2, PreciseTimestamp


CONTEXT = {
    "source_ref": "unit-cowrie.json",
    "environment_id": "unit-lab",
    "sensor_id": "unit-honeypot",
    "ingested_at": "2026-01-02T03:05:00Z",
}
BASE_DATA = {
    "eventid": "cowrie.login.failed",
    "timestamp": "2026-01-02T03:04:05.123456+0000",
    "src_ip": "192.0.2.20",
    "src_port": "54321",
    "dst_ip": "2001:db8::10",
    "dst_port": 22,
    "protocol": "ssh",
    "session": "test-session",
    "sensor": "source-sensor",
    "uuid": "source-uuid",
    "arch": "amd64",
    "username": "unit-user",
    "password": "synthetic-credential-only",
    "input": "echo synthetic-command",
}
_MISSING = object()


def raw_document(*, data=None, source=None):
    payload = dict(BASE_DATA)
    for key, value in (data or {}).items():
        if value is _MISSING:
            payload.pop(key, None)
        else:
            payload[key] = value
    wrapper = {
        "id": "unit-alert-001",
        "timestamp": "2026-01-02T03:04:06.123+0000",
        "rule": {"id": "55001", "level": 3, "groups": ["cowrie", "honeypot"]},
        "agent": {"id": "001", "name": "unit-agent", "ip": "192.0.2.10"},
        "manager": {"name": "unit-manager"},
        "data": payload,
        "full_log": "synthetic raw-only field",
    }
    for key, value in (source or {}).items():
        if value is _MISSING:
            wrapper.pop(key, None)
        else:
            wrapper[key] = value
    return json.dumps({"_source": wrapper}, ensure_ascii=True, separators=(",", ":")).encode()


def api():
    module = importlib.import_module("aegis_verify.connectors.cowrie")
    assert callable(getattr(module, "parse_cowrie_wazuh_document", None))
    return module


def parse(raw=None, **changes):
    return api().parse_cowrie_wazuh_document(raw or raw_document(), **(CONTEXT | changes))


def mutate(raw, path, value=_MISSING):
    document = json.loads(raw)
    parts = path.split(".")
    parent = document
    for part in parts[:-1]:
        parent = parent[part]
    if value is _MISSING:
        parent.pop(parts[-1], None)
    else:
        parent[parts[-1]] = value
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode()


def test_exact_evidence_identity_and_provenance_contract():
    result = parse()
    event, provenance = result.event, result.provenance
    assert type(event) is CanonicalEventV2
    assert event.raw_event_hash == "a945358acc56ba6194397ac58efb16ac0b30fd2f955b32818ab4a1333c0fdcda"
    assert event.event_id == "cowrie:wazuh-evidence-v1:bdad35fadb5caf03bd87e0ad51704d2873a598a9af10cca5c750424acdd24248"
    assert event.raw_event_ref == "unit-cowrie.json#L1-L1"
    assert provenance.mapping_version == "cowrie-wazuh-v1"
    assert provenance.input_profile == "wazuh-cowrie-v1"
    assert provenance.payload_basis == "wazuh._source.data"
    assert provenance.timestamp_basis == "cowrie.data.timestamp"
    assert provenance.source_record_namespace == "wazuh.alert.id"
    assert provenance.environment_id == "unit-lab"
    assert provenance.sensor_id == "unit-honeypot"
    assert provenance.source_ref == "unit-cowrie.json"
    assert provenance.record_index == provenance.line_start == 1
    assert provenance.line_end == 1


@pytest.mark.parametrize(
    "path,value,code",
    [
        ("_source", _MISSING, "missing_source"),
        ("_source", None, "missing_source"),
        ("_source", [], "invalid_field"),
        ("_source.data", None, "invalid_field"),
        ("_source.rule", None, "invalid_field"),
        ("_source.rule.groups", None, "invalid_field"),
        ("_source.rule.groups", "cowrie", "invalid_field"),
        ("_source.rule.groups", ["cowrie", 1], "invalid_field"),
        ("_source.rule.groups", ["honeypot"], "unsupported_profile"),
        ("_source.agent", [], "invalid_field"),
        ("_source.manager", 1, "invalid_field"),
    ],
)
def test_wrapper_profile_fails_closed(path, value, code):
    with pytest.raises(api().CowrieParseError) as caught:
        parse(mutate(raw_document(), path, value))
    assert caught.value.code == code
    assert caught.value.field_path == path


@pytest.mark.parametrize(
    "path,value",
    [
        ("_source.id", True),
        ("_source.timestamp", 1),
        ("_source.timestamp", "not-time"),
        ("_source.rule.id", True),
        ("_source.rule.id", -1),
        ("_source.rule.level", True),
        ("_source.rule.level", -1),
        ("_source.agent.id", 1),
        ("_source.agent.name", []),
        ("_source.agent.ip", {}),
        ("_source.manager.name", False),
    ],
)
def test_wrong_optional_collector_metadata_types_fail(path, value):
    with pytest.raises(api().CowrieParseError) as caught:
        parse(mutate(raw_document(), path, value))
    expected = "invalid_event_time" if path == "_source.timestamp" else "invalid_field"
    assert caught.value.code == expected
    assert caught.value.field_path == path


@pytest.mark.parametrize(
    "path,fields",
    [
        ("_source.id", ("source_record_id",)),
        ("_source.timestamp", ("wazuh_timestamp",)),
        ("_source.agent", ("collector_agent_id", "collector_agent_name", "collector_agent_ip")),
        ("_source.manager", ("collector_manager_name",)),
        ("_source.rule.id", ("wazuh_rule_id",)),
        ("_source.rule.level", ("wazuh_rule_level",)),
    ],
)
@pytest.mark.parametrize("value", [None, _MISSING])
def test_missing_optional_collector_metadata_stays_null(path, fields, value):
    result = parse(mutate(raw_document(), path, value))
    for field in fields:
        target = result.event if field == "source_record_id" else result.provenance
        assert getattr(target, field) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_ref", "../private"),
        ("source_ref", "a\n"),
        ("source_ref", "a" * 129),
        ("source_ref", None),
        ("sensor_id", "sensor/name"),
        ("sensor_id", "x" * 129),
        ("sensor_id", True),
        ("environment_id", ""),
        ("environment_id", " "),
        ("environment_id", "\ud800"),
        ("environment_id", "é" * 65),
        ("ingested_at", None),
        ("ingested_at", "2026-01-01"),
        ("ingested_at", datetime(2026, 1, 1)),
    ],
)
def test_invalid_context_is_rejected_before_input(field, value):
    with pytest.raises(api().CowrieParseError) as caught:
        api().parse_cowrie_wazuh_document(b"", **(CONTEXT | {field: value}))
    assert caught.value.code == "invalid_context"
    assert caught.value.field_path == field


def test_context_accepts_exact_environment_and_explicit_ingestion_types():
    precise = PreciseTimestamp.parse("2026-01-02T03:05:00.123456789Z")
    from_precise = parse(environment_id=" unit-lab ", ingested_at=precise)
    from_datetime = parse(ingested_at=datetime.fromisoformat("2026-01-02T10:05:00.123456+07:00"))
    assert from_precise.event.environment_id == " unit-lab "
    assert from_precise.event.ingested_at is precise
    assert from_datetime.event.ingested_at.isoformat() == "2026-01-02T03:05:00.123456Z"


@pytest.mark.parametrize(
    "raw,code",
    [
        (b"", "invalid_json"),
        (b"{", "invalid_json"),
        (b"[]", "invalid_root"),
        (b"\xff", "invalid_encoding"),
        (b'{"PRIVATE_VALUE":1,"PRIVATE_VALUE":2}', "duplicate_key"),
        (b'{"v":NaN}', "invalid_number"),
        (b'{"v":1e309}', "invalid_number"),
        (b'{"v":' + b"1" * 129 + b"}", "invalid_number"),
        (b'{"v":"\\ud800"}', "invalid_unicode"),
        (b'{"a":' + b"[" * 20 + b"0" + b"]" * 20 + b"}", "max_depth"),
        (b'{"a":[' + b"0," * 9999 + b"0]}", "max_nodes"),
        (b" " * (256 * 1024 + 1), "input_too_large"),
    ],
    ids=[
        "empty", "malformed", "array-root", "encoding", "duplicate-key",
        "nan", "float-overflow", "long-number", "unicode", "depth",
        "nodes", "size",
    ],
)
def test_bounded_decoder_errors_are_value_safe(raw, code):
    with pytest.raises(api().CowrieParseError) as caught:
        api().parse_cowrie_wazuh_document(raw, **CONTEXT)
    assert caught.value.code == code
    assert "PRIVATE_VALUE" not in str(caught.value)
    assert caught.value.__suppress_context__


def test_non_bytes_input_is_rejected_without_coercion():
    with pytest.raises(api().CowrieParseError) as caught:
        api().parse_cowrie_wazuh_document("{}", **CONTEXT)
    assert caught.value.code == "input_type"


def test_exact_bytes_bom_and_physical_line_endings_drive_evidence_identity():
    raw = raw_document()
    original = parse(raw)
    bom = b"\xef\xbb\xbf" + raw
    crlf = b"\xef\xbb\xbf\r\n\r\n" + raw
    cr = raw + b"\r\r"
    for changed in (bom, crlf, cr):
        result = parse(changed)
        assert result.event.raw_event_hash == hashlib.sha256(changed).hexdigest()
        assert result.event.event_id != original.event.event_id
    assert parse(bom).event.raw_event_ref == "unit-cowrie.json#L1-L1"
    assert parse(crlf).event.raw_event_ref == "unit-cowrie.json#L1-L3"
    assert parse(cr).event.raw_event_ref == "unit-cowrie.json#L1-L2"


def test_identity_stability_and_namespaces():
    raw = raw_document()
    original = parse(raw)
    assert parse(raw, ingested_at="2027-01-01T00:00:00Z").event.event_id == original.event.event_id
    assert parse(raw, source_ref="other.json").event.event_id != original.event.event_id
    assert parse(raw, sensor_id="other-sensor").event.event_id != original.event.event_id
    assert parse(raw, environment_id="other-env").event.event_id != original.event.event_id
    assert original.event.event_id.startswith("cowrie:wazuh-evidence-v1:")
    assert original.provenance.session_key.startswith("cowrie:session-v1:")


def test_unicode_line_separators_are_not_physical_lines():
    raw = raw_document(data={"unknown": "\u2028\u0085\u2029"})
    assert parse(raw).provenance.line_end == 1


def test_loader_validates_context_before_io_and_reads_bounded_exact_bytes(tmp_path):
    path = tmp_path / "unit.json"
    raw = raw_document()
    path.write_bytes(raw)
    result = api().load_cowrie_wazuh_document(path, **CONTEXT)
    assert result.event.raw_event_hash == "a945358acc56ba6194397ac58efb16ac0b30fd2f955b32818ab4a1333c0fdcda"
    assert path.read_bytes() == raw

    with pytest.raises(api().CowrieParseError) as caught:
        api().load_cowrie_wazuh_document(tmp_path / "PRIVATE-NOT-READ", **(CONTEXT | {"sensor_id": "bad/name"}))
    assert caught.value.code == "invalid_context"
    assert "PRIVATE" not in str(caught.value)

    for bad_path in (tmp_path / "PRIVATE-NOT-FOUND", None, 0):
        with pytest.raises(api().CowrieParseError) as caught:
            api().load_cowrie_wazuh_document(bad_path, **CONTEXT)
        assert caught.value.code == "io_error"
        assert "PRIVATE" not in str(caught.value)

    path.write_bytes(b" " * (256 * 1024 + 1))
    with pytest.raises(api().CowrieParseError) as caught:
        api().load_cowrie_wazuh_document(path, **CONTEXT)
    assert caught.value.code == "input_too_large"


def test_public_diagnostics_sanitize_direct_construction():
    error = api().CowrieParseError("PRIVATE_CODE", "PRIVATE_FIELD", line=0, column=True, record_index=0)
    diagnostic = error.diagnostic
    assert error.code == diagnostic.code == "invalid_field"
    assert error.field_path is diagnostic.field_path is None
    assert error.line is diagnostic.line is None
    assert error.column is diagnostic.column is None
    assert error.record_index == diagnostic.record_index == 1
    assert "PRIVATE" not in str(error)
    direct = api().CowrieDiagnostic("PRIVATE_CODE", "PRIVATE_FIELD", record_index=0, line=0, column=True)
    assert direct.code == "invalid_field"
    assert direct.field_path is None
    assert direct.record_index == 1 and direct.line is direct.column is None


def test_models_are_immutable_strict_extra_forbid_and_identity_consistent():
    result = parse()
    event, provenance = result.event, result.provenance
    with pytest.raises(ValidationError):
        provenance.session = "other"
    with pytest.raises(ValidationError):
        result.event = event
    with pytest.raises(ValidationError):
        api().CowrieProvenance(**(provenance.model_dump() | {"extra": "value"}))
    with pytest.raises(ValidationError):
        api().CowrieParseResult(event=event, provenance=provenance, extra="value")


@pytest.mark.parametrize(
    "change",
    [
        {"session_key": "cowrie:session-v1:" + "0" * 64},
        {"session": None},
        {"line_end": 0},
        {"raw_event_ref": "unit-cowrie.json#L1-L2"},
        {"event_id": "cowrie:wazuh-evidence-v1:" + "0" * 64},
        {"authentication_outcome": "success"},
        {"source_event_type": "cowrie.command.input"},
    ],
)
def test_provenance_constructor_rejects_invalid_relationships(change):
    provenance = parse().provenance
    with pytest.raises(ValidationError):
        api().CowrieProvenance(**(provenance.model_dump() | change))


@pytest.mark.parametrize(
    "event_change",
    [
        {"event_id": "cowrie:wazuh-evidence-v1:" + "0" * 64},
        {"raw_event_hash": "0" * 64},
        {"raw_event_ref": "other#L1-L1"},
        {"environment_id": "other-env"},
        {"event_action": "observed"},
        {"source_type": "wazuh"},
        {"event_provider": "other"},
    ],
)
def test_result_constructor_rejects_event_provenance_mismatches(event_change):
    result = parse()
    bad_event = result.event.model_copy(update=event_change)
    with pytest.raises(ValidationError):
        api().CowrieParseResult(event=bad_event, provenance=result.provenance)


def test_result_constructor_rejects_fraction_mismatch():
    result = parse()
    bad_provenance = result.provenance.model_copy(update={"source_fraction_digits": 9})
    with pytest.raises(ValidationError):
        api().CowrieParseResult(event=result.event, provenance=bad_provenance)
