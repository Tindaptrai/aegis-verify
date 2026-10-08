"""Artificial contract-test inputs; these are NOT incident evidence or vendor logs."""

import json
from datetime import datetime, timedelta, timezone
from ipaddress import IPv6Address

import pytest
from pydantic import ValidationError

from aegis_verify.models import CanonicalEvent


@pytest.fixture
def minimal_event():
    # Literal SHA-256 vector for b"abc"; no source-tool log is implied.
    return {
        "event_id": "unit-event-001",
        "timestamp": "2026-09-05T22:30:00+07:00",
        "source_type": "pfsense",
        "environment_id": "unit-environment",
        "raw_event_ref": "unit-only/record.txt:1",
        "raw_event_hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "ingested_at": "2026-09-05T22:31:00+07:00",
    }


def test_minimal_event_preserves_provenance_and_serializes_unknowns_as_null(minimal_event):
    output = CanonicalEvent.model_validate(minimal_event).model_dump(mode="json")
    assert output["schema_version"] == "1.0"
    assert output["event_id"] == "unit-event-001"
    assert output["raw_event_ref"] == "unit-only/record.txt:1"
    assert output["timestamp"] == "2026-09-05T15:30:00Z"
    assert output["ingested_at"] == "2026-09-05T15:31:00Z"
    for field in (
        "source_record_id", "event_provider", "asset_id", "hostname", "username",
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "process_name",
        "process_id", "parent_process_name", "command_line", "file_path",
        "file_hash", "rule_id", "signature_id", "event_action", "severity", "technique_ids",
    ):
        assert field in output
        assert output[field] is None


def test_full_event_round_trip_preserves_context_without_interpreting_it(minimal_event):
    data = minimal_event | {
        "source_type": "wazuh", "source_record_id": "unit-source-1",
        "event_provider": "Microsoft-Windows-Sysmon", "asset_id": "unit-asset",
        "hostname": "unit-host", "username": "unit-user",
        "src_ip": "192.0.2.10", "src_port": 49152,
        "dst_ip": "2001:db8::10", "dst_port": 8000, "protocol": "tcp",
        "process_name": "example.exe", "process_id": 123,
        "parent_process_name": "example-parent.exe",
        "command_line": "  <untrusted> example --flag  ",
        "file_path": "unit-only/example.txt", "file_hash": "source-format-hash",
        "rule_id": "unit-rule", "signature_id": "unit-signature",
        "event_action": "observed", "severity": 3, "technique_ids": ["T1059.001"],
        "session_key": "cowrie:session-v1:" + "b" * 64,
    }
    event = CanonicalEvent.model_validate(data)
    encoded = event.model_dump_json()
    assert CanonicalEvent.model_validate_json(encoded) == event
    assert json.loads(encoded) == data | {
        "schema_version": "1.0", "timestamp": "2026-09-05T15:30:00Z",
        "ingested_at": "2026-09-05T15:31:00Z",
    }


@pytest.mark.parametrize("field", [
    "event_id", "timestamp", "source_type", "environment_id",
    "raw_event_ref", "raw_event_hash", "ingested_at",
])
def test_required_provenance_cannot_be_omitted(minimal_event, field):
    minimal_event.pop(field)
    with pytest.raises(ValidationError) as error:
        CanonicalEvent.model_validate(minimal_event)
    assert field in {item["loc"][0] for item in error.value.errors()}


@pytest.mark.parametrize("field,value", [
    ("event_id", ""), ("event_id", " \t"), ("event_id", None), ("event_id", 1),
    ("environment_id", " "), ("raw_event_ref", ""), ("raw_event_ref", "\n"),
    ("schema_version", "2.0"), ("source_type", "sysmon"), ("source_type", None),
    ("source_type", b"wazuh"), ("event_action", b"blocked"),
    ("event_action", "detected"), ("rule_id", 123), ("signature_id", True),
    ("raw_event_hash", ""), ("raw_event_hash", "a" * 63),
    ("raw_event_hash", "g" * 64), ("raw_event_hash", "A" * 64),
    ("dst_port", -1), ("dst_port", 65536), ("dst_port", "8000"),
    ("src_port", True), ("src_port", 80.5),
    ("src_ip", "999.0.0.1"), ("src_ip", 1234), ("src_ip", True),
    ("dst_ip", "example.invalid"), ("dst_ip", "192.0.2.0/24"),
    ("process_id", -1), ("process_id", True), ("severity", -1),
    ("technique_ids", [" "]), ("technique_ids", [123]), ("technique_ids", "T1059"),
    ("technique_ids", {"T1059", "T1041"}),
    ("vendor_specific_field", "unmapped"),
])
def test_invalid_values_report_the_offending_field(minimal_event, field, value):
    with pytest.raises(ValidationError) as error:
        CanonicalEvent.model_validate(minimal_event | {field: value})
    assert field in {item["loc"][0] for item in error.value.errors()}


@pytest.mark.parametrize("field", ["timestamp", "ingested_at"])
@pytest.mark.parametrize("value", [
    "not-a-date", "2026-02-30T22:30:00Z", "2026-09-05", "2026-09-05T22:30:00",
    "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00",
    "2026-09-05T22:30:00-00:00", "2026-09-05T22:30:00.1234567Z",
    1788600000, "1788600000", True, None, datetime(2026, 9, 5, 22, 30),
])
def test_ambiguous_or_lossy_timestamps_are_rejected(minimal_event, field, value):
    with pytest.raises(ValidationError) as error:
        CanonicalEvent.model_validate(minimal_event | {field: value})
    assert field in {item["loc"][0] for item in error.value.errors()}


@pytest.mark.parametrize("timestamp,expected", [
    ("2026-09-05T00:30:00+07:00", "2026-09-04T17:30:00Z"),
    ("2026-09-05T23:30:00-05:00", "2026-09-06T04:30:00Z"),
    ("2026-09-05T15:30:00.123456Z", "2026-09-05T15:30:00.123456Z"),
    (datetime(2026, 9, 5, 22, 30, tzinfo=timezone(timedelta(hours=7))),
     "2026-09-05T15:30:00Z"),
])
def test_time_normalization_preserves_the_instant(minimal_event, timestamp, expected):
    event = CanonicalEvent.model_validate(minimal_event | {"timestamp": timestamp})
    assert event.model_dump(mode="json")["timestamp"] == expected
    assert event.timestamp.utcoffset() == timedelta(0)


@pytest.mark.parametrize("source", ["wazuh", "suricata", "pfsense", "cowrie", "snort", "opnsense"])
def test_supported_sources_survive_json_serialization(minimal_event, source):
    event = CanonicalEvent.model_validate(minimal_event | {"source_type": source})
    assert json.loads(event.model_dump_json())["source_type"] == source


@pytest.mark.parametrize("action", [
    "observed", "allowed", "blocked", "redirected", "login", "command", "other", None,
])
def test_source_action_is_preserved_without_classification(minimal_event, action):
    event = CanonicalEvent.model_validate(minimal_event | {"event_action": action})
    assert event.model_dump(mode="json")["event_action"] == action


@pytest.mark.parametrize("port", [0, 65535, None])
def test_port_boundaries_are_preserved(minimal_event, port):
    event = CanonicalEvent.model_validate(minimal_event | {"src_port": port, "dst_port": port})
    assert event.src_port == port
    assert event.dst_port == port


def test_explicit_null_and_empty_technique_mapping_remain_distinct(minimal_event):
    unknown = CanonicalEvent.model_validate(minimal_event | {"technique_ids": None})
    empty = CanonicalEvent.model_validate(minimal_event | {"technique_ids": []})
    assert unknown.model_dump(mode="json")["technique_ids"] is None
    assert empty.model_dump(mode="json")["technique_ids"] == []


def test_validated_event_cannot_be_changed_without_revalidation(minimal_event):
    event = CanonicalEvent.model_validate(minimal_event | {"technique_ids": ["T1059"]})
    with pytest.raises(ValidationError):
        event.dst_port = -1
    with pytest.raises(TypeError):
        event.technique_ids[0] = ""


def test_generated_schema_rejects_extra_fields_and_documents_required_provenance():
    schema = CanonicalEvent.model_json_schema()
    assert schema["additionalProperties"] is False
    assert {"event_id", "raw_event_ref", "raw_event_hash", "timestamp"} <= set(schema["required"])
    assert "null" in {entry.get("type") for entry in schema["properties"]["process_name"]["anyOf"]}


def test_formatted_validation_error_does_not_echo_untrusted_input(minimal_event):
    marker = "UNTRUSTED_UNIT_INPUT"
    with pytest.raises(ValidationError) as error:
        CanonicalEvent.model_validate(minimal_event | {"event_action": marker})
    assert marker not in str(error.value)


OPTIONAL_TEXT_FIELDS = [
    "source_record_id", "event_provider", "asset_id", "hostname", "username",
    "protocol", "process_name", "parent_process_name", "command_line",
    "file_path", "file_hash", "rule_id", "signature_id",
]


@pytest.mark.parametrize("field", OPTIONAL_TEXT_FIELDS)
@pytest.mark.parametrize("codepoint", [0xD800, 0xDFFF], ids=["high", "low"])
def test_json_decoded_surrogates_are_rejected_before_serialization(minimal_event, field, codepoint):
    # json.loads accepts escaped lone surrogates; a future parser may use it.
    marker = "UNTRUSTED_UNIT_INPUT"
    wire = json.dumps(minimal_event | {field: marker + chr(codepoint)})
    decoded = json.loads(wire)
    with pytest.raises(ValidationError) as error:
        CanonicalEvent.model_validate(decoded)
    assert field in {item["loc"][0] for item in error.value.errors()}
    assert marker not in str(error.value)


@pytest.mark.parametrize("field", OPTIONAL_TEXT_FIELDS)
@pytest.mark.parametrize("text", [
    "Tiếng Việt 🚀",
    "  a\u0301\t\n",  # Decomposed accent: must not normalize or strip it.
    "",  # Empty source text remains distinct from absent/null context.
], ids=["vietnamese-emoji", "decomposed-whitespace", "empty"])
def test_valid_unicode_is_preserved_through_both_json_paths(minimal_event, field, text):
    wire = json.dumps(minimal_event | {field: text})
    event = CanonicalEvent.model_validate(json.loads(wire))
    direct = CanonicalEvent.model_validate_json(wire)
    assert direct == event
    assert json.loads(event.model_dump_json())[field] == text
    assert CanonicalEvent.model_validate_json(event.model_dump_json()) == event


@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
@pytest.mark.parametrize("as_object", [False, True], ids=["text", "ip-object"])
@pytest.mark.parametrize("codepoint", [0xD800, 0xDFFF], ids=["high", "low"])
def test_ipv6_scope_surrogates_are_rejected_before_serialization(minimal_event, field, as_object, codepoint):
    # IPv6Address permits arbitrary scope text, including malformed Unicode.
    address = "fe80::1%" + chr(codepoint)
    value = IPv6Address(address) if as_object else address
    with pytest.raises(ValidationError) as error:
        CanonicalEvent.model_validate(minimal_event | {field: value})
    assert field in {item["loc"][0] for item in error.value.errors()}


@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
@pytest.mark.parametrize("as_object", [False, True], ids=["text", "ip-object"])
def test_valid_ipv6_scope_survives_serialization(minimal_event, field, as_object):
    address = "fe80::1%unit-interface"
    value = IPv6Address(address) if as_object else address
    event = CanonicalEvent.model_validate(minimal_event | {field: value})
    assert json.loads(event.model_dump_json())[field] == address
    assert CanonicalEvent.model_validate_json(event.model_dump_json()) == event
