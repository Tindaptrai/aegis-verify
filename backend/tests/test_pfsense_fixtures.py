"""Reviewed real-file derivatives; pass coverage is synthetic elsewhere."""

from hashlib import sha256
import json
from pathlib import Path

import pytest

from aegis_verify.connectors.pfsense import PfSenseParseError, parse_pfsense_filterlog
from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2


FIXTURES = Path(__file__).resolve().parents[2] / "tests/fixtures/pfsense"
CASES = [
    (1, "skipped", "rotation_notice"),
    (2, "parsed", None),
    (38, "skipped", "unsupported_protocol"),
    (39, "skipped", "unsupported_ip_version"),
    (45, "skipped", "unsupported_ip_version"),
    (726, "parsed", None),
    (296, "error", "malformed_header"),
]


def manifest():
    path = FIXTURES / "manifest.json"
    assert path.is_file(), "reviewed derivative manifest is required"
    return json.loads(path.read_text(encoding="utf-8"))


def fixture(source_line):
    document = manifest()
    entry = next(e for e in document["fixtures"] if e["source_line"] == source_line)
    raw = (FIXTURES / entry["file"]).read_bytes()
    context = document["parser_context"] | {"source_ref": entry["source_ref"]}
    return entry, raw, context


@pytest.mark.parametrize("source_line,status,reason", CASES)
def test_derivative_bytes_identity_and_classification(source_line, status, reason):
    entry, raw, context = fixture(source_line)
    assert hash_raw_event(raw) == entry["derivative_sha256"]
    assert raw.count(b"\n") == 1 and raw.endswith(b"\n") and b"\r" not in raw
    assert entry["source_ref"] == f"pfsense-l{source_line:04d}-sha256-{sha256(raw).hexdigest()}"
    assert entry["expected_status"] == status
    assert entry["expected_code"] == (reason if status == "error" else None)
    assert entry["expected_reason"] == (reason if status == "skipped" else None)
    if status == "error":
        with pytest.raises(PfSenseParseError) as caught:
            parse_pfsense_filterlog(raw, **context)
        assert caught.value.code == "malformed_header"
        assert caught.value.line == caught.value.record_index == 1
        assert raw.count(b"fixture-fw") == 2
        assert b"fixture-fw fSep 10 01:18:28 fixture-fw filterlog[1]:" in raw
        return
    records = parse_pfsense_filterlog(raw, **context)
    assert len(records) == 1
    record = records[0]
    assert record.status == status and record.reason == reason
    provenance = record.provenance
    assert provenance.raw_event_hash == entry["derivative_sha256"]
    assert provenance.raw_event_ref == entry["source_ref"] + "#L1-L1"
    assert provenance.line_start == provenance.line_end == provenance.record_index == 1
    assert provenance.source_year == 2026 and provenance.source_utc_offset == "+07:00"
    assert provenance.timestamp_basis == "bsd_syslog_with_caller_context"
    assert provenance.warnings == ("year_and_offset_supplied_by_caller",)
    assert provenance.nat_context is None
    if status == "skipped":
        assert record.event is provenance.event_id is None
    else:
        event = record.event
        assert CanonicalEventV2.model_validate_json(event.model_dump_json()) == event
        assert event.raw_event_hash == provenance.raw_event_hash
        assert event.raw_event_ref == provenance.raw_event_ref
        identity = ["pfsense-filterlog-evidence-v1", "fixture-lab", "fixture-fw",
                    entry["source_ref"], 1, sha256(raw).hexdigest(), 2026, "+07:00"]
        digest = sha256(json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
        assert event.event_id == provenance.event_id == "pfsense:filterlog-evidence-v1:" + digest


@pytest.mark.parametrize("source_line,timestamp,src,dst,src_port,dst_port,protocol,interface", [
    (2, "2026-09-08T16:01:00Z", "192.0.2.1", "192.0.2.2", 61928, 1900, "udp", "fixture0"),
    (726, "2026-09-09T19:11:25Z", "192.0.2.9", "192.0.2.10", 443, 56147, "tcp", "fixture2"),
])
def test_real_block_canonical_values(source_line, timestamp, src, dst, src_port, dst_port, protocol, interface):
    _, raw, context = fixture(source_line)
    record = parse_pfsense_filterlog(raw, **context)[0]
    event = record.event.model_dump(mode="json")
    expected = {
        "schema_version": "2.0", "timestamp": timestamp,
        "ingested_at": "2026-09-10T15:00:00Z", "source_type": "pfsense",
        "environment_id": "fixture-lab", "event_provider": "pfSense-filterlog",
        "hostname": "fixture-fw", "src_ip": src, "dst_ip": dst,
        "src_port": src_port, "dst_port": dst_port, "protocol": protocol,
        "rule_id": "1000000001", "event_action": "blocked",
        "source_record_id": None, "asset_id": None, "username": None,
        "process_name": None, "process_id": None, "parent_process_name": None,
        "command_line": None, "file_path": None, "file_hash": None,
        "signature_id": None, "severity": None, "technique_ids": None, "session_key": None,
    }
    assert {k: v for k, v in event.items() if k not in {"event_id", "raw_event_hash", "raw_event_ref"}} == expected
    metadata = record.provenance
    assert metadata.interface == interface
    assert metadata.direction == "in" and metadata.reason == "match"
    assert metadata.rule_number == "4" and metadata.tracker == "1000000001"
    assert metadata.subrule is metadata.anchor is None
    assert metadata.protocol_id == ("17" if protocol == "udp" else "6")
    assert metadata.protocol_text == protocol


def test_manifest_has_complete_lineage_and_raw_whitespace():
    document = manifest()
    assert document["source_sha256"] == "7c32779ba3825a2183b5eeae182af1ceb96d240b1f299cbb0d14f35f6de30f0c"
    entries = document["fixtures"]
    assert {e["source_line"] for e in entries} == {1, 2, 38, 39, 45, 726, 296}
    assert len({e["file"] for e in entries}) == len({e["source_ref"] for e in entries}) == 7
    for entry in entries:
        assert len(bytes.fromhex(entry["source_line_sha256"])) == 32
        assert entry["transformations"]
    assert fixture(38)[1].endswith(b"datalength=16 \n")
    assert fixture(726)[1].endswith(b"167,PA,40787473:40787640,1246112423,64240,,\n")
