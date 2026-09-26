"""A Sysmon Event 3 archive record can be placed in a bundle and evaluated.

The parser already existed (#50); this covers the intake wiring only. The
fixture is synthetic, so a passing test says the bundle path works, never that a
lab produced this telemetry.
"""

import json
from hashlib import sha256
from pathlib import Path

import pytest

from aegis_verify.intake import IntakeError, load_bundle, parse_manifest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "wazuh" / "network-telemetry" / "sysmon3-archive.synthetic.json"
PARSER = "wazuh-sysmon3-archive-v1"


def _bundle(tmp_path: Path, raw: bytes, context: dict | None = None):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "sysmon3.json").write_bytes(raw)
    manifest = {
        "bundle_schema_version": "0.1.0",
        "environment_id": "synthetic-env",
        "files": [{
            "path": "sysmon3.json",
            "source_ref": "synthetic-sysmon3",
            "parser": PARSER,
            "sha256": sha256(raw).hexdigest(),
            "context": {"ingested_at": "2026-01-01T00:01:00Z", "collection_mode": "direct"}
            if context is None else context,
        }],
    }
    return root, manifest


def test_one_archive_record_becomes_one_udp_event_with_a_faithful_ledger(tmp_path):
    raw = FIXTURE.read_bytes()
    root, manifest = _bundle(tmp_path, raw)
    result = load_bundle(root, parse_manifest(manifest))

    assert len(result.events) == 1 and len(result.ledger) == 1
    event = result.events[0]
    assert event.source_type == "wazuh"
    assert event.event_provider == "Microsoft-Windows-Sysmon"
    assert event.protocol == "udp"
    assert event.event_action == "observed"
    assert event.src_ip is not None and event.dst_ip is not None
    assert event.src_port is not None and event.dst_port is not None
    assert event.raw_event_hash == sha256(raw).hexdigest()

    entry = result.ledger[0]
    assert entry.parser == PARSER
    assert entry.source_type == "wazuh"
    assert entry.source_ref == "synthetic-sysmon3"
    assert entry.status == "parsed" and entry.reason is None
    assert entry.event_id == event.event_id
    assert entry.raw_event_ref == event.raw_event_ref
    assert entry.raw_event_hash == event.raw_event_hash
    assert entry.line_start == 1
    assert result.inventory[0]["parser"] == PARSER


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["data"]["win"]["eventdata"].__setitem__("protocol", "tcp"),
        lambda d: d["data"]["win"]["system"].__setitem__("eventID", "1"),
        lambda d: d.__setitem__("_source", {}),
    ],
    ids=["tcp", "wrong-event-id", "search-hit"],
)
def test_records_the_parser_refuses_stop_the_bundle_as_parser_error(tmp_path, mutate):
    document = json.loads(FIXTURE.read_bytes())
    mutate(document)
    raw = json.dumps(document).encode("utf-8")
    root, manifest = _bundle(tmp_path, raw)
    with pytest.raises(IntakeError) as raised:
        load_bundle(root, parse_manifest(manifest))
    assert raised.value.code == "parser_error"
    assert raised.value.stage == "evidence"
    assert raised.value.file_index == 0


@pytest.mark.parametrize(
    "context",
    [
        {"ingested_at": "2026-01-01T00:01:00Z"},
        {"ingested_at": "2026-01-01T00:01:00Z", "collection_mode": "mirror"},
        {"ingested_at": "2026-01-01T00:01:00Z", "collection_mode": "direct", "sensor_id": "x"},
    ],
    ids=["missing-mode", "unknown-mode", "extra-field"],
)
def test_context_is_closed_and_named_in_the_error(tmp_path, context):
    root, manifest = _bundle(tmp_path, FIXTURE.read_bytes(), context)
    with pytest.raises(IntakeError) as raised:
        parse_manifest(manifest)
    assert raised.value.code == "invalid_manifest"
    assert raised.value.field == "context"
    assert raised.value.file_index == 0
