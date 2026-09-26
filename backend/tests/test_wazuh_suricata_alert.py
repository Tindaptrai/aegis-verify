"""Invented fixture only; these tests are not evidence of a live scenario.

Covers the wazuh-source parser for a manager alert raised from a Suricata
alert (#61) and its intake wiring under key `wazuh-suricata-alert-v1`.
"""

import json
from hashlib import sha256
from pathlib import Path

import pytest

from aegis_verify.connectors import suricata, wazuh
from aegis_verify.intake import IntakeError, load_bundle, parse_manifest
from aegis_verify.validation import AssertionRule
from aegis_verify.validation.contracts import validate_rule_source

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "wazuh" / "suricata-alert" / "wazuh-suricata-alert.synthetic.json"
PARSER = "wazuh-suricata-alert-v1"
CONTEXT = dict(source_ref="synthetic-alert", environment_id="synthetic-env",
               ingested_at="2026-01-01T00:01:00Z", collection_mode="direct")


@pytest.fixture
def sample():
    return FIXTURE.read_bytes()


@pytest.fixture
def document(sample):
    return json.loads(sample)


def parse(raw, **overrides):
    return wazuh.parse_wazuh_suricata_alert_record(raw, **(CONTEXT | overrides))


def encode(document):
    return json.dumps(document).encode("utf-8")


def test_one_alert_is_one_wazuh_source_event_with_the_suricata_flow(sample):
    result = parse(sample)
    event, provenance = result.event, result.provenance
    assert event.source_type == "wazuh"
    assert event.event_provider == "suricata"
    assert event.rule_id == "86601"
    assert event.signature_id == "1000010"
    assert (str(event.src_ip), event.src_port, str(event.dst_ip), event.dst_port) == (
        "192.0.2.11", 51000, "198.51.100.10", 40000)
    assert event.protocol == "UDP"
    assert event.event_action == "allowed"
    assert event.severity == 1
    assert event.hostname is None
    assert event.asset_id == "911"
    assert event.source_record_id == "1767225612.100"
    assert event.timestamp.isoformat() == "2026-01-01T00:00:10.400000Z"
    assert event.ingested_at.isoformat() == "2026-01-01T00:01:00Z"
    assert event.raw_event_hash == sha256(sample).hexdigest()
    assert event.raw_event_ref == "synthetic-alert#record=1"
    assert provenance.envelope == "manager_alert"
    assert provenance.timestamp_basis == "suricata.data.timestamp"
    assert provenance.collector_received_at == "2026-01-01T00:00:12.345+0000"
    assert provenance.wazuh_rule_id == "86601" and provenance.wazuh_rule_level == 3
    assert provenance.signature_text == "AEGIS SCN-002 marker UDP"
    assert provenance.source_alert_action == "allowed"
    assert provenance.line_end == sample.count(b"\n") + int(not sample.endswith(b"\n"))


def as_eve_line(data):
    """Wazuh stringifies EVE numbers; give the direct EVE parser the native types back."""
    eve = json.loads(json.dumps(data))
    eve["flow_id"] = int(eve["flow_id"].split(".")[0])
    for key in ("src_port", "dest_port"):
        eve[key] = int(eve[key])
    for key in ("severity", "gid", "signature_id", "rev"):
        eve["alert"][key] = int(eve["alert"][key])
    eve.pop("flow")
    return json.dumps(eve).encode("utf-8")


def test_tuple_and_time_match_the_direct_eve_parser_for_the_same_alert(document):
    ours = parse(encode(document)).event
    records = suricata.parse_suricata_eve_jsonl(
        as_eve_line(document["data"]), source_ref="synthetic-eve", environment_id="synthetic-env",
        sensor_id="lan", ingested_at="2026-01-01T00:01:00Z", deployment_mode="ids")
    theirs = [record.event for record in records if record.event is not None]
    assert len(theirs) == 1
    theirs = theirs[0]
    for field in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "signature_id",
                  "event_action", "timestamp", "severity"):
        assert getattr(ours, field) == getattr(theirs, field), field
    assert theirs.source_type == "suricata" and ours.source_type == "wazuh"


def test_an_integer_rule_id_is_kept_as_decimal_text(document):
    document["rule"]["id"] = 86601
    assert parse(encode(document)).event.rule_id == "86601"


def test_forwarded_collection_does_not_claim_the_agent_as_asset(sample):
    event = parse(sample, collection_mode="forwarded").event
    assert event.asset_id is None and event.rule_id == "86601"


@pytest.mark.parametrize(
    "mutate, code, field",
    [
        (lambda d: d.__setitem__("_source", {}), "unsupported_profile", "_source"),
        (lambda d: d["rule"].__delitem__("id"), "invalid_field", "rule.id"),
        (lambda d: d["rule"].__setitem__("id", "eighty"), "invalid_field", "rule.id"),
        (lambda d: d["rule"].__setitem__("groups", ["ids"]), "unsupported_profile", "rule.groups"),
        (lambda d: d["rule"].__delitem__("groups"), "invalid_field", "rule.groups"),
        (lambda d: d["data"].__setitem__("event_type", "flow"), "unsupported_profile", "data.event_type"),
        (lambda d: d.__delitem__("data"), "invalid_field", "data"),
        (lambda d: d["data"]["alert"].__setitem__("action", "dropped"), "invalid_field", "data.alert.action"),
        (lambda d: d["data"].__setitem__("timestamp", "yesterday"), "invalid_event_time", "data.timestamp"),
    ],
    ids=["search-hit", "no-rule-id", "non-decimal-rule-id", "not-suricata-group", "no-groups",
         "not-an-alert", "no-data", "unknown-action", "bad-time"],
)
def test_records_outside_the_profile_are_refused_with_a_safe_diagnostic(document, mutate, code, field):
    mutate(document)
    with pytest.raises(wazuh.WazuhParseError) as raised:
        parse(encode(document))
    assert raised.value.diagnostic.code == code
    assert raised.value.diagnostic.field_path == field


@pytest.mark.parametrize("override", [dict(collection_mode="mirror"), dict(ingested_at="now")])
def test_bad_caller_context_is_refused(sample, override):
    with pytest.raises(wazuh.WazuhParseError) as raised:
        parse(sample, **override)
    assert raised.value.diagnostic.code == "invalid_context"


def test_the_a04_profile_rule_is_a_valid_wazuh_source_rule():
    rule = AssertionRule.model_validate({
        "assertion_id": "SCN-002-A04", "role": "detection", "capability": "supported",
        "source_type": "wazuh",
        "scope": [{"field": "src_ip", "op": "eq", "binding": "sender_ip"}],
        "match": [{"field": "rule_id", "op": "eq", "value": "86601"},
                  {"field": "signature_id", "op": "eq", "value": "1000010"}],
        "correlation": {"anchor_assertion_id": "SCN-002-A01",
                        "join_pairs": [{"target_field": "src_port", "anchor_field": "src_port"}],
                        "min_delta_ns": -5000000000, "max_delta_ns": 5000000000},
    })
    validate_rule_source(rule, "wazuh")


def _bundle(tmp_path, raw, context=None):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "alert.json").write_bytes(raw)
    manifest = {
        "bundle_schema_version": "0.1.0",
        "environment_id": "synthetic-env",
        "files": [{
            "path": "alert.json", "source_ref": "synthetic-alert", "parser": PARSER,
            "sha256": sha256(raw).hexdigest(),
            "context": {"ingested_at": "2026-01-01T00:01:00Z", "collection_mode": "direct"}
            if context is None else context,
        }],
    }
    return root, manifest


def test_bundle_intake_routes_the_key_to_the_parser_with_a_faithful_ledger(tmp_path, sample):
    root, manifest = _bundle(tmp_path, sample)
    result = load_bundle(root, parse_manifest(manifest))
    assert len(result.events) == 1 and len(result.ledger) == 1
    event, entry = result.events[0], result.ledger[0]
    assert event.source_type == "wazuh" and event.rule_id == "86601" and event.signature_id == "1000010"
    assert entry.parser == PARSER and entry.source_type == "wazuh"
    assert entry.status == "parsed" and entry.reason is None
    assert entry.event_id == event.event_id and entry.raw_event_hash == event.raw_event_hash
    assert entry.line_start == 1


def test_bundle_intake_stops_on_a_search_hit_as_parser_error(tmp_path, document):
    document["_source"] = {}
    root, manifest = _bundle(tmp_path, encode(document))
    with pytest.raises(IntakeError) as raised:
        load_bundle(root, parse_manifest(manifest))
    assert raised.value.code == "parser_error" and raised.value.stage == "evidence"


def test_bundle_context_is_closed_and_named(tmp_path, sample):
    root, manifest = _bundle(tmp_path, sample, {"ingested_at": "2026-01-01T00:01:00Z", "deployment_mode": "ids"})
    with pytest.raises(IntakeError) as raised:
        parse_manifest(manifest)
    assert raised.value.code == "invalid_manifest" and raised.value.field == "context"
