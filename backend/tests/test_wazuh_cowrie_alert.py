"""Invented fixture only; these tests are not evidence of a live scenario.

Covers the wazuh-source parser for a manager alert raised from a Cowrie login
failure (#76, plan Task 2) and its intake wiring under key
`wazuh-cowrie-alert-v1`.
"""

import dataclasses
import json
from hashlib import sha256
from pathlib import Path

import pytest

from aegis_verify.connectors import cowrie, wazuh
from aegis_verify.intake import IntakeError, load_bundle, parse_manifest
from aegis_verify.validation import AssertionRule
from aegis_verify.validation.contracts import validate_rule_source

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "wazuh" / "cowrie-alert" / "wazuh-cowrie-alert.synthetic.json"
PARSER = "wazuh-cowrie-alert-v1"
CONTEXT = dict(source_ref="synthetic-alert", environment_id="synthetic-env",
               ingested_at="2026-01-01T00:01:00Z", collection_mode="direct", sensor_id="synthetic-cowrie")
SESSION_PREFIX = "cowrie:session-v1:"
# Placeholder standing in for the credential a real login record carries. The
# parser must never read it: not into the event, provenance, ledger or report.
TYPED_VALUE = "synthetic-only"


@pytest.fixture
def sample():
    return FIXTURE.read_bytes()


@pytest.fixture
def document(sample):
    return json.loads(sample)


def parse(raw, **overrides):
    return wazuh.parse_wazuh_cowrie_alert_record(raw, **(CONTEXT | overrides))


def encode(document):
    return json.dumps(document).encode("utf-8")


def test_one_alert_is_one_wazuh_source_login_event_with_the_cowrie_facts(sample):
    result = parse(sample)
    event, provenance = result.event, result.provenance
    assert event.source_type == "wazuh"
    assert event.event_provider == "cowrie"
    assert event.rule_id == "120003"
    assert event.event_action == "login"
    assert event.username == "AEGIS-SCN003-1a2b3c4d"
    assert str(event.src_ip) == "192.0.2.10"
    # A real login record carries no ports and no destination; they stay null.
    assert event.src_port is None and event.dst_ip is None and event.dst_port is None
    assert event.protocol == "ssh"
    assert event.hostname is None and event.command_line is None and event.signature_id is None
    assert event.asset_id == "013"
    assert event.source_record_id == "1767225611.250"
    assert event.session_key is not None and event.session_key.startswith(SESSION_PREFIX)
    assert event.timestamp.isoformat() == "2026-01-01T00:00:10.800000Z"
    assert event.ingested_at.isoformat() == "2026-01-01T00:01:00Z"
    assert event.raw_event_hash == sha256(sample).hexdigest()
    assert event.raw_event_ref == "synthetic-alert#record=1"
    assert provenance.envelope == "manager_alert"
    assert provenance.timestamp_basis == "cowrie.data.timestamp"
    assert provenance.source_event_type == "cowrie.login.failed"
    assert provenance.authentication_outcome == "failure"
    assert provenance.collector_received_at == "2026-01-01T00:00:11.250+0000"
    assert provenance.wazuh_rule_id == "120003" and provenance.wazuh_rule_level == 5
    assert provenance.session_key == event.session_key
    assert provenance.sensor_id == "synthetic-cowrie"
    assert not hasattr(provenance, "session"), "the raw session identifier is never stored"


def test_facts_match_the_direct_cowrie_parser_including_the_session_key(document):
    ours = parse(encode(document)).event
    line = json.dumps(document["data"], separators=(",", ":")).encode("utf-8") + b"\n"
    records = cowrie.parse_cowrie_jsonl(line, source_ref="synthetic-native", environment_id="synthetic-env",
                                        sensor_id="synthetic-cowrie", ingested_at="2026-01-01T00:01:00Z")
    theirs = [record.event for record in records if record.event is not None]
    assert len(theirs) == 1
    theirs = theirs[0]
    for field in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "username",
                  "event_action", "timestamp", "session_key"):
        assert getattr(ours, field) == getattr(theirs, field), field
    assert ours.session_key is not None and ours.src_port is None
    assert theirs.source_type == "cowrie" and ours.source_type == "wazuh"
    assert theirs.rule_id is None and ours.rule_id == "120003"
    assert theirs.event_id != ours.event_id


def test_another_sensor_label_yields_another_session_key(sample):
    assert parse(sample).event.session_key != parse(sample, sensor_id="other-sensor").event.session_key


def test_an_integer_rule_id_is_kept_as_decimal_text(document):
    document["rule"]["id"] = 120003
    assert parse(encode(document)).event.rule_id == "120003"


def test_forwarded_collection_does_not_claim_the_agent_as_asset(sample):
    event = parse(sample, collection_mode="forwarded").event
    assert event.asset_id is None and event.rule_id == "120003"


@pytest.mark.parametrize(
    "mutate, code, field",
    [
        (lambda d: d.__setitem__("_source", {}), "unsupported_profile", "_source"),
        (lambda d: d["rule"].__delitem__("groups"), "invalid_field", "rule.groups"),
        (lambda d: d["rule"].__setitem__("groups", ["honeypot"]), "unsupported_profile", "rule.groups"),
        (lambda d: d["rule"].__delitem__("id"), "invalid_field", "rule.id"),
        (lambda d: d["rule"].__setitem__("id", "one-two"), "invalid_field", "rule.id"),
        (lambda d: d["data"].__setitem__("eventid", "cowrie.login.success"), "unsupported_profile", "data.eventid"),
        (lambda d: d["data"].__setitem__("eventid", "cowrie.command.input"), "unsupported_profile", "data.eventid"),
        (lambda d: d["data"].__delitem__("eventid"), "invalid_field", "data.eventid"),
        (lambda d: d["data"].__delitem__("session"), "invalid_field", "data.session"),
        (lambda d: d["data"].__delitem__("timestamp"), "missing_event_time", "data.timestamp"),
        (lambda d: d["data"].__setitem__("timestamp", "yesterday"), "invalid_event_time", "data.timestamp"),
        (lambda d: d["data"].__setitem__("protocol", "rdp"), "invalid_field", "data.protocol"),
        (lambda d: d["data"].__setitem__("src_ip", "not-an-address"), "invalid_field", "data.src_ip"),
        (lambda d: d["data"].__setitem__("src_port", "70000"), "invalid_field", "data.src_port"),
        (lambda d: d.__delitem__("data"), "invalid_field", "data"),
    ],
    ids=["search-hit", "no-groups", "not-cowrie-group", "no-rule-id", "non-decimal-rule-id",
         "login-success", "command", "no-eventid", "no-session", "no-time", "bad-time", "bad-protocol",
         "bad-address", "bad-port", "no-data"],
)
def test_records_outside_the_profile_are_refused_with_a_safe_diagnostic(document, mutate, code, field):
    # Every refusal is exercised on a record that also carries the typed
    # credential, as a real login record does; the diagnostic must not echo it.
    document["data"]["password"] = TYPED_VALUE
    mutate(document)
    with pytest.raises(wazuh.WazuhParseError) as raised:
        parse(encode(document))
    assert raised.value.diagnostic.code == code
    assert raised.value.diagnostic.field_path == field
    assert TYPED_VALUE not in str(raised.value) and "1a2b3c4d" not in str(raised.value)


def test_a_real_login_record_with_the_typed_credential_parses_without_reading_it(document):
    document["data"]["password"] = TYPED_VALUE
    result = parse(encode(document))
    assert result.event.rule_id == "120003" and result.event.username == "AEGIS-SCN003-1a2b3c4d"
    assert TYPED_VALUE not in result.event.model_dump_json()
    assert TYPED_VALUE not in result.provenance.model_dump_json()
    assert "password" not in result.event.model_dump() and "password" not in result.provenance.model_dump()


@pytest.mark.parametrize("override", [dict(collection_mode="mirror"), dict(ingested_at="now"),
                                      dict(sensor_id="bad label"), dict(sensor_id="")])
def test_bad_caller_context_is_refused(sample, override):
    with pytest.raises(wazuh.WazuhParseError) as raised:
        parse(sample, **override)
    assert raised.value.diagnostic.code == "invalid_context"


def test_the_a04_profile_rule_is_a_valid_wazuh_source_rule_joining_the_session_key():
    rule = AssertionRule.model_validate({
        "assertion_id": "SCN-003-A04", "role": "detection", "capability": "supported",
        "source_type": "wazuh",
        "scope": [{"field": "src_ip", "op": "eq", "binding": "initiator_ip"},
                  {"field": "event_provider", "op": "eq", "value": "cowrie"}],
        "match": [{"field": "rule_id", "op": "eq", "value": "120003"},
                  {"field": "username", "op": "eq", "binding": "username_marker"}],
        # A login record has no ports, so the join to the session.connect root
        # is source address, protocol and the session key.
        "correlation": {"anchor_assertion_id": "SCN-003-A03",
                        "join_pairs": [{"target_field": "src_ip", "anchor_field": "src_ip"},
                                       {"target_field": "protocol", "anchor_field": "protocol"},
                                       {"target_field": "session_key", "anchor_field": "session_key"}],
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
            "context": {"ingested_at": "2026-01-01T00:01:00Z", "collection_mode": "direct",
                        "sensor_id": "synthetic-cowrie"} if context is None else context,
        }],
    }
    return root, manifest


def test_bundle_intake_routes_the_key_to_the_parser_with_a_faithful_ledger(tmp_path, sample):
    root, manifest = _bundle(tmp_path, sample)
    result = load_bundle(root, parse_manifest(manifest))
    assert len(result.events) == 1 and len(result.ledger) == 1
    event, entry = result.events[0], result.ledger[0]
    assert event.source_type == "wazuh" and event.rule_id == "120003" and event.session_key
    assert entry.parser == PARSER and entry.source_type == "wazuh"
    assert entry.status == "parsed" and entry.reason is None
    assert entry.event_id == event.event_id and entry.raw_event_hash == event.raw_event_hash


def test_bundle_intake_keeps_the_typed_credential_out_of_events_and_ledger(tmp_path, document):
    document["data"]["password"] = TYPED_VALUE
    raw = encode(document)
    root, manifest = _bundle(tmp_path, raw)
    result = load_bundle(root, parse_manifest(manifest))
    assert len(result.events) == 1 and result.ledger[0].status == "parsed"
    assert TYPED_VALUE not in result.events[0].model_dump_json()
    assert TYPED_VALUE not in json.dumps([dataclasses.asdict(entry) for entry in result.ledger], default=str)
    # The raw bytes still hold it: the hash is over the exact evidence, which stays private.
    assert result.events[0].raw_event_hash == sha256(raw).hexdigest()


def test_bundle_intake_stops_on_a_search_hit_as_parser_error(tmp_path, document):
    document["_source"] = {}
    root, manifest = _bundle(tmp_path, encode(document))
    with pytest.raises(IntakeError) as raised:
        load_bundle(root, parse_manifest(manifest))
    assert raised.value.code == "parser_error" and raised.value.stage == "evidence"


@pytest.mark.parametrize("context", [
    {"ingested_at": "2026-01-01T00:01:00Z", "collection_mode": "direct"},
    {"ingested_at": "2026-01-01T00:01:00Z", "sensor_id": "synthetic-cowrie"},
    {"ingested_at": "2026-01-01T00:01:00Z", "collection_mode": "direct", "sensor_id": "synthetic-cowrie",
     "deployment_mode": "ids"},
], ids=["no-sensor", "no-mode", "extra"])
def test_bundle_context_is_closed_and_named(tmp_path, sample, context):
    root, manifest = _bundle(tmp_path, sample, context)
    with pytest.raises(IntakeError) as raised:
        parse_manifest(manifest)
    assert raised.value.code == "invalid_manifest" and raised.value.field == "context"
