"""Parser for a Wazuh manager alert raised from a Snort 3 alert (`wazuh-snort-alert-v1`).

The fixture is one real Lab C record of rule 130110, sanitized; see
`tests/fixtures/wazuh/snort-alert/README.md` for the substitutions and the lineage.
A green test says the parser still maps that shape; it is not itself evidence about
the lab. The lab verdicts live in `docs/SCN004_LAB_C.md`.
"""

import json
from hashlib import sha256
from pathlib import Path

import pytest

from aegis_verify.connectors import snort, wazuh
from aegis_verify.intake import IntakeError, load_bundle, parse_manifest
from aegis_verify.validation import AssertionRule
from aegis_verify.validation.contracts import validate_rule_source

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "wazuh" / "snort-alert" / "wazuh-snort-alert-labc.sanitized.json"
SNORT_LINE = ROOT / "tests" / "fixtures" / "cli" / "scn004-lab-c-sanitized" / "block" / "snort-alert.jsonl"
PARSER = "wazuh-snort-alert-v1"
CONTEXT = dict(source_ref="labc-wazuh-snort-8541573e", environment_id="lab-c-sanitized",
               ingested_at="2026-10-07T09:17:39Z", collection_mode="direct")


@pytest.fixture
def sample():
    return FIXTURE.read_bytes()


@pytest.fixture
def document(sample):
    return json.loads(sample)


def parse(raw, **overrides):
    return wazuh.parse_wazuh_snort_alert_record(raw, **(CONTEXT | overrides))


def encode(document):
    return json.dumps(document).encode("utf-8")


def relog(document, line):
    """Rewrite both copies of the alert line, the way the json decoder would have."""
    document["full_log"] = json.dumps(line)
    document["data"] = {key: value if type(value) is str else str(value) for key, value in line.items()}
    return document


def test_one_alert_is_one_wazuh_source_event_with_the_snort_flow(sample):
    result = parse(sample)
    event, provenance = result.event, result.provenance
    assert event.source_type == "wazuh"
    assert event.event_provider == "snort"
    assert event.rule_id == "130110"
    assert event.signature_id == "1000010"
    assert (str(event.src_ip), event.src_port, str(event.dst_ip), event.dst_port) == (
        "192.0.2.10", 65382, "203.0.113.10", 40000)
    assert event.protocol == "UDP"
    assert event.event_action == "allowed"
    # Snort printed priority 0 (no classtype): absent, not a rank. The Wazuh level is provenance.
    assert event.severity is None
    assert event.hostname is None
    assert event.asset_id == "001"
    assert event.source_record_id == "1791364125.537875"
    # The source time is Snort's, so this view and the direct Snort view correlate alike.
    assert event.timestamp.isoformat() == "2026-10-07T09:08:44.863672Z"
    assert event.ingested_at.isoformat() == "2026-10-07T09:17:39Z"
    assert event.raw_event_hash == sha256(sample).hexdigest()
    assert event.raw_event_ref == "labc-wazuh-snort-8541573e#record=1"
    assert provenance.envelope == "manager_alert"
    assert provenance.timestamp_basis == "snort.full_log.timestamp"
    assert provenance.decoder_name == "json"
    assert provenance.collector_location == "/var/log/snort/alert_json.txt"
    assert provenance.wazuh_rule_id == "130110" and provenance.wazuh_rule_level == 5
    assert provenance.wazuh_rule_groups == ("labc", "snort3", "ids")
    assert provenance.confirmed_data_fields == 17
    assert provenance.signature_text == "AEGIS SCN-004 marker UDP"
    assert (provenance.signature_gid, provenance.signature_rev) == ("1", "1")
    assert provenance.source_alert_action == "allow" and provenance.source_priority == 0
    assert (provenance.pkt_num, provenance.pkt_len, provenance.direction) == (2615, 94, "C2S")
    assert provenance.source_seconds == 1791364124 and provenance.source_fraction_digits == 6
    assert provenance.has_ip_header is True
    assert provenance.line_end == sample.count(b"\n") + int(not sample.endswith(b"\n"))


def test_the_wazuh_receipt_time_is_kept_apart_from_the_snort_source_time(sample):
    result = parse(sample)
    # Wazuh wrote the alert ~0.7 s after Snort logged it; neither value overwrites the other.
    assert result.provenance.collector_received_at == "2026-10-07T09:08:45.592+0000"
    assert result.event.timestamp.isoformat() == "2026-10-07T09:08:44.863672Z"


def test_tuple_and_time_match_the_direct_snort_parser_for_the_same_alert(sample, document):
    ours = parse(sample).event
    records = snort.parse_snort_alert_json(
        document["full_log"].encode("utf-8") + b"\n", source_ref="labc-snort-8541573e",
        environment_id="lab-c-sanitized", sensor_id="labc-snort-user",
        ingested_at="2026-10-07T09:17:39Z", deployment_mode="ids")
    theirs = [record.event for record in records if record.event is not None]
    assert len(theirs) == 1
    theirs = theirs[0]
    for field in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "signature_id",
                  "event_action", "timestamp", "severity"):
        assert getattr(ours, field) == getattr(theirs, field), field
    assert theirs.source_type == "snort" and ours.source_type == "wazuh"
    # Two events, two evidence IDs: the IDS alert at the source and the alert Wazuh raised for it.
    assert ours.event_id != theirs.event_id


def test_the_kept_line_is_the_same_alert_as_the_sanitized_lab_bundle(document):
    """Lineage: this record is rule 130110 for the Snort alert already in the block bundle."""
    assert json.loads(document["full_log"]) == json.loads(SNORT_LINE.read_bytes().strip())


def test_an_integer_rule_id_is_kept_as_decimal_text(document):
    document["rule"]["id"] = 130110
    assert parse(encode(document)).event.rule_id == "130110"


def test_the_plain_snort_group_spelling_is_accepted(document):
    document["rule"]["groups"] = ["labc", "snort", "ids"]
    assert parse(encode(document)).provenance.wazuh_rule_groups == ("labc", "snort", "ids")


def test_forwarded_collection_does_not_claim_the_agent_as_asset(sample):
    event = parse(sample, collection_mode="forwarded").event
    assert event.asset_id is None and event.rule_id == "130110"


def test_an_alert_without_an_ip_header_keeps_the_tuple_empty(document):
    line = json.loads(document["full_log"])
    for key in ("src_addr", "dst_addr", "src_port", "dst_port"):
        line.pop(key)
    line["proto"] = "ARP"
    result = parse(encode(relog(document, line)))
    assert result.provenance.has_ip_header is False
    assert (result.event.src_ip, result.event.dst_ip, result.event.src_port) == (None, None, None)
    assert result.event.protocol == "ARP" and result.event.rule_id == "130110"
    assert result.provenance.confirmed_data_fields == 13


@pytest.mark.parametrize(
    "mutate, code, field",
    [
        (lambda d: d.__setitem__("_source", {}), "unsupported_profile", "_source"),
        (lambda d: d["rule"].__delitem__("id"), "invalid_field", "rule.id"),
        (lambda d: d["rule"].__setitem__("id", "one-three"), "invalid_field", "rule.id"),
        (lambda d: d["rule"].__setitem__("groups", ["labc", "ids"]), "unsupported_profile", "rule.groups"),
        (lambda d: d["rule"].__delitem__("groups"), "invalid_field", "rule.groups"),
        (lambda d: d.__delitem__("rule"), "invalid_field", "rule"),
        (lambda d: d["decoder"].__setitem__("name", "snort"), "unsupported_profile", "decoder.name"),
        (lambda d: d.__delitem__("decoder"), "invalid_field", "decoder"),
        (lambda d: d.__delitem__("full_log"), "invalid_field", "full_log"),
        (lambda d: d.__setitem__("full_log", "not json"), "invalid_json", None),
        (lambda d: d.__setitem__("full_log", '{"seconds":1}'), "unsupported_profile", "full_log"),
        (lambda d: d.__delitem__("data"), "invalid_field", "data"),
        (lambda d: d["data"].__delitem__("src_port"), "unsupported_profile", "data"),
        (lambda d: d["data"].__setitem__("src_port", "65383"), "invalid_field", "data.src_port"),
        (lambda d: d["data"].__setitem__("msg", "something else"), "invalid_field", "data.msg"),
        (lambda d: d["data"].__setitem__("seconds", 1791364124), "invalid_field", "data.seconds"),
    ],
    ids=["search-hit", "no-rule-id", "non-decimal-rule-id", "not-a-snort-group", "no-groups", "no-rule",
         "other-decoder", "no-decoder", "no-kept-line", "kept-line-not-json", "kept-line-off-profile",
         "no-data", "data-field-missing", "data-port-disagrees", "data-message-disagrees",
         "data-value-not-text"],
)
def test_records_outside_the_profile_are_refused_with_a_safe_diagnostic(document, mutate, code, field):
    mutate(document)
    with pytest.raises(wazuh.WazuhParseError) as raised:
        parse(encode(document))
    assert raised.value.diagnostic.code == code
    assert raised.value.diagnostic.field_path == field


def test_a_diagnostic_never_carries_a_value_from_the_kept_line(document):
    line = json.loads(document["full_log"])
    line["timestamp"] = "99/99/99-99:99:99.999999"
    with pytest.raises(wazuh.WazuhParseError) as raised:
        parse(encode(relog(document, line)))
    assert raised.value.diagnostic.code == "invalid_event_time"
    assert raised.value.diagnostic.field_path == "full_log"


@pytest.mark.parametrize("override", [dict(collection_mode="mirror"), dict(ingested_at="now")])
def test_bad_caller_context_is_refused(sample, override):
    with pytest.raises(wazuh.WazuhParseError) as raised:
        parse(sample, **override)
    assert raised.value.diagnostic.code == "invalid_context"


def test_a_rule_on_this_source_is_a_valid_wazuh_source_rule():
    """Shape a future SIEM-alert assertion would take; no scenario uses it yet."""
    rule = AssertionRule.model_validate({
        "assertion_id": "SCN-004-A04", "role": "detection", "capability": "supported",
        "source_type": "wazuh",
        "scope": [{"field": "src_ip", "op": "eq", "binding": "sender_ip"},
                  {"field": "event_provider", "op": "eq", "value": "snort"}],
        "match": [{"field": "rule_id", "op": "eq", "value": "130110"},
                  {"field": "signature_id", "op": "eq", "value": "1000010"}],
        "correlation": {"anchor_assertion_id": "SCN-004-A01",
                        "join_pairs": [{"target_field": "src_port", "anchor_field": "src_port"}],
                        "min_delta_ns": -2000000000, "max_delta_ns": 2000000000},
    })
    validate_rule_source(rule, "wazuh")


def _bundle(tmp_path, raw, context=None):
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "alert.json").write_bytes(raw)
    manifest = {
        "bundle_schema_version": "0.1.0",
        "environment_id": "lab-c-sanitized",
        "files": [{
            "path": "alert.json", "source_ref": "labc-wazuh-snort-8541573e", "parser": PARSER,
            "sha256": sha256(raw).hexdigest(),
            "context": {"ingested_at": "2026-10-07T09:17:39Z", "collection_mode": "direct"}
            if context is None else context,
        }],
    }
    return root, manifest


def test_bundle_intake_routes_the_key_to_the_parser_with_a_faithful_ledger(tmp_path, sample):
    root, manifest = _bundle(tmp_path, sample)
    result = load_bundle(root, parse_manifest(manifest))
    assert len(result.events) == 1 and len(result.ledger) == 1
    event, entry = result.events[0], result.ledger[0]
    assert event.source_type == "wazuh" and event.rule_id == "130110" and event.signature_id == "1000010"
    assert entry.parser == PARSER and entry.source_type == "wazuh"
    assert entry.status == "parsed" and entry.reason is None
    assert entry.event_id == event.event_id and entry.raw_event_hash == event.raw_event_hash
    assert entry.line_start == 1
    # Raw evidence stays traceable to the one record and its bytes.
    assert entry.raw_event_ref == "labc-wazuh-snort-8541573e#record=1"
    assert entry.raw_event_hash == sha256(sample).hexdigest()


def test_bundle_intake_stops_on_a_search_hit_as_parser_error(tmp_path, document):
    document["_source"] = {}
    root, manifest = _bundle(tmp_path, encode(document))
    with pytest.raises(IntakeError) as raised:
        load_bundle(root, parse_manifest(manifest))
    assert raised.value.code == "parser_error" and raised.value.stage == "evidence"


def test_bundle_context_is_closed_and_named(tmp_path, sample):
    root, manifest = _bundle(tmp_path, sample, {"ingested_at": "2026-10-07T09:17:39Z", "deployment_mode": "ids"})
    with pytest.raises(IntakeError) as raised:
        parse_manifest(manifest)
    assert raised.value.code == "invalid_manifest" and raised.value.field == "context"
