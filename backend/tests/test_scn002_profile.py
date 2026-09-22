"""The public SCN-002 profile evaluates offline through the engine.

Events here are synthetic canonical records shaped like the parsers produce,
built in the test. A green run proves the profile, bindings and correlation
rules behave as documented, never that a lab produced this evidence.
"""

import json
from hashlib import sha256
from pathlib import Path

import pytest

from aegis_verify.models import CanonicalEventV2
from aegis_verify.scenario_loader import load_scenario
from aegis_verify.validation import (EvaluationContext, EvaluationProfile, evaluate_scenario,
                                     scenario_fingerprint)

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "scenarios" / "SCN-002-attempted-exfiltration.yaml"
PROFILE_DIR = ROOT / "scenarios" / "profiles" / "scn-002"

SENDER, RECEIVER, SRC_PORT, DST_PORT = "192.0.2.11", "198.51.100.10", 51000, 40000
TRACKER = "1700000001"
ANCHOR = "2026-01-01T00:00:10.000000Z"
TARGET_OF = {"suricata-alert": "SCN-002-A02", "filterlog": "SCN-002-A03", "wazuh-86601": "SCN-002-A04"}


@pytest.fixture(scope="module")
def manifest():
    return load_scenario(SCENARIO)


@pytest.fixture(scope="module")
def profile():
    return EvaluationProfile.model_validate(json.loads((PROFILE_DIR / "profile.json").read_text("utf-8")))


@pytest.fixture(scope="module")
def context():
    return EvaluationContext.model_validate(
        json.loads((PROFILE_DIR / "context.example.json").read_text("utf-8")))


def _event(event_id, source_type, timestamp, **fields):
    return CanonicalEventV2(event_id=event_id, source_type=source_type, environment_id="example-lab",
                            timestamp=timestamp, ingested_at="2026-01-01T00:00:30Z",
                            raw_event_ref="synthetic/" + event_id,
                            raw_event_hash=sha256(event_id.encode()).hexdigest(), **fields)


def _tuple(**overrides):
    fields = dict(src_ip=SENDER, dst_ip=RECEIVER, src_port=SRC_PORT, dst_port=DST_PORT)
    fields.update(overrides)
    return fields


def sysmon3(**overrides):
    return _event("sysmon3", "wazuh", ANCHOR, event_provider="Microsoft-Windows-Sysmon",
                  hostname="synthetic-sender", protocol="udp", event_action="observed",
                  process_id=4242, **_tuple(**overrides))


def suricata_alert(protocol="UDP", timestamp="2026-01-01T00:00:10.400000Z", **overrides):
    # Suricata EVE keeps `proto` as the sensor writes it: upper case.
    return _event("suricata-alert", "suricata", timestamp, event_provider="suricata", protocol=protocol,
                  signature_id="1000010", event_action="allowed", **_tuple(**overrides))


def filterlog(action="blocked", timestamp="2026-01-01T00:00:10.410000Z", **overrides):
    return _event("filterlog", "pfsense", timestamp, event_provider="pfSense-filterlog",
                  hostname="synthetic-fw", protocol="udp", event_action=action, rule_id=TRACKER,
                  **_tuple(**overrides))


def wazuh_alert(**overrides):
    return _event("wazuh-86601", "wazuh", "2026-01-01T00:00:11.200000Z", protocol="UDP",
                  rule_id="86601", signature_id="1000010", **_tuple(**overrides))


def outcomes(result):
    return {a.assertion_id: (a.outcome, a.reason_code) for a in result.assertions}


def test_profile_is_bound_to_the_committed_scenario_manifest(manifest, profile):
    assert profile.scenario_fingerprint == scenario_fingerprint(manifest)
    assert [rule.assertion_id for rule in profile.rules] == [a.id for a in manifest.assertions]
    assert manifest.expected_outcome == "prevented"


def test_example_context_resolves_every_binding_without_lab_values(manifest, profile, context):
    names = {binding.name for binding in context.bindings}
    assert names == {"sender_ip", "receiver_ip", "receiver_port", "block_rule_tracker"}
    result = evaluate_scenario(manifest, [], profile=profile, context=context)
    assert result.final_status == "Missing telemetry"


def test_block_round_with_all_four_witnesses_is_prevented(manifest, profile, context):
    events = [sysmon3(), suricata_alert(), filterlog(), wazuh_alert()]
    result = evaluate_scenario(manifest, events, profile=profile, context=context)
    assert result.final_status == "Prevented"
    assert all(outcome == "satisfied" for outcome, _ in outcomes(result).values())
    for assertion in result.assertions:
        if assertion.role != "telemetry":
            assert assertion.witness_pairs
            assert all(pair.anchor_event_id == "sysmon3" for pair in assertion.witness_pairs)


def test_control_round_is_inconclusive_never_prevented(manifest, profile, context):
    events = [sysmon3(), suricata_alert(), filterlog(action="allowed"), wazuh_alert()]
    result = evaluate_scenario(manifest, events, profile=profile, context=context)
    got = outcomes(result)
    assert got["SCN-002-A01"][0] == got["SCN-002-A02"][0] == got["SCN-002-A04"][0] == "satisfied"
    assert got["SCN-002-A03"] == ("inconclusive", "prevention_not_demonstrated")
    assert result.final_status == "Inconclusive"


@pytest.mark.parametrize("missing", sorted(TARGET_OF))
def test_a_missing_witness_without_declaration_is_not_prevented(manifest, profile, context, missing):
    events = [e for e in (sysmon3(), suricata_alert(), filterlog(), wazuh_alert()) if e.event_id != missing]
    result = evaluate_scenario(manifest, events, profile=profile, context=context)
    outcome, reason = outcomes(result)[TARGET_OF[missing]]
    assert outcome == "inconclusive"
    assert reason == ("prevention_not_demonstrated" if missing == "filterlog" else "collection_not_confirmed")
    assert result.final_status == "Inconclusive"


def test_witnesses_on_another_source_port_do_not_correlate(manifest, profile, context):
    events = [sysmon3(), suricata_alert(src_port=SRC_PORT + 1), filterlog(src_port=SRC_PORT + 1), wazuh_alert()]
    result = evaluate_scenario(manifest, events, profile=profile, context=context)
    got = outcomes(result)
    assert got["SCN-002-A03"] == ("inconclusive", "prevention_not_demonstrated")
    assert got["SCN-002-A02"][0] != "satisfied"
    assert result.final_status != "Prevented"


def test_protocol_literals_are_case_exact_per_source(manifest, profile, context):
    # Joins and predicates are exact string equality, so the profile pins each
    # parser's own spelling instead of joining on protocol.
    events = [sysmon3(), suricata_alert(protocol="udp"), filterlog(), wazuh_alert()]
    result = evaluate_scenario(manifest, events, profile=profile, context=context)
    assert outcomes(result)["SCN-002-A02"][0] != "satisfied"
    assert result.final_status != "Prevented"


def test_block_evidence_beyond_the_correlation_window_is_not_a_witness(manifest, profile, context):
    # Window is +/-2 s (measured lab skew 0.35 s and 1.37 s); 1 ns past it is out.
    late = filterlog(timestamp="2026-01-01T00:00:12.000000001Z")
    result = evaluate_scenario(manifest, [sysmon3(), suricata_alert(), late, wazuh_alert()],
                               profile=profile, context=context)
    assert outcomes(result)["SCN-002-A03"] == ("inconclusive", "prevention_not_demonstrated")
    assert result.final_status == "Inconclusive"
    on_edge = filterlog(timestamp="2026-01-01T00:00:12.000000000Z")
    result = evaluate_scenario(manifest, [sysmon3(), suricata_alert(), on_edge, wazuh_alert()],
                               profile=profile, context=context)
    assert outcomes(result)["SCN-002-A03"][0] == "satisfied"
    assert result.final_status == "Prevented"
