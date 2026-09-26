"""The public SCN-003 profile evaluates offline through the engine (#76, Task 3).

Two telemetry roots, one per NAT domain: pfSense pre-NAT (A02) anchors the
Suricata detection (A01); the Cowrie session.connect post-NAT (A03) anchors
the Wazuh login-failure detection (A04) through the opaque session key.
Events are synthetic canonical records shaped like the parsers produce; a
green run proves the contract, never that a lab produced this evidence.
"""

import json
from hashlib import sha256
from pathlib import Path

import pytest

from aegis_verify.models import CanonicalEventV2
from aegis_verify.scenario_loader import load_scenario
from aegis_verify.validation import (EvaluationContext, EvaluationProfile, evaluate_scenario,
                                     event_set_fingerprint, profile_fingerprint, scenario_fingerprint,
                                     scope_fingerprint)

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "scenarios" / "SCN-003-internal-deception.yaml"
PROFILE_DIR = ROOT / "scenarios" / "profiles" / "scn-003"

INITIATOR, INITIATOR_PORT = "192.0.2.10", 51003
DECOY, DECOY_PORT = "203.0.113.30", 2223
COWRIE, COWRIE_PORT = "198.51.100.20", 2223
TRACKER, USERNAME, PROTOCOL = "1700000003", "AEGIS-SCN003-1a2b3c4d", "telnet"
KEY = "cowrie:session-v1:" + sha256(b"synthetic-session-003").hexdigest()
OTHER_KEY = "cowrie:session-v1:" + sha256(b"another-session").hexdigest()
ANCHOR = "2026-01-01T00:00:10.000000Z"
TARGET_OF = {"eve": "SCN-003-A01", "filterlog": "SCN-003-A02", "connect": "SCN-003-A03", "wazuh": "SCN-003-A04"}


@pytest.fixture(scope="module")
def manifest():
    return load_scenario(SCENARIO)


@pytest.fixture(scope="module")
def profile():
    return EvaluationProfile.model_validate(json.loads((PROFILE_DIR / "profile.json").read_text("utf-8")))


@pytest.fixture(scope="module")
def context():
    return EvaluationContext.model_validate(json.loads((PROFILE_DIR / "context.example.json").read_text("utf-8")))


def _event(event_id, source_type, timestamp, **fields):
    return CanonicalEventV2(event_id=event_id, source_type=source_type, environment_id="example-lab",
                            timestamp=timestamp, ingested_at="2026-01-01T00:00:30Z",
                            raw_event_ref="synthetic/" + event_id,
                            raw_event_hash=sha256(event_id.encode()).hexdigest(), **fields)


def filterlog(action="allowed", src_port=INITIATOR_PORT, **overrides):
    # pf translates before it filters: with a port-forward the pass line
    # carries the post-NAT destination (the honeypot), unlike Suricata.
    fields = dict(event_provider="pfSense-filterlog", hostname="synthetic-fw", protocol="tcp",
                  src_ip=INITIATOR, src_port=src_port, dst_ip=COWRIE, dst_port=COWRIE_PORT,
                  event_action=action, rule_id=TRACKER)
    fields.update(overrides)
    return _event("filterlog", "pfsense", ANCHOR, **fields)


def eve(sid="1000012", timestamp="2026-01-01T00:00:10.050000Z", **overrides):
    fields = dict(event_provider="suricata", protocol="TCP", src_ip=INITIATOR, src_port=INITIATOR_PORT,
                  dst_ip=DECOY, dst_port=DECOY_PORT, signature_id=sid, event_action="allowed", severity=1)
    fields.update(overrides)
    return _event("eve", "suricata", timestamp, **fields)


def connect(src_port=INITIATOR_PORT, key=KEY, **overrides):
    fields = dict(event_provider="cowrie", protocol=PROTOCOL, src_ip=INITIATOR, src_port=src_port,
                  dst_ip=COWRIE, dst_port=COWRIE_PORT, event_action="observed", session_key=key)
    fields.update(overrides)
    return _event("connect", "cowrie", "2026-01-01T00:00:10.100000Z", **fields)


def login(key=KEY):
    # Supporting evidence only: a real login record carries no ports or destination.
    return _event("login", "cowrie", "2026-01-01T00:00:11.000000Z", event_provider="cowrie", protocol=PROTOCOL,
                  src_ip=INITIATOR, event_action="login", username=USERNAME, session_key=key)


def wazuh(username=USERNAME, key=KEY, rule="120003", timestamp="2026-01-01T00:00:11.000000Z", **overrides):
    fields = dict(event_provider="cowrie", protocol=PROTOCOL, src_ip=INITIATOR, event_action="login",
                  username=username, rule_id=rule, session_key=key)
    fields.update(overrides)
    return _event("wazuh", "wazuh", timestamp, **fields)


def all_events():
    return [filterlog(), eve(), connect(), login(), wazuh()]


def outcomes(result):
    return {a.assertion_id: (a.outcome, a.reason_code) for a in result.assertions}


def with_declaration(context, profile, events, assertion_id):
    """A complete_for_scope declaration is the only way absence becomes False negative."""
    declaration = {
        "assertion_id": assertion_id, "status": "complete_for_scope", "confirmed_by": "synthetic-reviewer",
        "reference": "synthetic-collection-review", "coverage_start": context.start.isoformat(),
        "coverage_end": context.end.isoformat(), "no_sampling_or_truncation": True,
        "no_parse_errors_or_gaps": True, "clocks_adequate": True,
        "profile_fingerprint": profile_fingerprint(profile), "scope_fingerprint": scope_fingerprint(context),
        "event_set_fingerprint": event_set_fingerprint(events),
    }
    return EvaluationContext.model_validate(context.model_dump(mode="json") | {"declarations": [declaration]})


def test_profile_is_bound_to_the_committed_scenario_manifest(manifest, profile):
    assert profile.scenario_fingerprint == scenario_fingerprint(manifest)
    assert [rule.assertion_id for rule in profile.rules] == [a.id for a in manifest.assertions]
    assert manifest.expected_outcome == "detected"
    roots = {rule.assertion_id for rule in profile.rules if rule.role == "telemetry"}
    assert roots == {"SCN-003-A02", "SCN-003-A03"}, "one root per NAT domain"


def test_example_context_resolves_every_binding_and_empty_evidence_is_missing_telemetry(manifest, profile, context):
    assert {b.name for b in context.bindings} == {
        "initiator_ip", "initiator_port", "decoy_ip", "decoy_port", "firewall_dst_ip", "firewall_dst_port",
        "cowrie_ip", "cowrie_port", "honeypot_protocol", "firewall_rule_tracker", "username_marker"}
    assert evaluate_scenario(manifest, [], profile=profile, context=context).final_status == "Missing telemetry"


def test_four_witnesses_of_one_session_are_detected_with_the_right_anchors(manifest, profile, context):
    result = evaluate_scenario(manifest, all_events(), profile=profile, context=context)
    assert result.final_status == "Detected"
    assert all(outcome == "satisfied" for outcome, _ in outcomes(result).values())
    anchors = {a.assertion_id: {p.anchor_event_id for p in a.witness_pairs} for a in result.assertions}
    assert anchors["SCN-003-A01"] == {"filterlog"} and anchors["SCN-003-A04"] == {"connect"}
    referenced = {entry.event_id for entry in result.evidence_index}
    assert "login" not in referenced, "the direct login record is supporting timeline evidence only"


@pytest.mark.parametrize("missing", sorted(TARGET_OF))
def test_a_missing_witness_is_never_detected(manifest, profile, context, missing):
    events = [e for e in all_events() if e.event_id != missing]
    result = evaluate_scenario(manifest, events, profile=profile, context=context)
    outcome, reason = outcomes(result)[TARGET_OF[missing]]
    if missing in {"filterlog", "connect"}:
        assert outcome == "missing_telemetry" and result.final_status == "Missing telemetry"
    else:
        assert (outcome, reason) == ("inconclusive", "collection_not_confirmed")
        assert result.final_status == "Inconclusive"


@pytest.mark.parametrize("bad, assertion_id", [
    (lambda: eve(sid="1000011"), "SCN-003-A01"),
    (lambda: wazuh(rule="100301"), "SCN-003-A04"),
], ids=["wrong-sid", "wrong-rule-id"])
def test_a_wrong_detection_id_is_false_negative_only_with_a_complete_collection_declaration(
        manifest, profile, context, bad, assertion_id):
    events = [e if e.event_id != bad().event_id else bad() for e in all_events()]
    plain = evaluate_scenario(manifest, events, profile=profile, context=context)
    assert outcomes(plain)[assertion_id] == ("inconclusive", "collection_not_confirmed")
    declared = with_declaration(context, profile, events, assertion_id)
    result = evaluate_scenario(manifest, events, profile=profile, context=declared)
    assert outcomes(result)[assertion_id] == ("false_negative", "expected_detection_absent")
    assert result.final_status == "False negative"


def test_a_rewritten_source_port_breaks_the_nat_bridge(manifest, profile, context):
    events = [filterlog(), eve(), connect(src_port=INITIATOR_PORT + 1), login(), wazuh()]
    result = evaluate_scenario(manifest, events, profile=profile, context=context)
    assert outcomes(result)["SCN-003-A03"][0] == "missing_telemetry"
    assert outcomes(result)["SCN-003-A04"] == ("missing_telemetry", "missing_activity_anchor")
    assert result.final_status == "Missing telemetry"


@pytest.mark.parametrize("bad", [
    lambda: eve(dst_port=22),
    lambda: eve(dst_ip=COWRIE),
    lambda: eve(src_port=INITIATOR_PORT + 1),
    lambda: filterlog(dst_ip=DECOY),
    lambda: wazuh(username="AEGIS-SCN003-ffffffff"),
    lambda: wazuh(key=OTHER_KEY),
    lambda: wazuh(protocol="ssh"),
    lambda: wazuh(timestamp="2026-01-01T00:00:12.100000001Z"),
    lambda: wazuh(timestamp="2026-01-01T00:00:08.099999999Z"),
    lambda: eve(timestamp="2026-01-01T00:00:12.000000001Z"),
    lambda: eve(timestamp="2026-01-01T00:00:07.999999999Z"),
], ids=["decoy-port", "suricata-sees-post-nat", "suricata-other-src-port", "filterlog-pre-nat-dst",
        "other-username", "other-session", "other-protocol", "wazuh-after-window", "wazuh-before-window",
        "suricata-after-window", "suricata-before-window"])
def test_evidence_of_another_flow_or_session_is_not_a_witness(manifest, profile, context, bad):
    replacement = bad()
    events = [replacement if e.event_id == replacement.event_id else e for e in all_events()]
    result = evaluate_scenario(manifest, events, profile=profile, context=context)
    assert outcomes(result)[TARGET_OF[replacement.event_id]][0] != "satisfied"
    assert result.final_status != "Detected"


@pytest.mark.parametrize("suricata, wazuh_at", [
    ("2026-01-01T00:00:12.000000000Z", "2026-01-01T00:00:12.100000000Z"),
    ("2026-01-01T00:00:08.000000000Z", "2026-01-01T00:00:08.100000000Z"),
], ids=["after-edge", "before-edge"])
def test_the_window_edge_is_inclusive(manifest, profile, context, suricata, wazuh_at):
    events = [filterlog(), eve(timestamp=suricata), connect(), login(), wazuh(timestamp=wazuh_at)]
    assert evaluate_scenario(manifest, events, profile=profile, context=context).final_status == "Detected"


def test_both_correlation_windows_are_two_seconds_measured_on_the_lab(profile):
    windows = {r.assertion_id: (r.correlation.min_delta_ns, r.correlation.max_delta_ns)
               for r in profile.rules if r.correlation is not None}
    assert windows == {"SCN-003-A01": (-2_000_000_000, 2_000_000_000),
                       "SCN-003-A04": (-2_000_000_000, 2_000_000_000)}


def test_direct_connection_without_dnat_uses_the_same_profile(manifest, profile, context):
    same = EvaluationContext.model_validate(context.model_dump(mode="json") | {"bindings": [
        {"name": "initiator_ip", "value": INITIATOR}, {"name": "initiator_port", "value": INITIATOR_PORT},
        {"name": "decoy_ip", "value": COWRIE}, {"name": "decoy_port", "value": COWRIE_PORT},
        {"name": "firewall_dst_ip", "value": COWRIE}, {"name": "firewall_dst_port", "value": COWRIE_PORT},
        {"name": "cowrie_ip", "value": COWRIE}, {"name": "cowrie_port", "value": COWRIE_PORT},
        {"name": "honeypot_protocol", "value": PROTOCOL}, {"name": "firewall_rule_tracker", "value": TRACKER},
        {"name": "username_marker", "value": USERNAME}]})
    events = [filterlog(), eve(dst_ip=COWRIE, dst_port=COWRIE_PORT), connect(), login(), wazuh()]
    assert evaluate_scenario(manifest, events, profile=profile, context=same).final_status == "Detected"
