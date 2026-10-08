"""The public SCN-004 (Lab C) profile evaluates offline through the engine.

Most events are synthetic canonical records shaped like the parsers produce. One
test builds them with the real Lab C parsers from artificial raw lines, so the
profile literals are checked against parser output. None of this is lab evidence.
"""

import calendar
from hashlib import sha256
import json
from pathlib import Path
import time

import pytest

from aegis_verify.connectors import opnsense, snort
from aegis_verify.connectors.wazuh import parse_wazuh_sysmon3_archive_record
from aegis_verify.models import CanonicalEventV2
from aegis_verify.scenario_loader import load_scenario
from aegis_verify.validation import (EvaluationContext, EvaluationProfile, ValidationEngineError,
                                     evaluate_scenario, scenario_fingerprint)

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "scenarios" / "SCN-004-attempted-exfiltration-lab-c.yaml"
PROFILE_DIR = ROOT / "scenarios" / "profiles" / "scn-004"
FIXTURES = ROOT / "tests" / "fixtures"

SENDER, RECEIVER, SRC_PORT, DST_PORT = "192.0.2.10", "203.0.113.10", 51000, 40000
LABEL = "00000000-0000-4000-8000-000000000001"
ANCHOR = "2026-01-01T00:00:10.950000Z"
TARGET_OF = {"snort-alert": "SCN-004-A02", "filterlog": "SCN-004-A03"}


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


def snort_alert(protocol="UDP", timestamp="2026-01-01T00:00:10.952000Z", **overrides):
    # Snort keeps `proto` as it prints it: upper case. A passive sensor logs `allow`.
    return _event("snort-alert", "snort", timestamp, event_provider="snort", protocol=protocol,
                  signature_id="1000010", event_action="allowed", **_tuple(**overrides))


def filterlog(action="blocked", timestamp="2026-01-01T00:00:10Z", rule_id=LABEL, **overrides):
    # BSD syslog from OPNsense has whole seconds, so the firewall time can trail
    # the endpoint time by up to one second for the same packet.
    return _event("filterlog", "opnsense", timestamp, event_provider="OPNsense-filterlog",
                  hostname="synthetic-fw", protocol="udp", event_action=action, rule_id=rule_id,
                  **_tuple(**overrides))


def outcomes(result):
    return {a.assertion_id: (a.outcome, a.reason_code) for a in result.assertions}


def test_profile_is_bound_to_the_committed_lab_c_manifest(manifest, profile):
    assert profile.scenario_fingerprint == scenario_fingerprint(manifest)
    assert [rule.assertion_id for rule in profile.rules] == [a.id for a in manifest.assertions]
    assert [rule.source_type for rule in profile.rules] == [a.source for a in manifest.assertions]
    assert [rule.role for rule in profile.rules] == ["telemetry", "detection", "prevention"]
    assert manifest.expected_outcome == "prevented"


def test_example_context_resolves_every_binding_without_lab_values(manifest, profile, context):
    names = {binding.name for binding in context.bindings}
    assert names == {"sender_ip", "receiver_ip", "receiver_port", "block_rule_label"}
    result = evaluate_scenario(manifest, [], profile=profile, context=context)
    assert result.final_status == "Missing telemetry"


def test_block_round_with_all_three_witnesses_is_prevented(manifest, profile, context):
    result = evaluate_scenario(manifest, [sysmon3(), snort_alert(), filterlog()], profile=profile, context=context)
    assert result.final_status == "Prevented"
    assert all(outcome == "satisfied" for outcome, _ in outcomes(result).values())
    for assertion in result.assertions:
        if assertion.role != "telemetry":
            assert assertion.witness_pairs
            assert all(pair.anchor_event_id == "sysmon3" for pair in assertion.witness_pairs)


def test_allowed_flow_is_inconclusive_never_prevented(manifest, profile, context):
    result = evaluate_scenario(manifest, [sysmon3(), snort_alert(), filterlog(action="allowed")],
                               profile=profile, context=context)
    got = outcomes(result)
    assert got["SCN-004-A01"][0] == got["SCN-004-A02"][0] == "satisfied"
    assert got["SCN-004-A03"] == ("inconclusive", "prevention_not_demonstrated")
    assert result.final_status == "Inconclusive"


@pytest.mark.parametrize("missing", sorted(TARGET_OF))
def test_a_missing_witness_without_declaration_is_not_prevented(manifest, profile, context, missing):
    events = [e for e in (sysmon3(), snort_alert(), filterlog()) if e.event_id != missing]
    result = evaluate_scenario(manifest, events, profile=profile, context=context)
    outcome, reason = outcomes(result)[TARGET_OF[missing]]
    assert outcome == "inconclusive"
    assert reason == ("prevention_not_demonstrated" if missing == "filterlog" else "collection_not_confirmed")
    assert result.final_status == "Inconclusive"


def test_a_block_by_another_rule_is_not_this_run_prevention(manifest, profile, context):
    other = filterlog(rule_id="fae559338f65e11c53669fc3642c93c2")
    result = evaluate_scenario(manifest, [sysmon3(), snort_alert(), other], profile=profile, context=context)
    assert outcomes(result)["SCN-004-A03"] == ("inconclusive", "prevention_not_demonstrated")
    assert result.final_status == "Inconclusive"


def test_witnesses_on_another_source_port_do_not_correlate(manifest, profile, context):
    events = [sysmon3(), snort_alert(src_port=SRC_PORT + 1), filterlog(src_port=SRC_PORT + 1)]
    result = evaluate_scenario(manifest, events, profile=profile, context=context)
    got = outcomes(result)
    assert got["SCN-004-A03"] == ("inconclusive", "prevention_not_demonstrated")
    assert got["SCN-004-A02"][0] != "satisfied"
    assert result.final_status != "Prevented"


def test_protocol_literals_are_case_exact_per_source(manifest, profile, context):
    result = evaluate_scenario(manifest, [sysmon3(), snort_alert(protocol="udp"), filterlog()],
                               profile=profile, context=context)
    assert outcomes(result)["SCN-004-A02"][0] != "satisfied"
    assert result.final_status != "Prevented"


def test_whole_second_firewall_time_stays_inside_the_window(manifest, profile, context):
    # Sysmon at 10.950 s; the same packet logged by OPNsense as 10 s is 0.95 s earlier.
    result = evaluate_scenario(manifest, [sysmon3(), snort_alert(), filterlog(timestamp="2026-01-01T00:00:10Z")],
                               profile=profile, context=context)
    assert result.final_status == "Prevented"
    too_early = filterlog(timestamp="2026-01-01T00:00:08.949999999Z")
    result = evaluate_scenario(manifest, [sysmon3(), snort_alert(), too_early], profile=profile, context=context)
    assert outcomes(result)["SCN-004-A03"] == ("inconclusive", "prevention_not_demonstrated")


def test_scn002_profile_cannot_be_rebound_to_lab_c_sources():
    # The reason SCN-004 exists: a rule binds only to the source its assertion names.
    manifest = load_scenario(ROOT / "scenarios" / "SCN-002-attempted-exfiltration.yaml")
    data = json.loads((ROOT / "scenarios" / "profiles" / "scn-002" / "profile.json").read_text("utf-8"))
    for index, source in ((1, "snort"), (2, "opnsense")):
        changed = json.loads(json.dumps(data))
        changed["rules"][index]["source_type"] = source
        context = EvaluationContext.model_validate(
            json.loads((ROOT / "scenarios" / "profiles" / "scn-002" / "context.example.json").read_text("utf-8")))
        with pytest.raises(ValidationEngineError) as caught:
            evaluate_scenario(manifest, [], profile=EvaluationProfile.model_validate(changed), context=context)
        assert caught.value.code == "assertion_binding"


def _epoch(text):
    return calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ"))


def test_events_from_the_real_lab_c_parsers_satisfy_the_profile(manifest, profile):
    # Artificial raw lines in each source's real layout; values are documentation ones.
    common = dict(environment_id="unit-lab", ingested_at="2026-10-06T12:05:00Z")
    archive = json.loads((FIXTURES / "cli/scn002-lab-sanitized/block/sysmon3-archive.json").read_bytes())
    data = archive["data"]["win"]["eventdata"]
    data.update(sourceIp=SENDER, sourcePort=str(SRC_PORT), destinationIp=RECEIVER,
                destinationPort=str(DST_PORT), utcTime="2026-10-06 12:00:00.500")
    sysmon = parse_wazuh_sysmon3_archive_record(
        json.dumps(archive, separators=(",", ":")).encode() + b"\n",
        source_ref="unit-sysmon3", collection_mode="direct", **common).event
    fixture = (FIXTURES / "snort/lab-c-probe-20261006.sanitized.jsonl").read_bytes().split(b"\n")[3]
    alert = json.loads(fixture)
    alert.update(seconds=_epoch("2026-10-06T12:00:00Z"), timestamp="26/10/06-12:00:00.600000",
                 src_addr=SENDER, src_port=SRC_PORT, dst_addr=RECEIVER, dst_port=DST_PORT,
                 rule="1:1000010:1", msg="AEGIS SCN-004 marker UDP")
    assert alert["proto"] == "UDP"
    snort_event = snort.parse_snort_alert_json(
        json.dumps(alert, separators=(", ", " : ")).encode() + b"\n", source_ref="unit-snort",
        sensor_id="unit-sensor", deployment_mode="ids", **common)[0].event
    line = ("<134>Oct  6 12:00:00 unit-fw filterlog[1]: 86,,," + LABEL + ",em2,match,block,in,4,0x0,,128,1,0,"
            "none,17,udp,94," + SENDER + "," + RECEIVER + "," + str(SRC_PORT) + "," + str(DST_PORT) + ",66\n")
    firewall = opnsense.parse_opnsense_filterlog(
        line.encode(), source_ref="unit-filterlog", sensor_id="unit-fw", source_year=2026,
        source_utc_offset="+00:00", **common)[0].event
    context = EvaluationContext.model_validate({
        "run_id": "scn004-unit", "environment_id": "unit-lab",
        "start": "2026-10-06T11:59:00Z", "end": "2026-10-06T12:02:00Z",
        "bindings": [{"name": "sender_ip", "value": SENDER}, {"name": "receiver_ip", "value": RECEIVER},
                     {"name": "receiver_port", "value": DST_PORT}, {"name": "block_rule_label", "value": LABEL}],
        "declarations": []})
    result = evaluate_scenario(manifest, [sysmon, snort_event, firewall], profile=profile, context=context)
    assert result.final_status == "Prevented"
    assert all(outcome == "satisfied" for outcome, _ in outcomes(result).values())
