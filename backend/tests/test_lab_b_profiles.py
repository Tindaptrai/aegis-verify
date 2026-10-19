"""The Lab B profiles evaluate synthetic canonical facts, never lab evidence."""

from hashlib import sha256
import json
from pathlib import Path

import pytest

from aegis_verify.models import CanonicalEventV2
from aegis_verify.scenario_loader import load_scenario
from aegis_verify.validation import (EvaluationContext, EvaluationProfile,
                                     evaluate_scenario, scenario_fingerprint)

ROOT = Path(__file__).resolve().parents[2]
IMAGE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def _contracts(number, name):
    path = ROOT / "scenarios" / f"SCN-{number:03}-{name}.yaml"
    assert path.is_file(), "The separate Lab B manifest must exist."
    manifest = load_scenario(path)
    profile_dir = ROOT / "scenarios" / "profiles" / f"scn-{number:03}"
    profile = EvaluationProfile.model_validate(json.loads((profile_dir / "profile.json").read_text("utf-8")))
    context = EvaluationContext.model_validate(json.loads((profile_dir / "context.example.json").read_text("utf-8")))
    return manifest, profile, context


@pytest.fixture
def ps_contracts():
    return _contracts(5, "powershell-elastic-lab-b")


@pytest.fixture
def net_contracts():
    return _contracts(6, "http-visibility-lab-b")


def _event(identifier, source, timestamp="2026-01-01T00:00:10Z", **fields):
    return CanonicalEventV2(
        event_id=identifier, source_type=source, environment_id="example-lab",
        timestamp=timestamp, ingested_at="2026-01-01T00:02:30Z",
        raw_event_ref="synthetic/" + identifier, raw_event_hash=sha256(identifier.encode()).hexdigest(),
        **fields,
    )


def _ps_events():
    return [
        _event("process", "elastic", event_provider="Microsoft-Windows-Sysmon",
               hostname="windows.example", process_id=4242, process_name=IMAGE,
               command_line='powershell.exe -NoProfile -Command "approved synthetic marker"',
               event_action="observed"),
        _event("script", "elastic", "2026-01-01T00:00:11Z",
               event_provider="Microsoft-Windows-PowerShell", hostname="windows.example",
               process_id=4242, event_action="observed"),
        _event("alert", "elastic", "2026-01-01T00:01:00Z",
               event_provider="elastic-security", hostname="windows.example", process_id=4242,
               rule_id="aegis-labb-safe-powershell-v1", event_action="observed"),
    ]


def _replace(event, **changes):
    return CanonicalEventV2.model_validate(event.model_dump(mode="python") | changes)


def _evaluate(contracts, events):
    manifest, profile, context = contracts
    return evaluate_scenario(manifest, events, profile=profile, context=context)


def _outcomes(result):
    return {assertion.assertion_id: (assertion.outcome, assertion.reason_code)
            for assertion in result.assertions}


def test_powershell_profile_is_bound_to_its_separate_manifest(ps_contracts):
    manifest, profile, _ = ps_contracts
    assert manifest.id == "SCN-005"
    assert profile.scenario_fingerprint == scenario_fingerprint(manifest)
    assert [assertion.source for assertion in manifest.assertions] == ["elastic"] * 3
    assert _evaluate(ps_contracts, []).final_status == "Missing telemetry"


def test_powershell_three_distinct_witnesses_are_detected(ps_contracts):
    result = _evaluate(ps_contracts, _ps_events())
    assert result.final_status == "Detected"
    assert [a.outcome for a in result.assertions] == ["satisfied"] * 3
    assert [(p.target_event_id, p.anchor_event_id) for p in result.assertions[2].witness_pairs] == [("alert", "script")]


def test_alert_copy_cannot_replace_windows_telemetry(ps_contracts):
    result = _evaluate(ps_contracts, [_ps_events()[2]])
    assert result.final_status == "Missing telemetry"
    assert result.assertions[0].outcome == result.assertions[1].outcome == "missing_telemetry"


def test_sysmon_network_record_cannot_replace_process_creation(ps_contracts):
    events = _ps_events()
    events[0] = _replace(events[0], command_line=None, src_ip="192.0.2.10", dst_ip="198.51.100.20")
    assert _evaluate(ps_contracts, events).assertions[0].outcome == "missing_telemetry"


@pytest.mark.parametrize("changes", [
    {"hostname": "other.example"}, {"process_id": 4243},
    {"rule_id": "another-rule"}, {"event_provider": "Microsoft-Windows-PowerShell"},
    {"timestamp": "2026-01-01T00:00:10.999999999Z"},
    {"timestamp": "2026-01-01T00:02:11.000000001Z"},
])
def test_wrong_or_out_of_window_alert_never_satisfies_detection(ps_contracts, changes):
    events = _ps_events()
    events[2] = _replace(events[2], **changes)
    result = _evaluate(ps_contracts, events)
    assert _outcomes(result)["SCN-005-A03"] == ("inconclusive", "collection_not_confirmed")
    assert result.final_status == "Inconclusive"


@pytest.mark.parametrize("timestamp", ["2026-01-01T00:00:11Z", "2026-01-01T00:02:11Z"])
def test_powershell_alert_interval_includes_its_pinned_endpoints(ps_contracts, timestamp):
    events = _ps_events()
    events[2] = _replace(events[2], timestamp=timestamp)
    assert _evaluate(ps_contracts, events).final_status == "Detected"


def test_missing_alert_does_not_invent_a_complete_collection_declaration(ps_contracts):
    result = _evaluate(ps_contracts, _ps_events()[:2])
    assert result.final_status == "Inconclusive"
    assert _outcomes(result)["SCN-005-A03"] == ("inconclusive", "collection_not_confirmed")


@pytest.mark.parametrize("changes", [{"hostname": "other.example"}, {"process_id": 4243},
                                     {"process_name": r"C:\Synthetic\other.exe"}])
def test_powershell_process_scope_does_not_accept_another_execution(ps_contracts, changes):
    events = _ps_events()
    events[0] = _replace(events[0], **changes)
    assert _evaluate(ps_contracts, events).assertions[0].outcome == "missing_telemetry"


def _tuple():
    return dict(src_ip="192.0.2.10", src_port=51000, dst_ip="198.51.100.20", dst_port=8080)


def _network_events():
    return [
        _event("connection", "elastic", event_provider="Microsoft-Windows-Sysmon",
               protocol="tcp", event_action="observed", **_tuple()),
        _event("ids", "suricata", "2026-01-01T00:00:09Z", event_provider="suricata",
               protocol="TCP", signature_id="9900201", event_action="allowed", **_tuple()),
        _event("firewall", "pfsense", "2026-01-01T00:00:09Z", event_provider="pfSense-filterlog",
               protocol="tcp", rule_id="1700000001", event_action="allowed", **_tuple()),
    ]


def test_network_profile_proves_visibility_and_never_claims_prevention(net_contracts):
    manifest, profile, _ = net_contracts
    assert profile.scenario_fingerprint == scenario_fingerprint(manifest)
    result = _evaluate(net_contracts, _network_events())
    assert result.final_status == "Detected"
    assert [a.role for a in result.assertions] == ["telemetry", "detection", "telemetry"]
    assert [a.outcome for a in result.assertions] == ["satisfied"] * 3


@pytest.mark.parametrize("changes", [
    {"src_ip": "192.0.2.11"}, {"src_port": 51001}, {"dst_ip": "198.51.100.21"},
    {"dst_port": 8081}, {"protocol": "UDP"}, {"signature_id": "9900202"},
    {"timestamp": "2026-01-01T00:00:06.999999999Z"},
    {"timestamp": "2026-01-01T00:00:13.000000001Z"},
])
def test_network_ids_requires_the_same_tuple_signature_and_clock_window(net_contracts, changes):
    events = _network_events()
    events[1] = _replace(events[1], **changes)
    assert _evaluate(net_contracts, events).assertions[1].outcome == "inconclusive"


@pytest.mark.parametrize("changes", [
    {"src_ip": "192.0.2.11"}, {"src_port": 51001}, {"dst_ip": "198.51.100.21"},
    {"dst_port": 8081}, {"protocol": "udp"}, {"rule_id": "1700000002"}, {"event_action": "blocked"},
])
def test_firewall_visibility_requires_the_bound_allowed_flow(net_contracts, changes):
    events = _network_events()
    events[2] = _replace(events[2], **changes)
    assert _evaluate(net_contracts, events).assertions[2].outcome == "missing_telemetry"


def test_ids_alert_cannot_replace_the_windows_connection(net_contracts):
    result = _evaluate(net_contracts, _network_events()[1:])
    assert result.final_status == "Missing telemetry"
    assert result.assertions[0].outcome == "missing_telemetry"
