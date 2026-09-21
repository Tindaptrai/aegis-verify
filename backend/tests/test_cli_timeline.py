"""The CLI report's evidence timeline copies canonical values in time order."""

from pathlib import Path

from aegis_verify.cli.service import evaluate_bundle, evidence_timeline
from aegis_verify.models import CanonicalEventV2
from aegis_verify.validation import EvaluationResult

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "tests" / "fixtures" / "cli" / "synthetic-detected"


def test_report_timeline_orders_referenced_evidence_and_keeps_nulls():
    report = evaluate_bundle(BUNDLE / "scenario.yaml", BUNDLE)
    timeline = report["timeline"]
    assert timeline["version"] == "0.3.0"
    assert timeline["order"] == "timestamp_then_event_id"
    events = timeline["events"]
    assert [event["raw_event_ref"] for event in events] == ["synthetic-activity#record=1", "synthetic-alert#record=1"]
    assert {event["event_id"] for event in events} == {
        entry["event_id"] for entry in report["evaluation"]["evidence_index"]}
    assert events[0]["timestamp"] == "2026-01-01T00:00:01Z"
    assert events[1]["timestamp"] == "2026-01-01T00:00:02Z"
    assert events[0]["rule_id"] == "900001" and events[1]["rule_id"] == "900002"
    assert events[0]["signature_id"] is None  # absent in source, never filled
    assert set(events[0]) == {"event_id", "timestamp", "ingested_at", "source_type", "event_provider",
                              "hostname", "event_action", "rule_id", "signature_id", "process_name",
                              "raw_event_ref", "source_ref", "source_label", "source_derived"}
    # This bundle configures no label, so the configured fields stay null while
    # the source ref still says which manifest entry the record came from.
    assert events[0]["source_ref"] == "synthetic-activity"
    assert events[0]["source_label"] is None
    # These bytes are the fixture files themselves, not an extract.
    assert events[0]["source_derived"] is False


def _event(event_id, timestamp):
    return CanonicalEventV2(event_id=event_id, source_type="wazuh", environment_id="e", timestamp=timestamp,
                            ingested_at="2026-01-01T00:00:09Z", raw_event_ref="ref/" + event_id,
                            raw_event_hash="a" * 64)


def test_timeline_ties_break_on_event_id_and_unreferenced_events_are_excluded():
    events = [_event("b", "2026-01-01T00:00:01.000000002Z"), _event("a", "2026-01-01T00:00:01.000000002Z"),
              _event("z", "2026-01-01T00:00:00Z"), _event("unreferenced", "2025-01-01T00:00:00Z")]
    result = EvaluationResult.model_validate({
        "run_id": "r", "scenario_id": "S", "scenario_version": "0.1.0", "profile_id": "p",
        "profile_version": "0.1.0", "scenario_fingerprint": "0" * 64, "profile_fingerprint": "0" * 64,
        "scope_fingerprint": "0" * 64, "context_fingerprint": "0" * 64, "event_set_fingerprint": "0" * 64,
        "final_status": "Detected",
        "assertions": [{"assertion_id": "S-A01", "role": "telemetry", "outcome": "satisfied",
                        "reason_code": "witness_found", "evidence_ids": ["a", "b", "z"]}],
        "counts": {"satisfied": 1},
        "evidence_index": [{"event_id": i, "raw_event_ref": "ref/" + i, "raw_event_hash": "a" * 64}
                           for i in ("a", "b", "z")],
    })
    ordered = [e["event_id"] for e in evidence_timeline(events, result)["events"]]
    assert ordered == ["z", "a", "b"]
