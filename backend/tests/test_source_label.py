"""A configured source label travels to the report without touching identity.

The label is presentation metadata supplied by whoever assembled the bundle. It
must never be mistaken for an observed hostname, never be derived from the source
type or the evidence bytes, and never change an evidence identity or any
fingerprint a collection attestation is bound to.
"""

import json
import shutil
from pathlib import Path

import pytest

from aegis_verify.cli.service import evaluate_bundle, evidence_timeline
from aegis_verify.intake import IntakeError, parse_manifest
from aegis_verify.models import CanonicalEventV2
from aegis_verify.validation import EvaluationResult

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "tests" / "fixtures" / "cli" / "synthetic-detected"


def _manifest() -> dict:
    return json.loads((BUNDLE / "inputs.json").read_text(encoding="utf-8"))


def _bundle_with_labels(tmp_path: Path, labels) -> tuple[Path, Path]:
    """Copy the reviewed fixture and set display labels on its two entries."""
    fixture = tmp_path / "bundle"
    shutil.copytree(BUNDLE, fixture)
    manifest = _manifest()
    for entry, label in zip(manifest["files"], labels):
        if label is None:
            entry.pop("display_label", None)
        else:
            entry["display_label"] = label
    (fixture / "inputs.json").write_text(
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return fixture / "scenario.yaml", fixture


def test_manifest_without_label_stays_valid():
    manifest = parse_manifest(_manifest())
    assert [entry.display_label for entry in manifest.files] == [None, None]


def test_manifest_keeps_a_configured_label_verbatim():
    data = _manifest()
    data["files"][0]["display_label"] = "pfSense lab (DMZ)"
    manifest = parse_manifest(data)
    assert manifest.files[0].display_label == "pfSense lab (DMZ)"
    assert manifest.files[1].display_label is None


@pytest.mark.parametrize(
    "label",
    [
        "",
        "   ",
        "\t",
        "a" * 65,
        "lab\x00name",
        "lab\nname",
        "labname",
        "lab​name",
        123,
        ["lab"],
    ],
)
def test_invalid_labels_are_rejected_without_echoing_the_value(label):
    data = _manifest()
    data["files"][0]["display_label"] = label
    with pytest.raises(IntakeError) as raised:
        parse_manifest(data)
    error = raised.value
    assert error.code == "invalid_manifest"
    assert error.stage == "inputs"
    assert error.field == "display_label"
    assert error.file_index == 0
    rendered = str(label)
    if rendered:  # an empty string is a substring of everything
        assert rendered not in error.hint


def test_explicit_null_reads_as_no_label():
    data = _manifest()
    data["files"][0]["display_label"] = None
    assert parse_manifest(data).files[0].display_label is None


def test_label_reaches_the_inventory_and_every_timeline_event(tmp_path):
    scenario, fixture = _bundle_with_labels(tmp_path, ["pfSense lab", "Wazuh manager"])
    report = evaluate_bundle(scenario, fixture)

    inventory = {item["source_ref"]: item["display_label"] for item in report["intake"]["inventory"]}
    assert inventory == {"synthetic-activity": "pfSense lab", "synthetic-alert": "Wazuh manager"}

    by_ref = {event["raw_event_ref"]: event for event in report["timeline"]["events"]}
    activity = by_ref["synthetic-activity#record=1"]
    alert = by_ref["synthetic-alert#record=1"]
    assert activity["source_ref"] == "synthetic-activity"
    assert activity["source_label"] == "pfSense lab"
    assert alert["source_ref"] == "synthetic-alert"
    assert alert["source_label"] == "Wazuh manager"
    # The observed hostname is untouched and stays separate from the label.
    assert activity["hostname"] == "synthetic-host"


def test_two_entries_of_one_source_type_keep_their_own_labels(tmp_path):
    scenario, fixture = _bundle_with_labels(tmp_path, ["Firewall A", "Firewall B"])
    report = evaluate_bundle(scenario, fixture)
    events = report["timeline"]["events"]
    assert {event["source_type"] for event in events} == {"wazuh"}
    assert {event["source_label"] for event in events} == {"Firewall A", "Firewall B"}


def test_duplicate_labels_are_allowed_because_a_label_is_not_an_identity(tmp_path):
    scenario, fixture = _bundle_with_labels(tmp_path, ["Lab edge", "Lab edge"])
    report = evaluate_bundle(scenario, fixture)
    events = report["timeline"]["events"]
    assert [event["source_label"] for event in events] == ["Lab edge", "Lab edge"]
    assert len({event["source_ref"] for event in events}) == 2


def test_missing_label_stays_null_and_is_never_guessed(tmp_path):
    scenario, fixture = _bundle_with_labels(tmp_path, [None, "Wazuh manager"])
    report = evaluate_bundle(scenario, fixture)
    by_ref = {event["raw_event_ref"]: event for event in report["timeline"]["events"]}
    activity = by_ref["synthetic-activity#record=1"]
    assert activity["source_label"] is None
    assert activity["source_ref"] == "synthetic-activity"


def test_label_changes_no_identity_and_no_attested_fingerprint(tmp_path):
    plain_scenario, plain = _bundle_with_labels(tmp_path / "plain", [None, None])
    labelled_scenario, labelled = _bundle_with_labels(tmp_path / "labelled", ["Lab edge", "Lab core"])
    before = evaluate_bundle(plain_scenario, plain)
    after = evaluate_bundle(labelled_scenario, labelled)

    for field in ("profile_fingerprint", "scope_fingerprint", "event_set_fingerprint",
                  "scenario_fingerprint", "context_fingerprint", "final_status"):
        assert before["evaluation"][field] == after["evaluation"][field]
    assert before["evaluation"]["evidence_index"] == after["evaluation"]["evidence_index"]
    assert before["evaluation"]["assertions"] == after["evaluation"]["assertions"]

    def identity(report):
        return [
            {key: event[key] for key in event if key not in {"source_label", "source_ref"}}
            for event in report["timeline"]["events"]
        ]

    assert identity(before) == identity(after)
    # Only the manifest bytes differ, which is honest: the manifest did change.
    assert before["input_fingerprints"]["inputs"] != after["input_fingerprints"]["inputs"]
    for key in ("scenario", "profile", "context"):
        assert before["input_fingerprints"][key] == after["input_fingerprints"][key]
    # The parser context is unchanged, so a per-source context fingerprint holds.
    assert [item["context_fingerprint"] for item in before["intake"]["inventory"]] == [
        item["context_fingerprint"] for item in after["intake"]["inventory"]
    ]


def _event(event_id, timestamp):
    return CanonicalEventV2(
        event_id=event_id, source_type="wazuh", environment_id="e", timestamp=timestamp,
        ingested_at="2026-01-01T00:00:09Z", raw_event_ref="ref/" + event_id,
        raw_event_hash="a" * 64,
    )


def _result(event_ids):
    return EvaluationResult.model_validate({
        "run_id": "r", "scenario_id": "S", "scenario_version": "0.1.0", "profile_id": "p",
        "profile_version": "0.1.0", "scenario_fingerprint": "0" * 64, "profile_fingerprint": "0" * 64,
        "scope_fingerprint": "0" * 64, "context_fingerprint": "0" * 64, "event_set_fingerprint": "0" * 64,
        "final_status": "Detected",
        "assertions": [{"assertion_id": "S-A01", "role": "telemetry", "outcome": "satisfied",
                        "reason_code": "witness_found", "evidence_ids": list(event_ids)}],
        "counts": {"satisfied": 1},
        "evidence_index": [{"event_id": i, "raw_event_ref": "ref/" + i, "raw_event_hash": "a" * 64}
                           for i in event_ids],
    })


def test_timeline_leaves_an_unresolved_event_null_rather_than_guessing():
    events = [_event("a", "2026-01-01T00:00:01Z"), _event("b", "2026-01-01T00:00:02Z")]
    timeline = evidence_timeline(
        events, _result(("a", "b")), sources={"a": ("known-source", "Lab edge")}
    )
    by_id = {event["event_id"]: event for event in timeline["events"]}
    assert by_id["a"]["source_ref"] == "known-source"
    assert by_id["a"]["source_label"] == "Lab edge"
    assert by_id["b"]["source_ref"] is None
    assert by_id["b"]["source_label"] is None


def test_timeline_without_a_source_mapping_still_reports_null_labels():
    events = [_event("a", "2026-01-01T00:00:01Z")]
    timeline = evidence_timeline(events, _result(("a",)))
    assert timeline["events"][0]["source_ref"] is None
    assert timeline["events"][0]["source_label"] is None
