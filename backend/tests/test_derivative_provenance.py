"""Extracted evidence bytes must never pass as a native capture.

Some records reach a bundle as a derivative: the original line lives inside a
manager archive field, and the importer decodes that field and encodes it as
UTF-8. Those bytes parse correctly, but their hash is not the hash of any file
the lab wrote. A bundle may therefore declare the parent archive hash and the
reviewed extraction rule, and that declaration travels to the report so a
reviewer can retrace it. The declaration is caller-supplied provenance, never a
verdict, and it changes no identity.
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
PARENT = "b" * 64
RULE = "wazuh-archive-full-log-utf8-v1"


def _manifest() -> dict:
    return json.loads((BUNDLE / "inputs.json").read_text(encoding="utf-8"))


def _derivation(parent: str = PARENT, extraction: str = RULE) -> dict:
    return {"parent_sha256": parent, "extraction": extraction}


def _bundle(tmp_path: Path, derivations) -> tuple[Path, Path]:
    """Copy the reviewed fixture and declare derivation on chosen entries."""
    fixture = tmp_path / "bundle"
    shutil.copytree(BUNDLE, fixture)
    manifest = _manifest()
    for entry, derived in zip(manifest["files"], derivations):
        if derived is None:
            entry.pop("derived_from", None)
        else:
            entry["derived_from"] = derived
    (fixture / "inputs.json").write_text(
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return fixture / "scenario.yaml", fixture


def test_an_entry_without_a_declaration_stays_native():
    manifest = parse_manifest(_manifest())
    assert [entry.derived_from for entry in manifest.files] == [None, None]


def test_a_declaration_keeps_the_parent_hash_and_the_reviewed_rule():
    data = _manifest()
    data["files"][0]["derived_from"] = _derivation()
    entry = parse_manifest(data).files[0]
    assert entry.derived_from is not None
    assert entry.derived_from.parent_sha256 == PARENT
    assert entry.derived_from.extraction == RULE


@pytest.mark.parametrize(
    "derivation, field",
    [
        (_derivation(extraction="decode-json-take-full-log"), "extraction"),
        (_derivation(extraction=""), "extraction"),
        (_derivation(parent="B" * 64), "parent_sha256"),
        (_derivation(parent="b" * 63), "parent_sha256"),
        (_derivation(parent="z" * 64), "parent_sha256"),
        ({"parent_sha256": PARENT}, "extraction"),
        ({"extraction": RULE}, "parent_sha256"),
        ({"parent_sha256": PARENT, "extraction": RULE, "note": "x"}, "derived_from"),
        ("not-an-object", "derived_from"),
        ([PARENT, RULE], "derived_from"),
    ],
)
def test_a_malformed_declaration_is_refused_with_a_safe_error(derivation, field):
    data = _manifest()
    data["files"][0]["derived_from"] = derivation
    with pytest.raises(IntakeError) as raised:
        parse_manifest(data)
    error = raised.value
    assert error.code == "invalid_manifest"
    assert error.stage == "inputs"
    assert error.file_index == 0
    assert error.field == field


def test_a_parent_equal_to_the_entrys_own_hash_is_refused():
    data = _manifest()
    own = data["files"][0]["sha256"]
    data["files"][0]["derived_from"] = _derivation(parent=own)
    with pytest.raises(IntakeError) as raised:
        parse_manifest(data)
    assert raised.value.code == "invalid_manifest"
    assert raised.value.field == "parent_sha256"


def test_the_declaration_reaches_the_report_inventory_as_plain_data(tmp_path):
    scenario, fixture = _bundle(tmp_path, [_derivation(), None])
    report = evaluate_bundle(scenario, fixture)
    inventory = {item["source_ref"]: item["derived_from"] for item in report["intake"]["inventory"]}
    assert inventory["synthetic-activity"] == {"parent_sha256": PARENT, "extraction": RULE}
    assert inventory["synthetic-alert"] is None
    # The whole report must stay serialisable; the CLI renders it as JSON.
    json.dumps(report, allow_nan=False)


def test_the_timeline_marks_a_derivative_and_leaves_a_native_record_alone(tmp_path):
    scenario, fixture = _bundle(tmp_path, [_derivation(), None])
    report = evaluate_bundle(scenario, fixture)
    by_ref = {event["raw_event_ref"]: event for event in report["timeline"]["events"]}
    assert by_ref["synthetic-activity#record=1"]["source_derived"] is True
    assert by_ref["synthetic-alert#record=1"]["source_derived"] is False


def test_declaring_derivation_changes_no_identity_and_no_attested_fingerprint(tmp_path):
    plain_scenario, plain = _bundle(tmp_path / "plain", [None, None])
    derived_scenario, derived = _bundle(tmp_path / "derived", [_derivation(), None])
    before = evaluate_bundle(plain_scenario, plain)
    after = evaluate_bundle(derived_scenario, derived)

    for field in ("profile_fingerprint", "scope_fingerprint", "event_set_fingerprint",
                  "scenario_fingerprint", "context_fingerprint", "final_status"):
        assert before["evaluation"][field] == after["evaluation"][field]
    assert before["evaluation"]["evidence_index"] == after["evaluation"]["evidence_index"]

    def identity(report):
        return [
            {key: event[key] for key in event if key != "source_derived"}
            for event in report["timeline"]["events"]
        ]

    assert identity(before) == identity(after)
    # The parser context is untouched, so a per-source context fingerprint holds.
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


def test_an_unresolved_event_says_unknown_rather_than_claiming_native():
    events = [_event("a", "2026-01-01T00:00:01Z"), _event("b", "2026-01-01T00:00:02Z")]
    timeline = evidence_timeline(
        events,
        _result(("a", "b")),
        sources={"a": {"source_ref": "known", "source_label": None, "source_derived": True}},
    )
    by_id = {event["event_id"]: event for event in timeline["events"]}
    assert by_id["a"]["source_derived"] is True
    # Nothing is known about b, so the report must not assert that it is native.
    assert by_id["b"]["source_derived"] is None
    assert by_id["b"]["source_ref"] is None
