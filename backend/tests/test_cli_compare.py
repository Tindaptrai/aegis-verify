"""End-to-end tests for comparing two offline validation reports."""

from hashlib import sha256
import json
import subprocess
import sys
from pathlib import Path

from aegis_verify.scenario_loader import parse_scenario_yaml
from aegis_verify.validation import scenario_fingerprint


def run_validate_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aegis_verify", "validate", *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


def run_compare_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aegis_verify", "compare", *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


def encode_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


SCENARIO = b"""\
id: SCN-999
name: Synthetic CLI validation
version: 0.1.0
status: draft
description: Synthetic test-only scenario.
safety:
  destructive: false
  authorization_required: true
  notes: Synthetic test-only input; no action is executed.
expected_sources: [wazuh]
expected_outcome: detected
assertions:
  - id: SCN-999-A01
    description: Synthetic activity exists.
    source: wazuh
  - id: SCN-999-A02
    description: Synthetic detection exists.
    source: wazuh
"""


def wazuh_record(*, rule_id: str = "67027") -> bytes:
    return encode_json(
        {
            "_source": {
                "id": "synthetic-record",
                "agent": {"id": "901", "name": "synthetic-host"},
                "manager": {"name": "synthetic-manager"},
                "rule": {"id": rule_id, "level": 3},
                "data": {
                    "win": {
                        "system": {
                            "providerName": "Microsoft-Windows-Security-Auditing",
                            "channel": "Security",
                            "eventID": "4688",
                            "systemTime": "2026-01-01T00:00:01Z",
                            "computer": "synthetic-host",
                        },
                        "eventdata": {
                            "newProcessId": "0x1",
                            "newProcessName": "synthetic.exe",
                        },
                    }
                },
            }
        }
    )


def write_synthetic_case(
    tmp_path: Path, *, records=2, evidence_rule_id="67027", run_id="synthetic-run", attested=False
):
    scenario_path = tmp_path / "scenario.yaml"
    fixture = tmp_path / "fixture"
    fixture.mkdir(parents=True)
    scenario_path.write_bytes(SCENARIO)
    manifest = parse_scenario_yaml(SCENARIO.decode(), source_name="<test-scenario>")
    profile = {
        "profile_schema_version": "0.1.0",
        "profile_id": "synthetic-profile",
        "profile_version": "0.1.0",
        "scenario_id": "SCN-999",
        "scenario_version": "0.1.0",
        "scenario_fingerprint": scenario_fingerprint(manifest),
        "rules": [
            {
                "assertion_id": "SCN-999-A01",
                "role": "telemetry",
                "capability": "supported",
                "source_type": "wazuh",
                "scope": [{"field": "hostname", "op": "eq", "binding": "target"}],
            },
            {
                "assertion_id": "SCN-999-A02",
                "role": "detection",
                "capability": "supported",
                "source_type": "wazuh",
                "scope": [{"field": "hostname", "op": "eq", "binding": "target"}],
                "match": [{"field": "rule_id", "op": "eq", "value": "67027"}],
                "correlation": {
                    "anchor_assertion_id": "SCN-999-A01",
                    "join_pairs": [{"target_field": "hostname", "anchor_field": "hostname"}],
                    "min_delta_ns": -1_000_000_000,
                    "max_delta_ns": 1_000_000_000,
                },
            },
        ],
    }
    context = {
        "run_id": run_id,
        "environment_id": "synthetic-lab",
        "start": "2026-01-01T00:00:00Z",
        "end": "2026-01-01T00:01:00Z",
        "bindings": [{"name": "target", "value": "synthetic-host"}],
        "declarations": [],
    }

    entries = []
    for index in range(records):
        raw = wazuh_record(rule_id=evidence_rule_id if index == 1 else "11111")
        name = f"event-{index}.json"
        (fixture / name).write_bytes(raw)
        entries.append(
            {
                "path": name,
                "source_ref": f"synthetic-{index}.json",
                "parser": "wazuh-win4688-v2",
                "sha256": sha256(raw).hexdigest(),
                "context": {
                    "ingested_at": "2026-01-01T00:00:02Z",
                    "collection_mode": "direct",
                },
            }
        )
    inputs = {
        "bundle_schema_version": "0.1.0",
        "environment_id": "synthetic-lab",
        "files": entries,
    }
    for name, value in (
        ("inputs.json", inputs),
        ("profile.json", profile),
        ("context.json", context),
    ):
        (fixture / name).write_bytes(encode_json(value))

    if attested:
        from aegis_verify.intake import load_bundle, parse_manifest
        from aegis_verify.validation import (
            EvaluationContext, EvaluationProfile, event_set_fingerprint,
            profile_fingerprint, scope_fingerprint,
        )
        intake = load_bundle(fixture, parse_manifest(inputs))
        context["declarations"] = [{
            "assertion_id": "SCN-999-A02", "status": "complete_for_scope",
            "confirmed_by": "synthetic-reviewer", "reference": "synthetic-only/attestation",
            "coverage_start": context["start"], "coverage_end": context["end"],
            "no_sampling_or_truncation": True, "no_parse_errors_or_gaps": True,
            "clocks_adequate": True,
            "profile_fingerprint": profile_fingerprint(EvaluationProfile.model_validate(profile)),
            "scope_fingerprint": scope_fingerprint(EvaluationContext.model_validate(context)),
            "event_set_fingerprint": event_set_fingerprint(intake.events),
        }]
        (fixture / "context.json").write_bytes(encode_json(context))

    return scenario_path, fixture


def _write_report(path: Path, report_stdout: str) -> None:
    path.write_text(report_stdout, encoding="utf-8")


def _read_report(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_compare_subcommand_is_listed_in_help():
    result = subprocess.run(
        [sys.executable, "-m", "aegis_verify", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert "validate" in result.stdout
    assert "compare" in result.stdout


def test_compare_json_output_reports_improvement_and_evidence_trace(tmp_path):
    before_scenario, before_fixture = write_synthetic_case(
        tmp_path / "before",
        records=2,
        evidence_rule_id="99999",
        run_id="run-before",
        attested=True,
    )
    after_scenario, after_fixture = write_synthetic_case(
        tmp_path / "after", records=2, evidence_rule_id="67027", run_id="run-after"
    )

    before_result = run_validate_cli(
        "--scenario",
        str(before_scenario),
        "--fixture",
        str(before_fixture),
        "--format=json",
    )
    after_result = run_validate_cli(
        "--scenario",
        str(after_scenario),
        "--fixture",
        str(after_fixture),
        "--format=json",
    )
    assert before_result.returncode in {0, 1, 3}
    assert after_result.returncode in {0, 1, 3}
    assert before_result.stderr == after_result.stderr == ""

    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    _write_report(before_path, before_result.stdout)
    _write_report(after_path, after_result.stdout)

    result = run_compare_cli(
        "--before", str(before_path), "--after", str(after_path), "--format=json"
    )
    assert result.returncode == 0
    assert result.stderr == ""

    report = json.loads(result.stdout)
    assert report["kind"] == "comparison"
    assert report["scenario"]["id"] == "SCN-999"
    assert report["comparison"]["status"] == "Regression Passed"
    assert report["comparison"]["assertion_state_counts"]["improvement"] == 1
    assert report["comparison"]["assertion_state_counts"]["unchanged_pass"] == 1

    by_id = {item["assertion_id"]: item for item in report["comparison"]["assertions"]}
    assert by_id["SCN-999-A01"]["state"] == "unchanged_pass"
    assert by_id["SCN-999-A02"]["state"] == "improvement"
    assert by_id["SCN-999-A02"]["before"]["evidence_refs"]
    assert by_id["SCN-999-A02"]["after"]["evidence_refs"]


def test_compare_service_report_regression(tmp_path):
    before_scenario, before_fixture = write_synthetic_case(
        tmp_path / "before", records=2, evidence_rule_id="67027", run_id="run-before"
    )
    after_scenario, after_fixture = write_synthetic_case(
        tmp_path / "after", records=2, evidence_rule_id="99999", run_id="run-after", attested=True
    )

    before_result = run_validate_cli(
        "--scenario", str(before_scenario), "--fixture", str(before_fixture), "--format=json"
    )
    after_result = run_validate_cli(
        "--scenario", str(after_scenario), "--fixture", str(after_fixture), "--format=json"
    )
    assert before_result.returncode in {0, 1, 3}
    assert after_result.returncode in {0, 1, 3}

    from aegis_verify.compare import compare_runs

    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    _write_report(before_path, before_result.stdout)
    _write_report(after_path, after_result.stdout)

    report = compare_runs(before=before_path, after=after_path)

    assert report["comparison"]["status"] == "Regression"
    by_id = {item["assertion_id"]: item for item in report["comparison"]["assertions"]}
    assert by_id["SCN-999-A01"]["state"] == "unchanged_pass"
    assert by_id["SCN-999-A02"]["state"] == "regression"


def test_compare_rejects_incompatible_runs(tmp_path):
    before_scenario, before_fixture = write_synthetic_case(
        tmp_path / "before", records=2, evidence_rule_id="67027", run_id="run-before"
    )
    after_scenario, after_fixture = write_synthetic_case(
        tmp_path / "after", records=2, evidence_rule_id="67027", run_id="run-after"
    )

    before_result = run_validate_cli(
        "--scenario", str(before_scenario), "--fixture", str(before_fixture), "--format=json"
    )
    after_result = run_validate_cli(
        "--scenario", str(after_scenario), "--fixture", str(after_fixture), "--format=json"
    )
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    _write_report(before_path, before_result.stdout)
    _write_report(after_path, after_result.stdout)

    bad_before = _read_report(before_path)
    bad_before["scenario"]["id"] = "SCN-DIFFERENT"
    _write_report(
        before_path,
        json.dumps(bad_before, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
    )

    mismatch = run_compare_cli("--before", str(before_path), "--after", str(after_path), "--format=json")
    assert mismatch.returncode == 2
    diagnostic = json.loads(mismatch.stderr)
    assert diagnostic["kind"] == "error"
    assert diagnostic["error"]["code"] == "comparison_incompatible"
    assert diagnostic["error"]["stage"] == "comparison"
    assert diagnostic["error"]["field"] == "scenario_id"


def test_compare_rejects_broken_evidence_trace(tmp_path):
    before_scenario, before_fixture = write_synthetic_case(
        tmp_path / "before", records=2, evidence_rule_id="67027"
    )
    after_scenario, after_fixture = write_synthetic_case(
        tmp_path / "after", records=2, evidence_rule_id="67027"
    )
    before_result = run_validate_cli(
        "--scenario", str(before_scenario), "--fixture", str(before_fixture), "--format=json"
    )
    after_result = run_validate_cli(
        "--scenario", str(after_scenario), "--fixture", str(after_fixture), "--format=json"
    )

    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    _write_report(before_path, before_result.stdout)
    _write_report(after_path, after_result.stdout)

    bad_before = _read_report(before_path)
    bad_before["evaluation"]["assertions"][1]["evidence_ids"] = ["missing-event-id"]
    _write_report(
        before_path,
        json.dumps(bad_before, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
    )

    broken = run_compare_cli("--before", str(before_path), "--after", str(after_path), "--format=json")
    assert broken.returncode == 2
    diagnostic = json.loads(broken.stderr)
    assert diagnostic["kind"] == "error"
    assert diagnostic["error"]["code"] == "comparison_missing_evidence_reference"
    assert diagnostic["error"]["field"] == "evidence_ids"
