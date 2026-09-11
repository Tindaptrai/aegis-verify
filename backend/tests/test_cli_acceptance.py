"""Portable synthetic-only acceptance bundle; real subprocess/parser/engine path."""

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


BUNDLE = Path(__file__).resolve().parents[2] / "tests/fixtures/cli/synthetic-detected"


def command(bundle=BUNDLE, *extra):
    return subprocess.run(
        [sys.executable, "-m", "aegis_verify", "validate", "--scenario",
         str(bundle / "scenario.yaml"), "--fixture", str(bundle), "--format=json", *extra],
        capture_output=True, text=True, check=False,
    )


def test_portable_sample_detects_distinct_activity_and_alert():
    result = command()
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert result.stderr == ""
    assert report["evaluation"]["final_status"] == "Detected"
    assert report["counts"] == {"parsed": 2, "referenced": 2, "skipped": 0}
    evidence = report["evaluation"]["evidence_index"]
    assert len({event["event_id"] for event in evidence}) == 2
    by_ref = {event["raw_event_ref"]: event for event in evidence}
    pair = report["evaluation"]["assertions"][1]["witness_pairs"]
    assert pair == [{
        "anchor_event_id": by_ref["synthetic-activity#record=1"]["event_id"],
        "target_event_id": by_ref["synthetic-alert#record=1"]["event_id"],
    }]
    assert {ref: item["raw_event_hash"] for ref, item in by_ref.items()} == {
        "synthetic-activity#record=1": "ea047cbd66426cbcea520654e075a1d33e8aefbe44bb6c8a0ff9f0f0d29707f2",
        "synthetic-alert#record=1": "f42363eef779bd818fbada18825f90c8f6c5ce36e71d0a792f33f1780cff113f",
    }


@pytest.fixture
def portable(tmp_path):
    return Path(shutil.copytree(BUNDLE, tmp_path / "portable space đ"))


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def remove_alert(bundle):
    inputs = json.loads((bundle / "inputs.json").read_bytes())
    inputs["files"] = inputs["files"][:1]
    write_json(bundle / "inputs.json", inputs)


def test_move_and_repeat_preserve_complete_report_and_input_bytes(portable):
    before = {p.name: p.read_bytes() for p in portable.iterdir() if p.is_file()}
    original, moved, repeated = command(), command(portable), command(portable)
    assert original.returncode == moved.returncode == repeated.returncode == 0
    assert original.stdout == moved.stdout == repeated.stdout
    assert original.stderr == moved.stderr == repeated.stderr == ""
    assert before == {p.name: p.read_bytes() for p in portable.iterdir() if p.is_file()}
    assert str(portable) not in moved.stdout


def test_removed_alert_unknown_assurance_retains_activity(portable):
    remove_alert(portable)
    result = command(portable)
    assert result.returncode == 3
    assert result.stderr == ""
    evaluation = json.loads(result.stdout)["evaluation"]
    assert evaluation["final_status"] == "Inconclusive"
    activity_id = evaluation["evidence_index"][0]["event_id"]
    assert evaluation["assertions"][1]["evidence_ids"] == [activity_id]
    assert evaluation["assertions"][1]["witness_pairs"] == []


def attest_synthetic_absence(bundle):
    remove_alert(bundle)
    initial = command(bundle)
    assert initial.returncode == 3
    evaluation = json.loads(initial.stdout)["evaluation"]
    context = json.loads((bundle / "context.json").read_bytes())
    context["declarations"] = [{
        "assertion_id": "SCN-999-A02", "status": "complete_for_scope",
        "confirmed_by": "synthetic-test-reviewer", "reference": "synthetic-test-only",
        "coverage_start": context["start"], "coverage_end": context["end"],
        "no_sampling_or_truncation": True, "no_parse_errors_or_gaps": True,
        "clocks_adequate": True,
        **{key: evaluation[key] for key in (
            "profile_fingerprint", "scope_fingerprint", "event_set_fingerprint")},
    }]
    write_json(bundle / "context.json", context)
    return context


def test_synthetic_attested_absence_is_false_negative(portable):
    attest_synthetic_absence(portable)
    result = command(portable)
    assert result.returncode == 1
    assert result.stderr == ""
    evaluation = json.loads(result.stdout)["evaluation"]
    assert evaluation["final_status"] == "False negative"
    assert evaluation["assertions"][1]["collection_assurance"] == "caller-attested"
    assert evaluation["assertions"][1]["evidence_ids"]


@pytest.mark.parametrize("change,expected_field", [
    ("run", "scope_fingerprint"),
    ("window", "scope_fingerprint"),
    ("profile", "profile_fingerprint"),
])
def test_stale_synthetic_attestation_is_rejected(portable, change, expected_field):
    context = attest_synthetic_absence(portable)
    if change == "profile":
        profile = json.loads((portable / "profile.json").read_bytes())
        profile["profile_id"] = "synthetic-revised-profile"
        write_json(portable / "profile.json", profile)
    else:
        context["run_id" if change == "run" else "end"] = (
            "synthetic-other-run" if change == "run" else "2026-01-01T00:00:59Z")
        write_json(portable / "context.json", context)
    result = command(portable)
    assert result.returncode == 2
    assert result.stdout == ""
    diagnostic = json.loads(result.stderr)
    assert diagnostic["kind"] == "error"
    assert diagnostic["error"]["code"] == "invalid_collection_declaration"
    assert diagnostic["error"]["stage"] == "collection"
    assert diagnostic["error"]["field"] == expected_field


def test_empty_inventory_is_missing_telemetry(portable):
    inputs = json.loads((portable / "inputs.json").read_bytes())
    inputs["files"] = []
    write_json(portable / "inputs.json", inputs)
    result = command(portable)
    assert result.returncode == 1
    assert result.stderr == ""
    report = json.loads(result.stdout)
    assert report["evaluation"]["final_status"] == "Missing telemetry"
    assert report["evaluation"]["evidence_index"] == []
    assert report["counts"] == {"parsed": 0, "referenced": 0, "skipped": 0}


@pytest.mark.parametrize("damage,code", [
    ("hash", "hash_mismatch"), ("late-input", "parser_error"), ("profile", "input_io")])
def test_damaged_sample_never_emits_partial_verdict(portable, damage, code):
    inputs = json.loads((portable / "inputs.json").read_bytes())
    if damage == "profile":
        (portable / "profile.json").unlink()
    elif damage == "hash":
        inputs["files"][-1]["sha256"] = "0" * 64
    else:
        raw = b'{"synthetic_invalid_last_input":true}\n'
        (portable / "alert.json").write_bytes(raw)
        inputs["files"][-1]["sha256"] = sha256(raw).hexdigest()
    write_json(portable / "inputs.json", inputs)
    result = command(portable)
    assert result.returncode == 2
    assert result.stdout == ""
    diagnostic = json.loads(result.stderr)
    assert diagnostic["error"]["code"] == code
    assert "synthetic_invalid_last_input" not in result.stderr


def test_explicit_files_ignore_broken_defaults_and_do_not_fallback(portable, tmp_path):
    profile, context = tmp_path / "chosen-profile.json", tmp_path / "chosen-context.json"
    shutil.copy2(portable / "profile.json", profile)
    shutil.copy2(portable / "context.json", context)
    (portable / "profile.json").write_bytes(b"broken-default")
    (portable / "context.json").write_bytes(b"broken-default")
    args = ("--profile", str(profile), "--context", str(context))
    assert command(portable, *args).returncode == 0
    context.write_bytes(b"broken-selected")
    result = command(portable, *args)
    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["stage"] == "context"


def test_prevention_from_real_eve_parser_has_distinct_blocked_witness(tmp_path):
    from test_cli_validate import write_prevented_case

    scenario, bundle = write_prevented_case(tmp_path)
    shutil.copy2(scenario, bundle / "scenario.yaml")
    result = command(bundle)
    assert result.returncode == 0
    assert result.stderr == ""
    report = json.loads(result.stdout)
    assert report["evaluation"]["final_status"] == "Prevented"
    pairs = report["evaluation"]["assertions"][1]["witness_pairs"]
    assert len(pairs) == 1
    assert pairs[0]["anchor_event_id"] != pairs[0]["target_event_id"]
    assert "ids_blocked_action_requires_review" in {
        warning for entry in report["intake"]["ledger"] for warning in entry["warnings"]}


def test_unsupported_eve_skip_blocks_complete_detection_claim(tmp_path):
    from test_cli_validate import write_prevented_case
    from aegis_verify.scenario_loader import load_scenario
    from aegis_verify.validation import scenario_fingerprint

    scenario, bundle = write_prevented_case(tmp_path)
    selected_scenario = bundle / "scenario.yaml"
    selected_scenario.write_bytes(scenario.read_bytes().replace(
        b"expected_outcome: prevented", b"expected_outcome: detected"))
    profile = json.loads((bundle / "profile.json").read_bytes())
    profile["scenario_fingerprint"] = scenario_fingerprint(load_scenario(selected_scenario))
    profile["rules"][1]["role"] = "detection"
    profile["rules"][1]["match"] = [{"field": "rule_id", "op": "eq", "value": "999999"}]
    write_json(bundle / "profile.json", profile)
    path = bundle / "flow-1.jsonl"
    path.write_bytes(path.read_bytes() + b'{"event_type":"dns"}\n')
    inputs = json.loads((bundle / "inputs.json").read_bytes())
    inputs["files"][1]["sha256"] = sha256(path.read_bytes()).hexdigest()
    write_json(bundle / "inputs.json", inputs)
    initial = command(bundle)
    assert initial.returncode == 3
    report = json.loads(initial.stdout)
    assert report["counts"]["skipped"] == 1
    assert report["intake"]["ledger"][-1]["reason"] == "unsupported_event_type"
    assert report["intake"]["ledger"][-1]["event_id"] is None
    context = json.loads((bundle / "context.json").read_bytes())
    context["declarations"] = [{
        "assertion_id": "SCN-999-A02", "status": "complete_for_scope",
        "confirmed_by": "synthetic-test-reviewer", "reference": "synthetic-test-only",
        "coverage_start": context["start"], "coverage_end": context["end"],
        "no_sampling_or_truncation": True, "no_parse_errors_or_gaps": True,
        "clocks_adequate": True,
        **{key: report["evaluation"][key] for key in (
            "profile_fingerprint", "scope_fingerprint", "event_set_fingerprint")},
    }]
    write_json(bundle / "context.json", context)
    result = command(bundle)
    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == "collection_conflict"
