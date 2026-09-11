"""End-to-end contracts for the offline validation command.

All evidence created here is synthetic and test-only.
"""

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from aegis_verify.intake import IntakeError
from aegis_verify.scenario_loader import parse_scenario_yaml
from aegis_verify.validation import scenario_fingerprint


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aegis_verify", *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


SCENARIO = b"""\
id: SCN-999
name: Synthetic CLI validation
version: 0.1.0
status: draft
description: Synthetic test-only CLI scenario.
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


def encode_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


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


def write_detected_case(
    tmp_path: Path, *, records=2, detection_id="67027", scenario_bytes=SCENARIO
):
    fixture = tmp_path / "fixture"
    fixture.mkdir(parents=True)
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_bytes(scenario_bytes)
    manifest = parse_scenario_yaml(scenario_bytes.decode(), source_name="<test-scenario>")
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
                "match": [{"field": "rule_id", "op": "eq", "value": detection_id}],
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
        "run_id": "synthetic-run",
        "environment_id": "synthetic-lab",
        "start": "2026-01-01T00:00:00Z",
        "end": "2026-01-01T00:01:00Z",
        "bindings": [{"name": "target", "value": "synthetic-host"}],
        "declarations": [],
    }
    entries = []
    for index in range(records):
        raw = wazuh_record()
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
    for name, value in (("inputs.json", inputs), ("profile.json", profile), ("context.json", context)):
        (fixture / name).write_bytes(encode_json(value))
    return scenario_path, fixture, profile, context


def eve_flow(*, action: str, timestamp: str, flow_id: int) -> bytes:
    return encode_json(
        {
            "timestamp": timestamp,
            "event_type": "flow",
            "flow_id": flow_id,
            "src_ip": "192.0.2.10",
            "dest_ip": "198.51.100.20",
            "src_port": 42000,
            "dest_port": 443,
            "proto": "TCP",
            "flow": {
                "start": timestamp,
                "end": timestamp,
                "alerted": False,
                "pkts_toserver": 1,
                "pkts_toclient": 1,
                "bytes_toserver": 64,
                "bytes_toclient": 64,
                "state": "closed",
                "reason": "shutdown",
                "action": action,
            },
        }
    ) + b"\n"


def write_prevented_case(tmp_path: Path):
    scenario_bytes = SCENARIO.replace(b"expected_sources: [wazuh]", b"expected_sources: [suricata]")
    scenario_bytes = scenario_bytes.replace(b"expected_outcome: detected", b"expected_outcome: prevented")
    scenario_bytes = scenario_bytes.replace(b"source: wazuh", b"source: suricata")
    fixture = tmp_path / "fixture"
    fixture.mkdir(parents=True)
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_bytes(scenario_bytes)
    manifest = parse_scenario_yaml(scenario_bytes.decode(), source_name="<test-scenario>")
    profile = {
        "profile_schema_version": "0.1.0",
        "profile_id": "synthetic-prevention-profile",
        "profile_version": "0.1.0",
        "scenario_id": "SCN-999",
        "scenario_version": "0.1.0",
        "scenario_fingerprint": scenario_fingerprint(manifest),
        "rules": [
            {
                "assertion_id": "SCN-999-A01",
                "role": "telemetry",
                "capability": "supported",
                "source_type": "suricata",
                "scope": [{"field": "src_ip", "op": "eq", "binding": "target"}],
            },
            {
                "assertion_id": "SCN-999-A02",
                "role": "prevention",
                "capability": "supported",
                "source_type": "suricata",
                "scope": [{"field": "src_ip", "op": "eq", "binding": "target"}],
                "match": [{"field": "event_action", "op": "eq", "value": "blocked"}],
                "correlation": {
                    "anchor_assertion_id": "SCN-999-A01",
                    "join_pairs": [{"target_field": "src_ip", "anchor_field": "src_ip"}],
                    "min_delta_ns": 0,
                    "max_delta_ns": 2_000_000_000,
                },
            },
        ],
    }
    context = {
        "run_id": "synthetic-prevention-run",
        "environment_id": "synthetic-lab",
        "start": "2026-01-01T00:00:00Z",
        "end": "2026-01-01T00:01:00Z",
        "bindings": [{"name": "target", "value": "192.0.2.10"}],
        "declarations": [],
    }
    raw_records = (
        eve_flow(action="pass", timestamp="2026-01-01T00:00:01Z", flow_id=1),
        eve_flow(action="drop", timestamp="2026-01-01T00:00:02Z", flow_id=2),
    )
    entries = []
    for index, raw in enumerate(raw_records):
        name = f"flow-{index}.jsonl"
        (fixture / name).write_bytes(raw)
        entries.append(
            {
                "path": name,
                "source_ref": f"synthetic-flow-{index}.jsonl",
                "parser": "suricata-eve-jsonl-v1",
                "sha256": sha256(raw).hexdigest(),
                "context": {
                    "ingested_at": "2026-01-01T00:00:03Z",
                    "sensor_id": "synthetic-sensor",
                    "deployment_mode": "ids",
                },
            }
        )
    inputs = {"bundle_schema_version": "0.1.0", "environment_id": "synthetic-lab", "files": entries}
    for name, value in (("inputs.json", inputs), ("profile.json", profile), ("context.json", context)):
        (fixture / name).write_bytes(encode_json(value))
    return scenario_path, fixture


def test_module_help_is_available():
    result = run_cli("--help")

    assert result.returncode == 0
    assert result.stderr == ""
    assert "validate" in result.stdout


def test_missing_required_input_is_safe_error():
    result = run_cli("validate")

    assert result.returncode == 2
    assert result.stdout == ""
    assert "invalid_arguments" in result.stderr
    assert "Traceback" not in result.stderr


def test_duplicate_and_unknown_flags_do_not_echo_values():
    secret = "SECRET-ARGV-\x1b[31m"

    duplicate = run_cli(
        "validate", "--scenario", secret, "--scenario", secret, "--fixture", "."
    )
    unknown = run_cli("validate", "--scenario", "x", "--fixture", ".", "--bad", secret)

    for result in (duplicate, unknown):
        assert result.returncode == 2
        assert result.stdout == ""
        assert "invalid_arguments" in result.stderr
        assert secret not in result.stderr
        assert "Traceback" not in result.stderr


def test_unambiguous_json_format_selects_json_error_only():
    json_result = run_cli("validate", "--format", "json")
    duplicate = run_cli("validate", "--format", "json", "--format", "json")

    assert json_result.returncode == 2
    assert json_result.stdout == ""
    diagnostic = json.loads(json_result.stderr)
    assert diagnostic["kind"] == "error"
    assert diagnostic["error"]["code"] == "invalid_arguments"
    assert duplicate.returncode == 2
    assert duplicate.stdout == ""
    assert not duplicate.stderr.lstrip().startswith("{")


def test_service_evaluates_real_parser_bundle_and_retains_evidence_index(tmp_path):
    from aegis_verify.cli.service import evaluate_bundle

    scenario, fixture, _, _ = write_detected_case(tmp_path)
    report = evaluate_bundle(scenario, fixture)

    assert report["cli_report_version"] == "0.1.0"
    assert report["kind"] == "evaluation"
    assert report["scenario"] == {
        "id": "SCN-999",
        "name": "Synthetic CLI validation",
        "version": "0.1.0",
    }
    assert report["evaluation"]["final_status"] == "Detected"
    assert len(report["evaluation"]["evidence_index"]) == 2
    assert {item["raw_event_ref"] for item in report["evaluation"]["evidence_index"]} == {
        "synthetic-0.json#record=1",
        "synthetic-1.json#record=1",
    }
    assert {item["raw_event_hash"] for item in report["evaluation"]["evidence_index"]} == {
        sha256(wazuh_record()).hexdigest()
    }
    assert report["counts"] == {"parsed": 2, "skipped": 0, "referenced": 2}
    assert len(report["intake"]["ledger"]) == 2
    assert len(report["intake"]["inventory"]) == 2
    assert report["input_fingerprints"]["scenario"] == sha256(SCENARIO).hexdigest()
    assert all("fixture" not in str(item) for item in report["intake"]["inventory"])


def test_json_cli_is_parseable_deterministic_and_uses_status_exit_code(tmp_path):
    scenario, fixture, _, _ = write_detected_case(tmp_path)
    arguments = (
        "validate", "--scenario", str(scenario), "--fixture", str(fixture), "--format", "json"
    )

    first = run_cli(*arguments)
    second = run_cli(*arguments)

    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == ""
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)["evaluation"]["final_status"] == "Detected"


def test_missing_telemetry_and_inconclusive_are_evaluated_not_input_errors(tmp_path):
    empty_scenario, empty_fixture, _, _ = write_detected_case(tmp_path / "empty", records=0)
    uncertain_scenario, uncertain_fixture, _, _ = write_detected_case(
        tmp_path / "uncertain", records=1, detection_id="99999"
    )

    empty = run_cli(
        "validate", "--scenario", str(empty_scenario), "--fixture", str(empty_fixture), "--format=json"
    )
    uncertain = run_cli(
        "validate", "--scenario", str(uncertain_scenario), "--fixture", str(uncertain_fixture), "--format=json"
    )

    assert empty.returncode == 1
    assert json.loads(empty.stdout)["evaluation"]["final_status"] == "Missing telemetry"
    assert empty.stderr == ""
    assert uncertain.returncode == 3
    uncertain_report = json.loads(uncertain.stdout)
    assert uncertain_report["evaluation"]["final_status"] == "Inconclusive"
    assert uncertain_report["evaluation"]["assertions"][1]["evidence_ids"]
    assert uncertain.stderr == ""


def test_false_negative_uses_unchanged_engine_attestation(tmp_path):
    from aegis_verify.cli.service import evaluate_bundle

    scenario, fixture, _, context = write_detected_case(
        tmp_path, records=1, detection_id="99999"
    )
    initial = evaluate_bundle(scenario, fixture)
    evaluation = initial["evaluation"]
    context["declarations"] = [
        {
            "assertion_id": "SCN-999-A02",
            "status": "complete_for_scope",
            "confirmed_by": "synthetic-reviewer",
            "reference": "synthetic-test-only-attestation",
            "coverage_start": context["start"],
            "coverage_end": context["end"],
            "no_sampling_or_truncation": True,
            "no_parse_errors_or_gaps": True,
            "clocks_adequate": True,
            "profile_fingerprint": evaluation["profile_fingerprint"],
            "scope_fingerprint": evaluation["scope_fingerprint"],
            "event_set_fingerprint": evaluation["event_set_fingerprint"],
        }
    ]
    (fixture / "context.json").write_bytes(encode_json(context))

    result = run_cli(
        "validate", "--scenario", str(scenario), "--fixture", str(fixture), "--format=json"
    )

    report = json.loads(result.stdout)
    assert result.returncode == 1
    assert result.stderr == ""
    assert report["evaluation"]["final_status"] == "False negative"
    assert report["evaluation"]["assertions"][1]["collection_assurance"] == "caller-attested"
    assert report["evaluation"]["assertions"][1]["evidence_ids"]


def test_prevented_uses_distinct_real_parser_witnesses_and_warns(tmp_path):
    scenario, fixture = write_prevented_case(tmp_path)

    result = run_cli(
        "validate", "--scenario", str(scenario), "--fixture", str(fixture), "--format=json"
    )

    report = json.loads(result.stdout)
    assertion = report["evaluation"]["assertions"][1]
    assert result.returncode == 0
    assert result.stderr == ""
    assert report["evaluation"]["final_status"] == "Prevented"
    assert assertion["witness_pairs"]
    assert assertion["witness_pairs"][0]["target_event_id"] != assertion["witness_pairs"][0]["anchor_event_id"]
    assert "ids_blocked_action_requires_review" in {
        warning for entry in report["intake"]["ledger"] for warning in entry["warnings"]
    }


def test_explicit_profile_and_context_never_read_or_fallback_to_defaults(tmp_path):
    from aegis_verify.cli.service import evaluate_bundle

    scenario, fixture, _, _ = write_detected_case(tmp_path)
    external_profile = tmp_path / "external-profile.json"
    external_context = tmp_path / "external-context.json"
    external_profile.write_bytes((fixture / "profile.json").read_bytes())
    external_context.write_bytes((fixture / "context.json").read_bytes())
    (fixture / "profile.json").write_bytes(b"not-json SECRET-DEFAULT")
    (fixture / "context.json").write_bytes(b"not-json SECRET-DEFAULT")

    report = evaluate_bundle(
        scenario, fixture, profile=external_profile, context=external_context
    )
    assert report["evaluation"]["final_status"] == "Detected"
    assert report["input_fingerprints"]["profile"] == sha256(external_profile.read_bytes()).hexdigest()

    external_profile.write_bytes(b"not-json SECRET-SELECTED")
    with pytest.raises(IntakeError) as caught:
        evaluate_bundle(scenario, fixture, profile=external_profile, context=external_context)
    assert caught.value.code == "invalid_json"
    assert "SECRET" not in str(caught.value)


@pytest.mark.parametrize("damage", ["hash", "late-parser"])
def test_input_failure_is_atomic_json_error_with_empty_stdout(tmp_path, damage):
    scenario, fixture, _, _ = write_detected_case(tmp_path)
    inputs = json.loads((fixture / "inputs.json").read_bytes())
    if damage == "hash":
        inputs["files"][0]["sha256"] = "0" * 64
    else:
        (fixture / "event-1.json").write_bytes(b'{"secret":"DO-NOT-ECHO"}')
        inputs["files"][1]["sha256"] = sha256((fixture / "event-1.json").read_bytes()).hexdigest()
    (fixture / "inputs.json").write_bytes(encode_json(inputs))

    result = run_cli(
        "validate", "--scenario", str(scenario), "--fixture", str(fixture), "--format=json"
    )

    diagnostic = json.loads(result.stderr)
    assert result.returncode == 2
    assert result.stdout == ""
    assert diagnostic["kind"] == "error"
    assert diagnostic["error"]["code"] == ("hash_mismatch" if damage == "hash" else "parser_error")
    assert "DO-NOT-ECHO" not in result.stderr
    assert "Traceback" not in result.stderr


def test_text_output_escapes_controls_and_separates_unknown_ids(tmp_path):
    malicious_scenario = SCENARIO.replace(
        b"name: Synthetic CLI validation", b'name: "Synthetic\\n\\u001b[31mCLI"'
    )
    scenario, fixture, _, context = write_detected_case(
        tmp_path, records=1, detection_id="99999", scenario_bytes=malicious_scenario
    )
    context["run_id"] = "run\n\x1b[32mINJECT"
    (fixture / "context.json").write_bytes(encode_json(context))

    result = run_cli("validate", "--scenario", str(scenario), "--fixture", str(fixture))

    assert result.returncode == 3
    assert result.stderr == ""
    assert "\x1b" not in result.stdout
    assert "run\\u000a\\u001b[32mINJECT" in result.stdout
    assert "Evidence IDs:" in result.stdout
    assert "Unevaluable IDs:" in result.stdout
    assert "Final status: Inconclusive" in result.stdout


def test_report_budget_counts_final_newline_and_text_escape_expansion(tmp_path, monkeypatch):
    from aegis_verify.cli import reporting
    from aegis_verify.cli.service import evaluate_bundle

    scenario, fixture, _, _ = write_detected_case(tmp_path)
    report = evaluate_bundle(scenario, fixture)
    report["scenario"]["name"] = "line\n\x1b"
    rendered = reporting.render_report(report, "text")
    assert rendered.endswith("\n")
    assert "line\\u000a\\u001b" in rendered
    exact = len(rendered.encode("utf-8"))

    monkeypatch.setattr(reporting, "MAX_OUTPUT_BYTES", exact)
    assert reporting.render_report(report, "text") == rendered
    monkeypatch.setattr(reporting, "MAX_OUTPUT_BYTES", exact - 1)
    with pytest.raises(IntakeError) as caught:
        reporting.render_report(report, "text")
    assert caught.value.code == "resource_limit"
    assert caught.value.stage == "output"

    monkeypatch.setattr(reporting, "MAX_OUTPUT_BYTES", 32 * 1024 * 1024)
    json_rendered = reporting.render_report(report, "json")
    json_exact = len(json_rendered.encode("utf-8"))
    monkeypatch.setattr(reporting, "MAX_OUTPUT_BYTES", json_exact)
    assert reporting.render_report(report, "json") == json_rendered
    monkeypatch.setattr(reporting, "MAX_OUTPUT_BYTES", json_exact - 1)
    with pytest.raises(IntakeError):
        reporting.render_report(report, "json")


def test_internal_and_output_failures_return_four_without_source_details(tmp_path, monkeypatch, capsys):
    import aegis_verify.cli as cli

    scenario, fixture, _, _ = write_detected_case(tmp_path)
    arguments = ["validate", "--scenario", str(scenario), "--fixture", str(fixture), "--format=json"]

    def fail_service(*_args, **_kwargs):
        raise RuntimeError("SECRET-INTERNAL")

    with monkeypatch.context() as patch:
        patch.setattr(cli, "evaluate_bundle", fail_service)
        internal = cli.main(arguments)
    assert internal == 4
    internal_output = capsys.readouterr()
    assert internal_output.out == ""
    assert json.loads(internal_output.err)["error"]["code"] == "internal_error"
    assert "SECRET" not in internal_output.err

    class BrokenStdout:
        def write(self, _text):
            raise BrokenPipeError("SECRET-PIPE")

        def flush(self):
            raise BrokenPipeError("SECRET-PIPE")

    with monkeypatch.context() as patch:
        patch.setattr(sys, "stdout", BrokenStdout())
        assert cli.main(arguments) == 4
    output_failure = capsys.readouterr()
    assert json.loads(output_failure.err)["error"]["code"] == "output_error"
    assert "SECRET" not in output_failure.err


def test_at_file_expansion_and_abbreviated_flags_are_disabled(tmp_path):
    arguments_file = tmp_path / "SECRET-ARGS.txt"
    arguments_file.write_text("validate --scenario anything --fixture anything", encoding="utf-8")

    for arguments in ((f"@{arguments_file}",), ("validate", "--scen", "SECRET", "--fixture", ".")):
        result = run_cli(*arguments)
        assert result.returncode == 2
        assert result.stdout == ""
        assert "SECRET" not in result.stderr


def test_report_is_independent_of_bundle_location_with_spaces_and_unicode(tmp_path):
    from aegis_verify.cli.service import evaluate_bundle

    scenario, fixture, _, _ = write_detected_case(tmp_path / "first")
    moved_root = tmp_path / "moved space \u0111"
    moved_fixture = moved_root / "fixture"
    moved_root.mkdir()
    shutil.copytree(fixture, moved_fixture)
    moved_scenario = moved_root / "scenario.yaml"
    shutil.copy2(scenario, moved_scenario)

    assert evaluate_bundle(scenario, fixture) == evaluate_bundle(moved_scenario, moved_fixture)


def test_console_and_module_entry_points_are_equivalent(tmp_path):
    scenario, fixture, _, _ = write_detected_case(tmp_path)
    command = [
        "validate",
        "--scenario",
        str(scenario),
        "--fixture",
        str(fixture),
        "--format=json",
    ]
    console = Path(sys.executable).with_name("aegis.exe")
    assert console.is_file(), "editable install must register the aegis console script"

    module_result = run_cli(*command)
    console_result = subprocess.run(
        [str(console), *command], capture_output=True, text=True, check=False
    )

    assert console_result.returncode == module_result.returncode == 0
    assert console_result.stdout == module_result.stdout
    assert console_result.stderr == module_result.stderr == ""


def test_main_help_returns_zero_to_library_caller(capsys):
    from aegis_verify.cli import main

    assert main(["--help"]) == 0
    captured = capsys.readouterr()
    assert "validate" in captured.out
    assert captured.err == ""


def test_short_stdout_write_overrides_success_exit(tmp_path, monkeypatch, capsys):
    import aegis_verify.cli as cli

    scenario, fixture, _, _ = write_detected_case(tmp_path)
    arguments = ["validate", "--scenario", str(scenario), "--fixture", str(fixture), "--format=json"]

    class ShortStdout:
        def write(self, text):
            return len(text) - 1

        def flush(self):
            return None

    with monkeypatch.context() as patch:
        patch.setattr(sys, "stdout", ShortStdout())
        result = cli.main(arguments)
    diagnostic = capsys.readouterr()
    assert result == 4
    assert json.loads(diagnostic.err)["error"]["code"] == "output_error"


def test_closed_stdout_pipe_exits_four_without_shutdown_exception(tmp_path):
    scenario, fixture, _, _ = write_detected_case(tmp_path)
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aegis_verify",
            "validate",
            "--scenario",
            str(scenario),
            "--fixture",
            str(fixture),
            "--format=json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    process.stdout.close()
    stderr = process.stderr.read().decode("utf-8", errors="replace")
    returncode = process.wait(timeout=10)

    assert returncode == 4
    assert json.loads(stderr)["error"]["code"] == "output_error"
    assert "Exception ignored" not in stderr
    assert "Traceback" not in stderr


def test_closed_help_stdout_pipe_is_output_error_without_shutdown_exception():
    process = subprocess.Popen(
        [sys.executable, "-m", "aegis_verify", "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    process.stdout.close()
    stderr = process.stderr.read().decode("utf-8", errors="replace")
    returncode = process.wait(timeout=10)

    assert returncode == 4
    assert "output_error" in stderr
    assert "Exception ignored" not in stderr
    assert "Traceback" not in stderr


def test_failed_error_stream_returns_four_and_is_shutdown_safe():
    process = subprocess.Popen(
        [sys.executable, "-m", "aegis_verify", "validate"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    process.stderr.close()
    stdout = process.stdout.read().decode("utf-8", errors="replace")
    returncode = process.wait(timeout=10)

    assert returncode == 4
    assert stdout == ""


def test_library_help_and_diagnostic_stream_failures_return_four(monkeypatch, capsys):
    import aegis_verify.cli as cli

    class BrokenStream:
        def write(self, _text):
            raise OSError("SECRET-STREAM")

        def flush(self):
            raise OSError("SECRET-STREAM")

    with monkeypatch.context() as patch:
        patch.setattr(sys, "stdout", BrokenStream())
        assert cli.main(["--help"]) == 4
    help_error = capsys.readouterr()
    assert "output_error" in help_error.err
    assert "SECRET" not in help_error.err

    with monkeypatch.context() as patch:
        patch.setattr(sys, "stderr", BrokenStream())
        assert cli.main(["validate"]) == 4
    diagnostic_error = capsys.readouterr()
    assert diagnostic_error.out == diagnostic_error.err == ""
