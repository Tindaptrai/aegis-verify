"""Regenerate the synthetic dashboard fixtures through the real CLI service and comparison.

Everything here is artificial: scenario SCN-999, hosts, rule IDs, hashes and the
collection attestation. The "before" run omits the alert and carries a synthetic
``complete_for_scope`` declaration so the engine returns ``False negative``; the
"after" run has the alert and returns ``Detected``. The comparison is produced by
``compare_reports`` on those two reports. No lab data is involved.

Usage: python scripts/prepare_dashboard_fixtures.py [--output tests/fixtures/dashboard]
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from aegis_verify.cli.service import evaluate_bundle  # noqa: E402
from aegis_verify.compare import compare_reports  # noqa: E402
from aegis_verify.intake import load_bundle, parse_manifest  # noqa: E402
from aegis_verify.scenario_loader import parse_scenario_yaml  # noqa: E402
from aegis_verify.validation import (  # noqa: E402
    EvaluationContext, EvaluationProfile, event_set_fingerprint, profile_fingerprint,
    scenario_fingerprint, scope_fingerprint,
)

SCENARIO = b"""\
id: SCN-999
name: Synthetic dashboard example
version: 0.1.0
status: draft
description: Synthetic test-only scenario for the results dashboard; not lab evidence.
safety:
  destructive: false
  authorization_required: true
  notes: Synthetic test-only input; no scenario action is executed.
expected_sources: [wazuh]
expected_outcome: detected
assertions:
  - id: SCN-999-A01
    description: Synthetic activity exists.
    source: wazuh
  - id: SCN-999-A02
    description: Distinct correlated synthetic alert exists.
    source: wazuh
"""


def encode(value) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("utf-8")


def record(source_id: str, rule_id: str, second: int) -> bytes:
    return encode({"_source": {
        "id": source_id, "agent": {"id": "901", "name": "synthetic-host"},
        "manager": {"name": "synthetic-manager"}, "rule": {"id": rule_id, "level": 3},
        "data": {"win": {"system": {
            "providerName": "Microsoft-Windows-Security-Auditing", "channel": "Security",
            "eventID": "4688", "systemTime": f"2026-01-01T00:00:0{second}Z", "computer": "synthetic-host"},
            "eventdata": {"newProcessId": "0x1", "newProcessName": "synthetic.exe"}}}}})


def bundle(directory: Path, *, run_id: str, with_alert: bool, attested: bool):
    directory.mkdir(parents=True)
    scenario_path = directory / "scenario.yaml"
    scenario_path.write_bytes(SCENARIO)
    manifest = parse_scenario_yaml(SCENARIO.decode(), source_name="<dashboard-fixture>")
    profile = {
        "profile_schema_version": "0.1.0", "profile_id": "synthetic-dashboard-profile",
        "profile_version": "0.1.0", "scenario_id": "SCN-999", "scenario_version": "0.1.0",
        "scenario_fingerprint": scenario_fingerprint(manifest),
        "rules": [
            {"assertion_id": "SCN-999-A01", "role": "telemetry", "capability": "supported",
             "source_type": "wazuh", "scope": [{"field": "hostname", "op": "eq", "binding": "target"}],
             "match": [{"field": "rule_id", "op": "eq", "value": "900001"}]},
            {"assertion_id": "SCN-999-A02", "role": "detection", "capability": "supported",
             "source_type": "wazuh", "scope": [{"field": "hostname", "op": "eq", "binding": "target"}],
             "match": [{"field": "rule_id", "op": "eq", "value": "900002"}],
             "correlation": {"anchor_assertion_id": "SCN-999-A01",
                             "join_pairs": [{"target_field": "hostname", "anchor_field": "hostname"}],
                             "min_delta_ns": 0, "max_delta_ns": 2_000_000_000}},
        ],
    }
    context = {"run_id": run_id, "environment_id": "synthetic-lab", "start": "2026-01-01T00:00:00Z",
               "end": "2026-01-01T00:01:00Z", "bindings": [{"name": "target", "value": "synthetic-host"}],
               "declarations": []}
    files = [("activity.json", "synthetic-activity", record("synthetic-activity", "900001", 1))]
    if with_alert:
        files.append(("alert.json", "synthetic-alert", record("synthetic-alert", "900002", 2)))
    entries = []
    for name, ref, raw in files:
        (directory / name).write_bytes(raw)
        entries.append({"path": name, "source_ref": ref, "parser": "wazuh-win4688-v2",
                        "sha256": sha256(raw).hexdigest(),
                        "context": {"ingested_at": "2026-01-01T00:00:03Z", "collection_mode": "direct"}})
    inputs = {"bundle_schema_version": "0.1.0", "environment_id": "synthetic-lab", "files": entries}
    (directory / "inputs.json").write_bytes(encode(inputs))
    (directory / "profile.json").write_bytes(encode(profile))
    if attested:
        intake = load_bundle(directory, parse_manifest(inputs))
        context["declarations"] = [{
            "assertion_id": "SCN-999-A02", "status": "complete_for_scope",
            "confirmed_by": "synthetic-reviewer", "reference": "synthetic-only/collection-attestation",
            "coverage_start": context["start"], "coverage_end": context["end"],
            "no_sampling_or_truncation": True, "no_parse_errors_or_gaps": True, "clocks_adequate": True,
            "profile_fingerprint": profile_fingerprint(EvaluationProfile.model_validate(profile)),
            "scope_fingerprint": scope_fingerprint(EvaluationContext.model_validate(context)),
            "event_set_fingerprint": event_set_fingerprint(intake.events),
        }]
    (directory / "context.json").write_bytes(encode(context))
    return scenario_path, directory


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(ROOT / "tests" / "fixtures" / "dashboard"))
    args = parser.parse_args(argv)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        before = evaluate_bundle(*bundle(tmp / "before", run_id="synthetic-run-before-gap",
                                         with_alert=False, attested=True))
        after = evaluate_bundle(*bundle(tmp / "after", run_id="synthetic-run-after-fix",
                                        with_alert=True, attested=False))
    comparison = compare_reports(before=before, after=after)
    written = {}
    for name, report in (("before-false-negative.json", before), ("after-detected.json", after),
                         ("comparison-regression-passed.json", comparison)):
        raw = encode(report)
        (output / name).write_bytes(raw)
        written[name] = sha256(raw).hexdigest()
    malformed = b'{"cli_report_version": "0.1.0", "kind": "evaluation", "scenario": {"id": "SCN-999"'
    (output / "malformed-truncated.json").write_bytes(malformed)
    written["malformed-truncated.json"] = sha256(malformed).hexdigest()
    wrong_kind = encode({"cli_report_version": "0.1.0", "kind": "note", "text": "not a report"})
    (output / "unsupported-kind.json").write_bytes(wrong_kind)
    written["unsupported-kind.json"] = sha256(wrong_kind).hexdigest()
    print(json.dumps({"before": before["evaluation"]["final_status"], "after": after["evaluation"]["final_status"],
                      "comparison": comparison["comparison"]["status"], "sha256": written}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
