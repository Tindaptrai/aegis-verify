"""Prepare an offline public replay kit using the unchanged validation engine."""

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import unicodedata

from ..cli.service import evaluate_bundle
from ..compare import compare_runs
from ..intake import IntakeError, local_path


_FIXTURES = (
    "scn002-lab-sanitized", "scn003-lab-sanitized",
    "scn004-lab-c-sanitized", "scn005-elastic-synthetic",
    "scn006-elastic-synthetic",
)
_CASES = (
    ("scn002-control", "002", "scn002-lab-sanitized/control", "sanitized_derivative"),
    ("scn002-block", "002", "scn002-lab-sanitized/block", "sanitized_derivative"),
    ("scn003-detected", "003", "scn003-lab-sanitized", "sanitized_derivative"),
    ("scn004-block-siem", "004", "scn004-lab-c-sanitized/block-siem", "sanitized_derivative"),
    ("scn004-block", "004", "scn004-lab-c-sanitized/block", "sanitized_derivative"),
    ("scn004-sensor-down", "004", "scn004-lab-c-sanitized/sensor-down", "sanitized_derivative"),
    ("scn005-synthetic", "005", "scn005-elastic-synthetic", "synthetic"),
    ("scn006-synthetic", "006", "scn006-elastic-synthetic", "synthetic"),
)
_SYNTHETIC_REPORTS = ("before-false-negative.json", "after-detected.json")


def _write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8", newline="\n")


def _copy_tree(source, destination, *, output_root, files):
    """Copy trusted package bytes; reject links/reparse points like normal intake."""
    source = local_path(source, directory=True, stage="inputs")
    destination.mkdir()
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_dir():
            local_path(path, directory=True, stage="inputs")
            target.mkdir()
        else:
            selected = local_path(path, stage="inputs")
            shutil.copyfile(selected, target)
            files.append({"path": target.relative_to(output_root).as_posix(),
                          "sha256": sha256(target.read_bytes()).hexdigest()})


def _new_target(out):
    try:
        requested = Path(os.fspath(out))
    except (TypeError, ValueError):
        raise IntakeError("invalid_path", stage="output") from None
    name = requested.name
    if (not name or name in {".", ".."} or name.endswith((".", " "))
            or any(char in "*?[]:" or unicodedata.category(char) == "Cc" for char in name)):
        raise IntakeError("invalid_path", stage="output")
    parent = local_path(requested.parent, directory=True, stage="output")
    return parent / name


def prepare_demo(out):
    """Create one new kit, replay public evidence, and never run scenario actions.

    Existing output paths are rejected. On failure only the directory created by
    this invocation is removed; packaged inputs and unrelated user files stay put.
    """
    from ..resources import resource_root

    source = local_path(resource_root(), directory=True, stage="inputs")
    target = _new_target(out)
    if target.is_relative_to(source):
        raise IntakeError("invalid_path", stage="output")
    try:
        target.mkdir()
    except OSError:
        raise IntakeError("output_error", stage="output") from None
    try:
        local_path(target, directory=True, stage="output")
        files = []
        for name in ("scenarios", "static", "licenses"):
            _copy_tree(source / name, target / name, output_root=target, files=files)
        (target / "fixtures").mkdir()
        for name in _FIXTURES:
            _copy_tree(source / "fixtures" / name, target / "fixtures" / name,
                       output_root=target, files=files)
        reports = target / "reports"
        reports.mkdir()
        for name in _SYNTHETIC_REPORTS:
            original = local_path(source / "dashboard-reports" / name, stage="inputs")
            copied = reports / ("synthetic-" + name)
            shutil.copyfile(original, copied)
            files.append({"path": copied.relative_to(target).as_posix(),
                          "sha256": sha256(copied.read_bytes()).hexdigest()})

        evaluations = []
        for name, number, fixture, data_kind in _CASES:
            manifests = sorted((target / "scenarios").glob("SCN-" + number + "-*.yaml"))
            if len(manifests) != 1:
                raise IntakeError("invalid_scenario", stage="scenario")
            report = evaluate_bundle(manifests[0], target / "fixtures" / fixture,
                                     profile=target / "scenarios/profiles" / ("scn-" + number) / "profile.json")
            report_path = reports / (name + ".json")
            _write_json(report_path, report)
            evaluations.append({
                "case": name, "scenario_id": report["scenario"]["id"],
                "data_kind": data_kind, "final_status": report["evaluation"]["final_status"],
                "report": report_path.relative_to(target).as_posix(),
                "evidence_ids": [entry["event_id"] for entry in report["evaluation"]["evidence_index"]],
            })
        comparisons = []
        for name, before, after in (
            ("scn002-control-to-block", "scn002-control.json", "scn002-block.json"),
            ("synthetic-gap-to-fix", "synthetic-before-false-negative.json", "synthetic-after-detected.json"),
        ):
            comparison = compare_runs(before=reports / before, after=reports / after)
            path = reports / (name + ".json")
            _write_json(path, comparison)
            comparisons.append({"case": name, "status": comparison["comparison"]["status"],
                                "report": path.relative_to(target).as_posix()})
        provenance = {
            "kind": "public_demo_provenance", "version": "0.1.0",
            "sanitized_derivatives": [name for name in _FIXTURES if "sanitized" in name],
            "synthetic_data": ["scn005-elastic-synthetic", "scn006-elastic-synthetic",
                               "synthetic-before-false-negative.json", "synthetic-after-detected.json"],
            "files": sorted(files, key=lambda item: item["path"]),
            "limitations": [
                "Offline replay checks software behavior; it is not a new live lab run.",
                "Synthetic data and its synthetic collection attestation prove no lab detection coverage.",
                "SCN-001 real evidence is private and is not included.",
                "No payload, scenario action, rule change or live evidence collection is executed.",
            ],
        }
        _write_json(target / "provenance.json", provenance)
        summary = {"kind": "demo_summary", "version": "0.1.0", "output": str(target),
                   "network_access": False, "scenario_execution": False,
                   "evaluations": evaluations, "comparisons": comparisons}
        _write_json(target / "demo-summary.json", summary)
        (target / "README.md").write_text(
            "# AEGIS Verify offline public demo\n\n"
            "This kit replays eight public cases through the actual parsers and validation engine. "
            "SCN-002/003/004 inputs are sanitized lab derivatives; SCN-005/006 and the "
            "Gap/Fix example are synthetic. No network access, payload execution, rule changes "
            "or live collection occurs. This is not a new lab run or production certification.\n\n"
            "Open the dashboard from this directory:\n\n"
            "```text\naegis dashboard --reports reports --static static --scenarios scenarios\n```\n\n"
            "For a frozen Windows build, use aegis.exe in place of aegis. Open the loopback URL "
            "printed by the server. Stop with Ctrl+C.\n\n"
            "SCN-001 is in the catalog but its private real evidence is omitted; it may show not run. "
            "SCN-004 historical block and sensor-down cases remain Inconclusive under the current "
            "four-assertion manifest. SCN-002 control-to-block comparison remains Inconclusive; "
            "Regression Passed belongs to the separate synthetic False negative-to-Detected example.\n\n"
            "The supplied synthetic Gap/Fix reports use SCN-999, intentionally absent from the six-manifest "
            "catalog. The registry therefore reports Degraded with unregistered reports; this known "
            "demo state remains visible. Open those reports in the Reports view. No real scenario "
            "manifest or ground truth was changed to hide that state.\n\n"
            "Read demo-summary.json for actual verdicts, reports/ for complete evidence links, "
            "and provenance.json plus the fixture README files for byte hashes and lineage. "
            "Keep licenses/frontend.txt with this kit when redistributing its dashboard. "
            "Original resource bytes and scenario ground truth were copied without modification.\n",
            encoding="utf-8", newline="\n")
        return summary
    except BaseException:
        # Validate the exact absolute directory created above before recursive cleanup.
        checked = local_path(target, directory=True, stage="output")
        if checked != target or checked.parent != target.parent:
            raise IntakeError("invalid_path", stage="output") from None
        shutil.rmtree(checked)
        raise
