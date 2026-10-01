"""Regenerate the dashboard overview fixtures through the real overview backend.

Inputs are already reviewed: the scenario manifests in ``scenarios/``, the sanitized
lab bundles in ``tests/fixtures/cli/`` (evaluated here by the real engine), and the
synthetic SCN-999 dashboard reports plus one truncated file. File times and the
status clock are fixed so the output is reproducible. Nothing is hand-written.

Usage: python scripts/prepare_dashboard_overview_fixtures.py [--output tests/fixtures/dashboard/overview]
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from aegis_verify.cli.service import evaluate_bundle  # noqa: E402
from aegis_verify.compare import compare_reports  # noqa: E402
from aegis_verify.dashboard import ReportStore  # noqa: E402
from aegis_verify.dashboard.overview import (  # noqa: E402
    ScenarioRegistry, build_scenario_detail, build_scenario_index, build_system_status,
)

NOW = "2026-10-01T06:00:00Z"
MTIME = 1790000000
SYNTHETIC = ("after-detected.json", "before-false-negative.json", "comparison-regression-passed.json",
             "malformed-truncated.json")


def _evaluate(scenario, bundle, profile):
    return evaluate_bundle(str(ROOT / "scenarios" / scenario), str(ROOT / "tests/fixtures/cli" / bundle),
                           profile=str(ROOT / "scenarios" / profile))


def _reports(directory: Path) -> None:
    control = _evaluate("SCN-002-attempted-exfiltration.yaml", "scn002-lab-sanitized/control",
                        "profiles/scn-002/profile.json")
    block = _evaluate("SCN-002-attempted-exfiltration.yaml", "scn002-lab-sanitized/block",
                      "profiles/scn-002/profile.json")
    reports = {"scn002-control.json": control, "scn002-block.json": block,
               "scn002-compare.json": compare_reports(before=control, after=block),
               "scn003.json": _evaluate("SCN-003-internal-deception.yaml", "scn003-lab-sanitized",
                                        "profiles/scn-003/profile.json")}
    for name, report in reports.items():
        (directory / name).write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    for name in SYNTHETIC:
        shutil.copyfile(ROOT / "tests/fixtures/dashboard" / name, directory / name)
    for offset, path in enumerate(sorted(directory.iterdir())):
        os.utime(path, (MTIME + offset, MTIME + offset))


def build_fixtures() -> dict:
    with tempfile.TemporaryDirectory() as temp:
        reports = Path(temp) / "reports"
        reports.mkdir()
        _reports(reports)
        store, registry = ReportStore(reports), ScenarioRegistry(ROOT / "scenarios")
        return {
            "scenario-index.json": build_scenario_index(registry, store),
            "scenario-detail-SCN-002.json": build_scenario_detail(registry, store, "SCN-002"),
            "scenario-detail-SCN-001.json": build_scenario_detail(registry, store, "SCN-001"),
            "system-status.json": build_system_status(registry, store, None, now=NOW),
            "scenario-index-not-configured.json": build_scenario_index(None, store),
            "system-status-not-configured.json": build_system_status(None, store, None, now=NOW),
        }


def encode(payload) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", default=str(ROOT / "tests/fixtures/dashboard/overview"))
    output = Path(parser.parse_args(argv).output)
    output.mkdir(parents=True, exist_ok=True)
    for name, payload in build_fixtures().items():
        (output / name).write_text(encode(payload), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
