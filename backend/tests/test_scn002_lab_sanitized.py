"""Sanitized derivatives of the real SCN-002 lab rounds replay the verdicts.

The bytes are derived from private lab evidence with documented substitutions
(see the fixture README). A green run shows the parsers accept the real
source shapes and the engine reaches the same verdicts as on the originals;
it does not by itself prove anything about the lab.
"""

from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "cli" / "scn002-lab-sanitized"
SCENARIO = ROOT / "scenarios" / "SCN-002-attempted-exfiltration.yaml"
PROFILE = ROOT / "scenarios" / "profiles" / "scn-002" / "profile.json"
LAB_IDENTIFIERS = re.compile(rb"192\.168\.|10\.0\.[0-9]+\.|172\.(1[6-9]|2[0-9]|3[01])\.|soc\.lab|WIN-USER")


def validate(bundle):
    result = subprocess.run(
        [sys.executable, "-m", "aegis_verify", "validate", "--scenario", str(SCENARIO),
         "--fixture", str(bundle), "--profile", str(PROFILE), "--format=json"],
        capture_output=True, text=True, check=False, cwd=str(ROOT))
    report = json.loads(result.stdout) if result.stdout.startswith("{") else None
    return result, report


def outcomes(report):
    return {a["assertion_id"]: (a["outcome"], a["reason_code"]) for a in report["evaluation"]["assertions"]}


@pytest.mark.parametrize("round_name", ["block", "control"])
def test_inputs_hashes_match_bytes_and_no_lab_identifier_survives(round_name):
    bundle = FIXTURE / round_name
    inputs = json.loads((bundle / "inputs.json").read_bytes())
    for entry in inputs["files"]:
        assert sha256((bundle / entry["path"]).read_bytes()).hexdigest() == entry["sha256"], entry["path"]
    for path in bundle.iterdir():
        assert LAB_IDENTIFIERS.search(path.read_bytes()) is None, path.name
        assert b'"packet"' not in path.read_bytes(), path.name


def test_block_round_derivative_is_prevented_with_witnesses_on_the_sysmon_record():
    result, report = validate(FIXTURE / "block")
    assert result.returncode == 0, result.stderr
    assert report["evaluation"]["final_status"] == "Prevented"
    assert report["counts"] == {"parsed": 4, "referenced": 4, "skipped": 0}
    assert all(outcome == "satisfied" for outcome, _ in outcomes(report).values())
    by_ref = {e["raw_event_ref"]: e["event_id"] for e in report["evaluation"]["evidence_index"]}
    anchor = next(event_id for ref, event_id in by_ref.items() if ref.startswith("lab-sysmon3"))
    for assertion in report["evaluation"]["assertions"]:
        if assertion["role"] != "telemetry":
            assert [p["anchor_event_id"] for p in assertion["witness_pairs"]] == [anchor]
    blocked = [e for e in report["timeline"]["events"] if e["source_type"] == "pfsense"]
    assert len(blocked) == 1 and blocked[0]["event_action"] == "blocked" and blocked[0]["rule_id"] == "1790087102"


def test_control_round_derivative_is_inconclusive_not_prevented():
    result, report = validate(FIXTURE / "control")
    assert report is not None and result.returncode == 3, result.stderr
    got = outcomes(report)
    assert got["SCN-002-A03"] == ("inconclusive", "prevention_not_demonstrated")
    assert got["SCN-002-A01"][0] == got["SCN-002-A02"][0] == got["SCN-002-A04"][0] == "satisfied"
    assert report["evaluation"]["final_status"] == "Inconclusive"


def test_real_clock_skew_stays_inside_the_two_second_window():
    _, report = validate(FIXTURE / "block")
    times = {e["source_ref"]: e["timestamp"] for e in report["timeline"]["events"]}
    from datetime import datetime
    def parse(text):
        head, frac = text.rstrip("Z").split(".") if "." in text else (text.rstrip("Z"), "0")
        return datetime.fromisoformat(head + "." + frac[:6].ljust(6, "0"))
    anchor = parse(next(t for r, t in times.items() if r.startswith("lab-sysmon3")))
    for ref, stamp in times.items():
        assert abs((parse(stamp) - anchor).total_seconds()) <= 2.0, ref
