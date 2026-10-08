"""Sanitized derivatives of the real SCN-004 rounds on Lab C replay the verdicts.

The bytes are derived from private lab evidence with documented substitutions
(see the fixture README). A green run shows the Lab C parsers accept the real
source shapes and the engine reaches the same verdicts as on the originals;
it does not by itself prove anything about the lab.
"""

from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "cli" / "scn004-lab-c-sanitized"
SCENARIO = ROOT / "scenarios" / "SCN-004-attempted-exfiltration-lab-c.yaml"
PROFILE = ROOT / "scenarios" / "profiles" / "scn-004" / "profile.json"
LAB_IDENTIFIERS = re.compile(
    rb"192\.168\.|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.|WIN10|Win10|Admin|\.internal|wazuh\.manager")
LABEL = "f18da9d8-ba44-4a26-8909-effe55135cb6"


def validate(bundle):
    result = subprocess.run(
        [sys.executable, "-m", "aegis_verify", "validate", "--scenario", str(SCENARIO),
         "--fixture", str(bundle), "--profile", str(PROFILE), "--format=json"],
        capture_output=True, text=True, check=False, cwd=str(ROOT))
    report = json.loads(result.stdout) if result.stdout.startswith("{") else None
    return result, report


def outcomes(report):
    return {a["assertion_id"]: (a["outcome"], a["reason_code"]) for a in report["evaluation"]["assertions"]}


def parse(text):
    head, frac = text.rstrip("Z").split(".") if "." in text else (text.rstrip("Z"), "0")
    return datetime.fromisoformat(head + "." + frac[:6].ljust(6, "0"))


@pytest.mark.parametrize("round_name", ["block", "sensor-down"])
def test_inputs_hashes_match_bytes_and_no_lab_identifier_survives(round_name):
    bundle = FIXTURE / round_name
    inputs = json.loads((bundle / "inputs.json").read_bytes())
    for entry in inputs["files"]:
        assert sha256((bundle / entry["path"]).read_bytes()).hexdigest() == entry["sha256"], entry["path"]
    for path in bundle.iterdir():
        assert LAB_IDENTIFIERS.search(path.read_bytes()) is None, path.name
    parsers = sorted(entry["parser"] for entry in inputs["files"])
    expected = ["opnsense-filterlog-bsd-v1", "snort3-alert-json-v1", "wazuh-sysmon3-archive-v1"]
    assert parsers == (expected if round_name == "block" else [p for p in expected if not p.startswith("snort")])


def test_block_round_derivative_is_prevented_with_witnesses_on_the_sysmon_record():
    result, report = validate(FIXTURE / "block")
    assert result.returncode == 0, result.stderr
    assert report["evaluation"]["final_status"] == "Prevented"
    assert report["counts"] == {"parsed": 3, "referenced": 3, "skipped": 0}
    assert all(outcome == "satisfied" for outcome, _ in outcomes(report).values())
    by_ref = {e["raw_event_ref"]: e["event_id"] for e in report["evaluation"]["evidence_index"]}
    anchor = next(event_id for ref, event_id in by_ref.items() if ref.startswith("labc-sysmon3"))
    for assertion in report["evaluation"]["assertions"]:
        if assertion["role"] != "telemetry":
            assert [p["anchor_event_id"] for p in assertion["witness_pairs"]] == [anchor]
    events = {e["source_type"]: e for e in report["timeline"]["events"]}
    assert events["opnsense"]["event_action"] == "blocked" and events["opnsense"]["rule_id"] == LABEL
    assert events["snort"]["signature_id"] == "1000010" and events["snort"]["event_provider"] == "snort"
    assert events["wazuh"]["event_provider"] == "Microsoft-Windows-Sysmon"


def test_round_without_the_ids_alert_is_inconclusive_not_prevented():
    result, report = validate(FIXTURE / "sensor-down")
    assert report is not None and result.returncode == 3, result.stderr
    got = outcomes(report)
    assert got["SCN-004-A02"] == ("inconclusive", "collection_not_confirmed")
    assert got["SCN-004-A01"][0] == got["SCN-004-A03"][0] == "satisfied"
    assert report["evaluation"]["final_status"] == "Inconclusive"


def test_real_clock_skew_stays_inside_the_two_second_window():
    _, report = validate(FIXTURE / "block")
    times = {e["source_type"]: parse(e["timestamp"]) for e in report["timeline"]["events"]}
    for source in ("snort", "opnsense"):
        assert abs((times[source] - times["wazuh"]).total_seconds()) <= 2.0, source
    # OPNsense writes whole seconds; Snort keeps microseconds.
    assert times["opnsense"].microsecond == 0 and times["snort"].microsecond != 0
