"""SCN-002 end to end through the real CLI on a synthetic four-source bundle.

A green run proves parsers, public profile and engine agree; it is not
evidence that any lab prevented anything.
"""

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "tests" / "fixtures" / "cli" / "scn002-synthetic-prevented"
SCENARIO = ROOT / "scenarios" / "SCN-002-attempted-exfiltration.yaml"
PROFILE = ROOT / "scenarios" / "profiles" / "scn-002" / "profile.json"


def validate(bundle):
    result = subprocess.run(
        [sys.executable, "-m", "aegis_verify", "validate", "--scenario", str(SCENARIO),
         "--fixture", str(bundle), "--profile", str(PROFILE), "--format=json"],
        capture_output=True, text=True, check=False, cwd=str(ROOT))
    report = json.loads(result.stdout) if result.stdout.startswith("{") else None
    return result, (report if report and report.get("kind") != "error" else None)


def outcomes(report):
    return {a["assertion_id"]: (a["outcome"], a["reason_code"]) for a in report["evaluation"]["assertions"]}


def rewrite(bundle, name, transform):
    path = bundle / name
    data = transform(path.read_bytes())
    path.write_bytes(data)
    inputs = json.loads((bundle / "inputs.json").read_bytes())
    for entry in inputs["files"]:
        if entry["path"] == name:
            entry["sha256"] = sha256(data).hexdigest()
    (bundle / "inputs.json").write_bytes(json.dumps(inputs, indent=2).encode("utf-8") + b"\n")


@pytest.fixture
def portable(tmp_path):
    return Path(shutil.copytree(BUNDLE, tmp_path / "scn002"))


def test_committed_bundle_hashes_match_the_bytes():
    inputs = json.loads((BUNDLE / "inputs.json").read_bytes())
    for entry in inputs["files"]:
        assert sha256((BUNDLE / entry["path"]).read_bytes()).hexdigest() == entry["sha256"], entry["path"]


def test_four_synthetic_sources_give_prevented_anchored_on_sysmon():
    result, report = validate(BUNDLE)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert report["evaluation"]["final_status"] == "Prevented"
    assert report["counts"] == {"parsed": 4, "referenced": 4, "skipped": 0}
    got = outcomes(report)
    assert all(outcome == "satisfied" for outcome, _ in got.values())
    by_ref = {e["raw_event_ref"]: e["event_id"] for e in report["evaluation"]["evidence_index"]}
    anchor = by_ref["synthetic-sysmon3#record=1"]
    for assertion in report["evaluation"]["assertions"]:
        if assertion["role"] != "telemetry":
            assert [pair["anchor_event_id"] for pair in assertion["witness_pairs"]] == [anchor]
    timeline = report["timeline"]["events"]
    assert {e["source_type"] for e in timeline} == {"wazuh", "suricata", "pfsense"}
    assert {e["source_label"] for e in timeline} == {
        "Synthetic sender (Sysmon 3)", "Synthetic Suricata LAN", "Synthetic pfSense LAN", "Synthetic Wazuh manager"}


def test_control_round_with_a_pass_line_is_inconclusive_not_prevented(portable):
    rewrite(portable, "filterlog-block.log", lambda raw: raw.replace(b",block,", b",pass,"))
    result, report = validate(portable)
    assert report is not None, result.stderr
    assert result.returncode == 3  # report emitted, status is not a pass
    got = outcomes(report)
    assert got["SCN-002-A03"] == ("inconclusive", "prevention_not_demonstrated")
    assert got["SCN-002-A01"][0] == got["SCN-002-A02"][0] == got["SCN-002-A04"][0] == "satisfied"
    assert report["evaluation"]["final_status"] == "Inconclusive"


def test_a_block_for_another_datagram_is_not_a_witness(portable):
    rewrite(portable, "filterlog-block.log", lambda raw: raw.replace(b",51000,", b",51001,"))
    result, report = validate(portable)
    assert report is not None and result.returncode == 3, result.stderr
    assert outcomes(report)["SCN-002-A03"] == ("inconclusive", "prevention_not_demonstrated")
    assert report["evaluation"]["final_status"] == "Inconclusive"


def test_changed_bytes_without_a_new_hash_stop_the_bundle(portable):
    path = portable / "eve-alert.jsonl"
    path.write_bytes(path.read_bytes().replace(b"1000010", b"1000011"))
    result, report = validate(portable)
    assert result.returncode != 0 and report is None
    assert "sha256" in result.stderr or "hash" in result.stderr.lower()
