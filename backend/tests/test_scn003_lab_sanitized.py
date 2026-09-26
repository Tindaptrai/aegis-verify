"""Sanitized derivative of the real SCN-003 control round replays the verdict.

The bytes are derived from private lab evidence with documented substitutions
(see the fixture README). A green run shows the parsers accept the real
source shapes and the engine reaches the same verdict as on the original; it
does not by itself prove anything about the lab.
"""

from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "cli" / "scn003-lab-sanitized"
SCENARIO = ROOT / "scenarios" / "SCN-003-internal-deception.yaml"
PROFILE = ROOT / "scenarios" / "profiles" / "scn-003" / "profile.json"
LAB_IDENTIFIERS = re.compile(rb"10\.0\.1\.|192\.168\.20\.|corwrie")
# The real per-run random login password is not embedded here even as a
# comparison literal; the fixture-generation step already verified and
# scrubbed it before these bytes were committed.
PASSWORD_FIELD = re.compile(rb'"password":"(?!synthetic-marker-password")[^"]+"')


def validate():
    result = subprocess.run(
        [sys.executable, "-m", "aegis_verify", "validate", "--scenario", str(SCENARIO),
         "--fixture", str(FIXTURE), "--profile", str(PROFILE), "--format=json"],
        capture_output=True, text=True, check=False, cwd=str(ROOT))
    report = json.loads(result.stdout) if result.stdout.startswith("{") else None
    return result, report


def outcomes(report):
    return {a["assertion_id"]: (a["outcome"], a["reason_code"]) for a in report["evaluation"]["assertions"]}


def test_inputs_hashes_match_bytes_and_no_lab_identifier_or_real_password_survives():
    inputs = json.loads((FIXTURE / "inputs.json").read_bytes())
    for entry in inputs["files"]:
        raw = (FIXTURE / entry["path"]).read_bytes()
        assert sha256(raw).hexdigest() == entry["sha256"], entry["path"]
        assert LAB_IDENTIFIERS.search(raw) is None, entry["path"]
        # Any password-shaped value present must be exactly the fixed marker.
        assert PASSWORD_FIELD.search(raw) is None, entry["path"]
        assert b'"packet"' not in raw, entry["path"]


def test_lab_derived_bundle_is_detected_with_witnesses_on_both_roots():
    result, report = validate()
    assert result.returncode == 0, result.stderr
    assert report["evaluation"]["final_status"] == "Detected"
    assert report["counts"] == {"parsed": 5, "referenced": 4, "skipped": 0}
    assert all(outcome == "satisfied" for outcome, _ in outcomes(report).values())
    by_id = {e["event_id"]: e for e in report["timeline"]["events"]}
    anchors = {a["assertion_id"]: {p["anchor_event_id"] for p in a["witness_pairs"]}
               for a in report["evaluation"]["assertions"]}
    assert {by_id[i]["source_type"] for i in anchors["SCN-003-A01"]} == {"pfsense"}
    assert {by_id[i]["source_type"] for i in anchors["SCN-003-A04"]} == {"cowrie"}
    assert {e["source_type"] for e in report["timeline"]["events"]} == {"pfsense", "suricata", "cowrie", "wazuh"}
    assert PASSWORD_FIELD.search(result.stdout.encode()) is None


def test_wazuh_alert_carries_the_marker_password_but_the_parser_never_reads_it():
    from aegis_verify.connectors import wazuh
    raw = (FIXTURE / "wazuh-alert.json").read_bytes()
    assert b"synthetic-marker-password" in raw, "the fixture keeps a stand-in credential, as a real alert would"
    event = wazuh.parse_wazuh_cowrie_alert_record(
        raw, source_ref="fixture", environment_id="lab-sanitized",
        ingested_at="2026-09-26T15:00:00Z", collection_mode="direct", sensor_id="lab-cowrie").event
    assert b"synthetic-marker-password" not in event.model_dump_json().encode()
