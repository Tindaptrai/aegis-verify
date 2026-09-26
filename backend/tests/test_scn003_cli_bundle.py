"""SCN-003 end to end through the real CLI on a synthetic four-source bundle.

A green run proves parsers, the two-root profile and the engine agree; it is
not evidence that any lab detected anything.
"""

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "tests" / "fixtures" / "cli" / "scn003-synthetic-detected"
SCENARIO = ROOT / "scenarios" / "SCN-003-internal-deception.yaml"
PROFILE = ROOT / "scenarios" / "profiles" / "scn-003" / "profile.json"


def validate(bundle):
    result = subprocess.run(
        [sys.executable, "-m", "aegis_verify", "validate", "--scenario", str(SCENARIO),
         "--fixture", str(bundle), "--profile", str(PROFILE), "--format=json"],
        capture_output=True, text=True, check=False, cwd=str(ROOT))
    report = json.loads(result.stdout) if result.stdout.startswith("{") else None
    return result, (report if report and report.get("kind") != "error" else None)


def outcomes(report):
    return {a["assertion_id"]: (a["outcome"], a["reason_code"]) for a in report["evaluation"]["assertions"]}


def rewrite(bundle, name, transform, rehash=True):
    path = bundle / name
    data = transform(path.read_bytes())
    path.write_bytes(data)
    if rehash:
        inputs = json.loads((bundle / "inputs.json").read_bytes())
        for entry in inputs["files"]:
            if entry["path"] == name:
                entry["sha256"] = sha256(data).hexdigest()
        (bundle / "inputs.json").write_bytes(json.dumps(inputs, indent=2).encode("utf-8") + b"\n")


def drop(bundle, name):
    inputs = json.loads((bundle / "inputs.json").read_bytes())
    inputs["files"] = [entry for entry in inputs["files"] if entry["path"] != name]
    (bundle / "inputs.json").write_bytes(json.dumps(inputs, indent=2).encode("utf-8") + b"\n")


@pytest.fixture
def portable(tmp_path):
    return Path(shutil.copytree(BUNDLE, tmp_path / "scn003"))


def test_committed_bundle_hashes_match_the_bytes_and_hold_no_password():
    inputs = json.loads((BUNDLE / "inputs.json").read_bytes())
    for entry in inputs["files"]:
        raw = (BUNDLE / entry["path"]).read_bytes()
        assert sha256(raw).hexdigest() == entry["sha256"], entry["path"]
        assert b"password" not in raw, entry["path"]


def test_four_synthetic_sources_give_detected_with_the_two_roots():
    result, report = validate(BUNDLE)
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
    assert "password" not in result.stdout


def test_cowrie_records_share_one_session_key_and_only_connect_carries_the_tuple():
    from aegis_verify.connectors import cowrie
    records = cowrie.parse_cowrie_jsonl((BUNDLE / "cowrie-session.jsonl").read_bytes(), source_ref="synthetic-cowrie",
                                        environment_id="synthetic-lab", sensor_id="synthetic-cowrie",
                                        ingested_at="2026-01-01T00:02:00Z")
    events = [r.event for r in records if r.event is not None]
    assert [e.event_action for e in events] == ["observed", "login"]
    assert len({e.session_key for e in events}) == 1 and events[0].session_key is not None
    assert events[0].src_port == 51003 and events[1].src_port is None and events[1].dst_ip is None


@pytest.mark.parametrize("name, transform, assertion, status", [
    ("filterlog-pass.log", lambda raw: raw.replace(b",51003,", b",51004,"), "SCN-003-A02", "Missing telemetry"),
    ("eve-alert.jsonl", lambda raw: raw.replace(b'"signature_id":1000012', b'"signature_id":1000011'),
     "SCN-003-A01", "Inconclusive"),
    ("cowrie-session.jsonl", lambda raw: raw.replace(b'"src_port":51003', b'"src_port":51004'),
     "SCN-003-A03", "Missing telemetry"),
    ("cowrie-session.jsonl",
     lambda raw: raw.replace(b'"session":"synthetic-session-003","protocol":"telnet","sensor"',
                             b'"session":"other-session","protocol":"telnet","sensor"', 1),
     "SCN-003-A04", "Inconclusive"),
    ("wazuh-cowrie-alert.json", lambda raw: raw.replace(b"AEGIS-SCN003-1a2b3c4d", b"AEGIS-SCN003-ffffffff"),
     "SCN-003-A04", "Inconclusive"),
    ("wazuh-cowrie-alert.json", lambda raw: raw.replace(b'"id": "120003"', b'"id": "100301"'),
     "SCN-003-A04", "Inconclusive"),
    ("wazuh-cowrie-alert.json", lambda raw: raw.replace(b"2026-01-01T00:00:11.000000+0000",
                                                        b"2026-01-01T00:00:12.200000+0000"),
     "SCN-003-A04", "Inconclusive"),
], ids=["filterlog-other-port", "wrong-sid", "connect-port-rewritten", "connect-other-session",
        "wazuh-other-username", "wazuh-wrong-rule", "wazuh-beyond-window"])
def test_a_mutated_witness_is_never_detected(portable, name, transform, assertion, status):
    rewrite(portable, name, transform)
    result, report = validate(portable)
    assert report is not None, result.stderr
    assert outcomes(report)[assertion][0] != "satisfied"
    assert report["evaluation"]["final_status"] == status
    assert result.returncode != 0


@pytest.mark.parametrize("name", ["filterlog-pass.log", "eve-alert.jsonl", "cowrie-session.jsonl",
                                  "wazuh-cowrie-alert.json"])
def test_a_removed_source_is_never_detected(portable, name):
    drop(portable, name)
    result, report = validate(portable)
    assert report is not None, result.stderr
    assert report["evaluation"]["final_status"] in {"Missing telemetry", "Inconclusive"}


def test_changed_bytes_without_a_new_hash_stop_the_bundle(portable):
    rewrite(portable, "eve-alert.jsonl", lambda raw: raw.replace(b"1000012", b"1000013"), rehash=False)
    result, report = validate(portable)
    assert result.returncode != 0 and report is None
