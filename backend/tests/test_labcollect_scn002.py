"""Offline tests for the read-only SCN-002 collector (#98): a fake runner over the sanitized lab bundles."""

import datetime as dt
import json
import re
from pathlib import Path

import pytest

from aegis_verify.cli.service import evaluate_bundle
from aegis_verify.labcollect import CollectionError, scn002

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "tests/fixtures/cli/scn002-lab-sanitized"
NOW = lambda: dt.datetime(2026, 9, 22, 15, 0, tzinfo=dt.timezone.utc)
CONFIG = {
    "schema_version": "0.1.0", "environment_id": "lab-sanitized",
    "firewall": {"user": "admin", "host": "fw.example"},
    "manager": {"user": "soc", "host": "mgr.example"},
    "sender": {"user": "operator", "host": "sender.example"},
    "paths": {"eve_lan": "/var/log/suricata/lan/eve.json", "filterlog": "/var/log/filter.log",
              "archives": "/var/ossec/logs/archives/archives.json", "alerts": "/var/ossec/logs/alerts/alerts.json"},
    "receipt_dir": "C:\\AEGIS\\probe", "sender_agent_id": "012",
    "sender_ip": "192.0.2.11", "receiver_ip": "198.51.100.10", "receiver_port": 45002,
    "block_rule_tracker": "1790087102", "firewall_utc_offset": "+07:00", "clock_reference_ip": "198.51.100.99",
}
ROUNDS = {
    "block": ("2fb0b7700fd54fee81ebfe19bb78ecd9", 64307, "2026-09-22T14:28:16.4232706Z"),
    "control": ("72340d493a7e4330ad2af25bbbd282d2", 56991, "2026-09-22T13:48:33.4000000Z"),
}
NTPQ = "*198.51.100.99  203.0.113.5  3 u  51  64  377  0.236  -0.032  0.110\n"
CHRONY = "Leap status     : Normal\n"
W32TM = "Tracking 198.51.100.99 [198.51.100.99:123].\nCollecting 1 samples.\n21:30:00, +00.0080599s\n"


def config(**changes):
    return scn002.load_config(json.dumps(CONFIG | changes).encode())


def probe(label):
    return f"sent 66 bytes  run={ROUNDS[label][0]}  label={label}"


def receipt(round_label, **changes):
    run, port, sent = ROUNDS[round_label]
    body = {"kind": "scn002_sender_receipt", "version": "0.1.0", "run_id": run, "label": round_label,
            "marker": "AEGIS-SCN002-TEST", "payload_bytes": 66, "payload_sha256": "0" * 64,
            "sent_before_utc": sent, "sent_after_utc": sent, "local_endpoint": f"0.0.0.0:{port}",
            "remote_endpoint": "198.51.100.10:45002", "note": "Sender-side log only."} | changes
    return json.dumps(body, indent=4)


def sources(label):
    base = LAB / label
    sysmon = (base / "sysmon3-archive.json").read_bytes()
    port = str(ROUNDS[label][1]).encode()
    other_agent = sysmon.replace(b'"agent":{"id":"012"', b'"agent":{"id":"099"')
    other_port = sysmon.replace(b'"sourcePort":"' + port + b'"', b'"sourcePort":"1"')
    eve = (base / "eve-alert.json").read_bytes()
    alert = (base / "wazuh-alert.json").read_bytes()
    files = {
        "/var/ossec/logs/archives/archives.json": other_agent + other_port + sysmon,
        "/var/log/suricata/lan/eve.json": eve.replace(b'"src_port":' + port, b'"src_port":1') + eve,
        "/var/ossec/logs/alerts/alerts.json": alert.replace(ROUNDS[label][0].encode(), b"f" * 32) + alert,
        "/var/log/filter.log": b"",
    }
    if label == "block":
        line = (LAB / "block" / "filterlog.log").read_bytes()
        files["/var/log/filter.log"] = line.replace(b",block,", b",pass,") + line
    return files


class FakeRunner:
    def __init__(self, label, files=None, answers=None, receipt_text=None):
        self.label, self.calls = label, []
        self.files = files or sources(label)
        self.receipt = receipt_text if receipt_text is not None else receipt(label)
        self.answers = {"ntpq -pn": NTPQ, "chronyc tracking": CHRONY,
                        "w32tm /stripchart /computer:198.51.100.99 /samples:1 /dataonly": W32TM} | (answers or {})

    def __call__(self, target, command):
        self.calls.append((target.host, command))
        if command in self.answers:
            return 0, self.answers[command].encode()
        if command == f"type C:\\AEGIS\\probe\\scn002-sender-{ROUNDS[self.label][0]}.json":
            return 0, self.receipt.encode()
        grep = re.fullmatch(r"grep -F -- '?([^' ]+)'? (\S+)", command)
        if grep:
            lines = [l for l in self.files[grep[2]].splitlines(keepends=True) if grep[1].encode() in l]
            return (0, b"".join(lines)) if lines else (1, b"")
        raise AssertionError("unexpected remote command: " + command)


def evaluate(out):
    return evaluate_bundle(str(ROOT / "scenarios/SCN-002-attempted-exfiltration.yaml"), str(out),
                           profile=str(ROOT / "scenarios/profiles/scn-002/profile.json"))


def test_block_round_is_prevented_and_bytes_match_the_lab_bundle(tmp_path):
    out = tmp_path / "block"
    summary = scn002.collect_round(config(), probe("block"), out, FakeRunner("block"), now=NOW)
    assert summary["label"] == "block" and summary["source_port"] == 64307
    assert summary["preflight"] == {"firewall_offset_ms": -0.032, "manager_leap": "Normal", "sender_offset_ms": 8.06}
    assert summary["source_minus_send_s"] == {
        "sysmon3-archive.json": 0.191, "eve-alert.json": -0.059, "wazuh-alert.json": 1.28}
    for name in ("sysmon3-archive.json", "eve-alert.json", "filterlog.log", "wazuh-alert.json"):
        assert (out / name).read_bytes() == (LAB / "block" / name).read_bytes(), name
    assert evaluate(out)["evaluation"]["final_status"] == "Prevented"


def test_control_round_has_no_filterlog_and_stays_inconclusive(tmp_path):
    out, runner = tmp_path / "control", FakeRunner("control")
    scn002.collect_round(config(), probe("control"), out, runner, now=NOW)
    assert not (out / "filterlog.log").exists()
    assert not any("filter.log" in cmd for _, cmd in runner.calls)
    report = evaluate(out)
    assert report["evaluation"]["final_status"] == "Inconclusive"
    outcomes = {a["assertion_id"]: a["outcome"] for a in report["evaluation"]["assertions"]}
    assert outcomes["SCN-002-A03"] == "inconclusive"
    assert {outcomes[k] for k in ("SCN-002-A01", "SCN-002-A02", "SCN-002-A04")} == {"satisfied"}


def test_skewed_sysmon_clock_is_reported_and_bytes_are_kept(tmp_path):
    # Lab 2026-09-27: Sysmon's network events kept a clock from before a w32time step.
    skewed = {path: data.replace(b"2026-09-22 13:48:33.809", b"2026-09-22 13:48:28.909")
              for path, data in sources("control").items()}
    out = tmp_path / "control"
    summary = scn002.collect_round(config(), probe("control"), out, FakeRunner("control", files=skewed), now=NOW)
    assert summary["source_minus_send_s"] == {
        "sysmon3-archive.json": -4.491, "eve-alert.json": 0.064, "wazuh-alert.json": 0.552}
    lab = (LAB / "control" / "sysmon3-archive.json").read_bytes()
    assert (out / "sysmon3-archive.json").read_bytes() == lab.replace(b"13:48:33.809", b"13:48:28.909")
    outcomes = {a["assertion_id"]: a["outcome"] for a in evaluate(out)["evaluation"]["assertions"]}
    assert outcomes["SCN-002-A02"] != "satisfied"


def test_unreadable_source_time_is_null(tmp_path):
    files = sources("control")
    alerts = "/var/ossec/logs/alerts/alerts.json"
    files[alerts] = files[alerts].replace(b'{"timestamp":"2026-09-22T13:48:33.952+0000"', b'{"timestamp":"later"')
    summary = scn002.collect_round(config(), probe("control"), tmp_path / "control",
                                   FakeRunner("control", files=files), now=NOW)
    assert summary["source_minus_send_s"]["wazuh-alert.json"] is None
    assert summary["source_minus_send_s"]["eve-alert.json"] == 0.064


def test_remote_commands_are_read_only_and_fixed(tmp_path):
    runner = FakeRunner("block")
    scn002.collect_round(config(), probe("block"), tmp_path / "block", runner, now=NOW)
    assert runner.calls == [
        ("fw.example", "ntpq -pn"), ("mgr.example", "chronyc tracking"),
        ("sender.example", "w32tm /stripchart /computer:198.51.100.99 /samples:1 /dataonly"),
        ("sender.example", "type C:\\AEGIS\\probe\\scn002-sender-2fb0b7700fd54fee81ebfe19bb78ecd9.json"),
        ("mgr.example", "grep -F -- '\"sourcePort\":\"64307\"' /var/ossec/logs/archives/archives.json"),
        ("fw.example", "grep -F -- 1000010 /var/log/suricata/lan/eve.json"),
        ("mgr.example", "grep -F -- 2fb0b7700fd54fee81ebfe19bb78ecd9 /var/ossec/logs/alerts/alerts.json"),
        ("fw.example", "grep -F -- 1790087102 /var/log/filter.log"),
    ]


@pytest.mark.parametrize("changes", [
    {"label": "control"}, {"remote_endpoint": "198.51.100.10:45003"}, {"marker": "OTHER"},
    {"run_id": "0" * 32}, {"local_endpoint": "0.0.0.0:notaport"},
])
def test_receipt_must_match_the_probe_and_config(tmp_path, changes):
    with pytest.raises(CollectionError) as caught:
        scn002.collect_round(config(), probe("block"), tmp_path / "block",
                             FakeRunner("block", receipt_text=receipt("block", **changes)), now=NOW)
    assert (caught.value.code, caught.value.source) == ("probe_config_mismatch", "sender")


def test_sender_clock_is_checked(tmp_path):
    answers = {"w32tm /stripchart /computer:198.51.100.99 /samples:1 /dataonly": W32TM.replace("+00.0080599", "+03.8")}
    with pytest.raises(CollectionError) as caught:
        scn002.collect_round(config(), probe("block"), tmp_path / "block", FakeRunner("block", answers=answers), now=NOW)
    assert (caught.value.code, caught.value.source) == ("clock_not_synchronised", "sender")


def test_missing_block_line_stops_before_writing(tmp_path):
    files = sources("block")
    files["/var/log/filter.log"] = files["/var/log/filter.log"].splitlines(keepends=True)[0]
    with pytest.raises(CollectionError) as caught:
        scn002.collect_round(config(), probe("block"), tmp_path / "block", FakeRunner("block", files=files), now=NOW)
    assert caught.value.code == "unexpected_line_count"
    assert caught.value.detail["counts"]["filterlog.log"] == 0
    assert not (tmp_path / "block").exists()


@pytest.mark.parametrize("line", ["garbage", "sent 66 bytes  run=XYZ  label=block",
                                  "sent 66 bytes  run=" + "a" * 32 + "  label=other"])
def test_probe_line_is_checked(tmp_path, line):
    with pytest.raises(CollectionError) as caught:
        scn002.collect_round(config(), line, tmp_path / "x", FakeRunner("block"), now=NOW)
    assert caught.value.code == "invalid_probe_line"


@pytest.mark.parametrize("change", [
    {"receipt_dir": "C:\\AEGIS\\..\\Windows"}, {"receipt_dir": "C:\\AEGIS probe"}, {"receipt_dir": "relative"},
    {"sender_agent_id": "12"}, {"paths": CONFIG["paths"] | {"archives": "/var/ossec/$(id)"}},
    {"clock_reference_ip": "198.51.100.099"}, {"block_rule_tracker": "17900871O2"}, {"extra": 1},
])
def test_config_rejects_unsafe_values(change):
    with pytest.raises(CollectionError) as caught:
        config(**change)
    assert caught.value.code == "invalid_config"


def test_documented_example_config_is_valid():
    example = scn002.load_config((ROOT / "docs/examples/scn002-collect.example.json").read_bytes())
    assert example.receiver_port == 45002
