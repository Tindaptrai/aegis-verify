"""Offline tests for the read-only SCN-003 collector (#95): a fake runner, no network."""

import datetime as dt
import json
import re
from pathlib import Path

import pytest

from aegis_verify.cli import main
from aegis_verify.cli.service import evaluate_bundle
from aegis_verify.labcollect import CollectionError, collect_round, load_config
from aegis_verify.labcollect.scn003 import ssh_command

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/cli/scn003-synthetic-detected"
NOW = lambda: dt.datetime(2026, 1, 1, 0, 5, tzinfo=dt.timezone.utc)
PROBE = ("connected 192.0.2.10:51003 -> 203.0.113.30:2223  run=" + "a" * 32
         + "  user=AEGIS-SCN003-1a2b3c4d  label=control")
CONFIG = {
    "schema_version": "0.1.0", "environment_id": "synthetic-lab",
    "firewall": {"user": "admin", "host": "fw.example"},
    "manager": {"user": "soc", "host": "mgr.example"},
    "honeypot": {"user": "soc", "host": "hp.example", "jump": {"user": "soc", "host": "mgr.example"}},
    "paths": {"filterlog": "/var/log/filter.log", "eve": "/var/log/suricata/wan/eve.json",
              "honeypot_log": "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
              "alerts": "/var/ossec/logs/alerts/alerts.json"},
    "honeypot_read_as": "cowrie", "initiator_ip": "192.0.2.10", "decoy_ip": "203.0.113.30", "decoy_port": 2223,
    "firewall_dst_ip": "198.51.100.20", "firewall_dst_port": 2223, "cowrie_ip": "198.51.100.20",
    "cowrie_port": 2223, "honeypot_protocol": "telnet", "firewall_rule_tracker": "1700000003",
    "firewall_utc_offset": "+07:00", "honeypot_sensor_id": "synthetic-cowrie",
}
NTPQ = ("     remote           refid      st t when poll reach   delay   offset  jitter\n"
        "==============================================================================\n"
        "*198.51.100.99  203.0.113.5      3 u   51   64  377    0.236   -0.032   0.110\n")
CHRONY = "Reference ID    : C6336463 (198.51.100.99)\nStratum         : 3\nLeap status     : Normal\n"
SS = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 50 0.0.0.0:2223 0.0.0.0:*\n"


def config(**changes):
    return load_config(json.dumps(CONFIG | changes).encode())


def sources():
    """The synthetic round plus records of other flows and sessions that must not be picked."""
    alert = json.dumps(json.loads((FIXTURE / "wazuh-cowrie-alert.json").read_bytes()), separators=(",", ":"))
    other_alert = alert.replace("AEGIS-SCN003-1a2b3c4d", "AEGIS-SCN003-ffffffff")
    filterlog = (FIXTURE / "filterlog-pass.log").read_bytes()
    eve = (FIXTURE / "eve-alert.jsonl").read_bytes()
    cowrie = (FIXTURE / "cowrie-session.jsonl").read_bytes()
    return {
        "/var/log/filter.log": filterlog.replace(b",51003,", b",51004,") + filterlog
                               + filterlog.replace(b",pass,", b",block,"),
        "/var/log/suricata/wan/eve.json": eve.replace(b'"src_port":51003', b'"src_port":51004') + eve,
        "/home/cowrie/cowrie/var/log/cowrie/cowrie.json":
            cowrie.replace(b'"src_port":51003', b'"src_port":51004').replace(b"synthetic-session-003", b"other-session")
            + cowrie,
        "/var/ossec/logs/alerts/alerts.json": (other_alert + "\n" + alert + "\n").encode(),
    }


class FakeRunner:
    def __init__(self, files=None, answers=None, fail_host=None):
        self.files, self.calls, self.fail_host = files or sources(), [], fail_host
        self.answers = {"ntpq -pn": NTPQ, "chronyc tracking": CHRONY, "ss -ltn": SS} | (answers or {})

    def __call__(self, target, command):
        self.calls.append((target.host, command))
        if target.host == self.fail_host:
            return 255, b""
        if command in self.answers:
            return 0, self.answers[command].encode()
        grep = re.fullmatch(r"grep -F -- (\S+) (\S+)", command)
        if grep:
            lines = [l for l in self.files[grep[2]].splitlines(keepends=True) if grep[1].encode() in l]
            return (0, b"".join(lines)) if lines else (1, b"")
        cat = re.fullmatch(r"sudo -n -u cowrie /usr/bin/cat (\S+)", command)
        if cat and target.host == "hp.example":
            return 0, self.files[cat[1]]
        raise AssertionError("unexpected remote command: " + command)


def test_collected_round_validates_as_detected(tmp_path):
    out = tmp_path / "round"
    summary = collect_round(config(), PROBE, out, FakeRunner(), now=NOW)
    assert summary["kind"] == "collection" and summary["run_id"] == "scn003-control-" + "a" * 32
    assert summary["preflight"]["firewall_offset_ms"] == -0.032
    report = evaluate_bundle(str(ROOT / "scenarios/SCN-003-internal-deception.yaml"), str(out),
                             profile=str(ROOT / "scenarios/profiles/scn-003/profile.json"))
    assert report["evaluation"]["final_status"] == "Detected"
    assert {a["outcome"] for a in report["evaluation"]["assertions"]} == {"satisfied"}


def test_only_the_round_records_are_taken_byte_for_byte(tmp_path):
    out = tmp_path / "round"
    collect_round(config(), PROBE, out, FakeRunner(), now=NOW)
    assert (out / "filterlog.log").read_bytes() == (FIXTURE / "filterlog-pass.log").read_bytes()
    assert (out / "eve-alert.json").read_bytes() == (FIXTURE / "eve-alert.jsonl").read_bytes()
    assert (out / "cowrie-session.jsonl").read_bytes() == (FIXTURE / "cowrie-session.jsonl").read_bytes()
    assert b"AEGIS-SCN003-1a2b3c4d" in (out / "wazuh-alert.json").read_bytes()
    context = json.loads((out / "context.json").read_bytes())
    bindings = {b["name"]: b["value"] for b in context["bindings"]}
    assert bindings["initiator_port"] == 51003 and bindings["username_marker"] == "AEGIS-SCN003-1a2b3c4d"
    assert (context["start"], context["end"]) == ("2025-12-31T23:59:00Z", "2026-01-01T00:02:00Z")
    inputs = json.loads((out / "inputs.json").read_bytes())
    assert [f["parser"] for f in inputs["files"]] == [
        "pfsense-filterlog-bsd-ipv4-tcp-udp-v1", "suricata-eve-jsonl-v1", "cowrie-jsonl-v1", "wazuh-cowrie-alert-v1"]


def test_remote_commands_are_read_only_and_fixed(tmp_path):
    runner = FakeRunner()
    collect_round(config(), PROBE, tmp_path / "round", runner, now=NOW)
    assert runner.calls == [
        ("fw.example", "ntpq -pn"), ("mgr.example", "chronyc tracking"), ("hp.example", "ss -ltn"),
        ("fw.example", "grep -F -- 1700000003 /var/log/filter.log"),
        ("fw.example", "grep -F -- 1000012 /var/log/suricata/wan/eve.json"),
        ("hp.example", "sudo -n -u cowrie /usr/bin/cat /home/cowrie/cowrie/var/log/cowrie/cowrie.json"),
        ("mgr.example", "grep -F -- AEGIS-SCN003-1a2b3c4d /var/ossec/logs/alerts/alerts.json"),
    ]


def test_skip_preflight_runs_no_preflight_command(tmp_path):
    runner = FakeRunner()
    summary = collect_round(config(), PROBE, tmp_path / "round", runner, now=NOW, check_preflight=False)
    assert summary["preflight"] is None
    assert not any(cmd in ("ntpq -pn", "chronyc tracking", "ss -ltn") for _, cmd in runner.calls)


@pytest.mark.parametrize("path, drop", [
    ("/var/log/suricata/wan/eve.json", b'"src_port":51003'),
    ("/var/log/filter.log", b",51003,"),
    ("/home/cowrie/cowrie/var/log/cowrie/cowrie.json", b"cowrie.login.failed"),
])
def test_wrong_line_count_stops_before_writing(tmp_path, path, drop):
    files = sources()
    files[path] = b"".join(l for l in files[path].splitlines(keepends=True)
                           if not (drop in l and b"other-session" not in l and b",51004," not in l
                                   and b'"src_port":51004' not in l))
    with pytest.raises(CollectionError) as caught:
        collect_round(config(), PROBE, tmp_path / "round", FakeRunner(files=files), now=NOW)
    assert caught.value.code == "unexpected_line_count"
    assert not (tmp_path / "round").exists()


@pytest.mark.parametrize("answers, code, source", [
    ({"ntpq -pn": NTPQ.replace("*198", " 198")}, "clock_not_synchronised", "firewall"),
    ({"ntpq -pn": NTPQ.replace("-0.032", "+900.5")}, "clock_not_synchronised", "firewall"),
    ({"chronyc tracking": CHRONY.replace("Normal", "Not synchronised")}, "clock_not_synchronised", "manager"),
    ({"ss -ltn": SS.replace("2223", "2222")}, "honeypot_not_listening", "honeypot"),
])
def test_preflight_failures_stop_the_round(tmp_path, answers, code, source):
    with pytest.raises(CollectionError) as caught:
        collect_round(config(), PROBE, tmp_path / "round", FakeRunner(answers=answers), now=NOW)
    assert (caught.value.code, caught.value.source) == (code, source)


def test_unreachable_host_is_named_without_lab_values(tmp_path):
    with pytest.raises(CollectionError) as caught:
        collect_round(config(), PROBE, tmp_path / "round", FakeRunner(fail_host="mgr.example"), now=NOW)
    error = caught.value.as_dict()
    assert error["error"]["code"] == "source_unreachable" and error["error"]["source"] == "manager"
    assert "mgr.example" not in json.dumps(error) and "192.0.2.10" not in json.dumps(error)


@pytest.mark.parametrize("line, code", [
    ("garbage", "invalid_probe_line"),
    (PROBE.replace("user=AEGIS-SCN003-1a2b3c4d", "user=AEGIS-SCN003-XYZ"), "invalid_probe_line"),
    (PROBE.replace(":51003", ":70000"), "invalid_probe_line"),
    (PROBE.replace("192.0.2.10", "192.0.2.11"), "probe_config_mismatch"),
    (PROBE.replace("203.0.113.30:2223", "203.0.113.30:23"), "probe_config_mismatch"),
])
def test_probe_line_is_checked(tmp_path, line, code):
    with pytest.raises(CollectionError) as caught:
        collect_round(config(), line, tmp_path / "round", FakeRunner(), now=NOW)
    assert caught.value.code == code


@pytest.mark.parametrize("change", [
    {"paths": CONFIG["paths"] | {"eve": "/var/log/eve.json; rm -rf /"}},
    {"paths": CONFIG["paths"] | {"alerts": "/var/ossec/$(id)/alerts.json"}},
    {"paths": CONFIG["paths"] | {"filterlog": "relative/filter.log"}},
    {"paths": CONFIG["paths"] | {"filterlog": "/var/log/../etc/passwd"}},
    {"firewall": {"user": "admin", "host": "fw.example;id"}},
    {"manager": {"user": "Root", "host": "mgr.example"}},
    {"initiator_ip": "192.0.2.010"},
    {"firewall_rule_tracker": "17000000 03"},
    {"honeypot_read_as": "cowrie /bin/sh"},
    {"decoy_port": 70000},
    {"unexpected": True},
])
def test_config_rejects_unsafe_or_unknown_values(change):
    with pytest.raises(CollectionError) as caught:
        config(**change)
    assert caught.value.code == "invalid_config"


def test_output_must_be_new_and_outside_any_repository(tmp_path):
    used = tmp_path / "used"
    used.mkdir()
    (used / "keep.txt").write_text("x")
    with pytest.raises(CollectionError) as caught:
        collect_round(config(), PROBE, used, FakeRunner(), now=NOW)
    assert caught.value.code == "output_exists"
    with pytest.raises(CollectionError) as caught:
        collect_round(config(), PROBE, ROOT / "build" / "scn003-round", FakeRunner(), now=NOW)
    assert caught.value.code == "output_in_repository"
    assert not (ROOT / "build" / "scn003-round").exists()


def test_ssh_uses_batch_mode_known_hosts_and_the_jump_host():
    cfg = config()
    args = ssh_command(cfg.honeypot, "ss -ltn", key_path="C:/keys/aegis_lab")
    assert args[:3] == ["ssh", "-i", "C:/keys/aegis_lab"]
    assert "BatchMode=yes" in args and "StrictHostKeyChecking=yes" in args
    assert any(a.startswith("ProxyCommand=ssh -i C:/keys/aegis_lab") and a.endswith("-W %h:%p soc@mgr.example")
               for a in args)
    assert args[-2:] == ["soc@hp.example", "ss -ltn"]
    for bad in ("C:/my keys/aegis_lab", 'C:/k"ey', "C:/key;rm"):
        with pytest.raises(CollectionError):
            ssh_command(cfg.firewall, "ntpq -pn", key_path=bad)


def test_cli_reports_a_safe_json_error_for_a_bad_config(tmp_path, capsys):
    bad = tmp_path / "config.json"
    bad.write_text(json.dumps(CONFIG | {"initiator_ip": "not-an-ip"}))
    code = main(["collect", "scn003", "--config", str(bad), "--key", "C:/keys/aegis_lab",
                 "--probe-line", PROBE, "--out", str(tmp_path / "round")])
    captured = capsys.readouterr()
    assert code == 2 and captured.out == ""
    assert json.loads(captured.err)["error"]["code"] == "invalid_config"
    assert main(["collect", "scn003", "--help"]) == 0


def test_documented_example_config_is_valid():
    example = load_config((ROOT / "docs/examples/scn003-collect.example.json").read_bytes())
    assert example.honeypot.jump is not None and example.firewall_rule_tracker == "1700000003"
