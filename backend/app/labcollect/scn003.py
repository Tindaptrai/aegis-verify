"""Read-only SCN-003 control-round collector (issue #95).

Reads the four lab sources over SSH, selects the round's records locally with exact
byte matching, and writes a bundle for `aegis validate`. It never runs the probe,
never changes lab state and never reads credentials: SSH uses a key in batch mode
against known hosts. Every configured value is checked before it reaches a remote
command line.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from pydantic import Field, ValidationError, field_validator

from ._common import (
    NAME, CollectionError, Closed, PosixPath, Runner, SshTarget, canonical_ipv4, check_chrony,
    check_ntpq, check_output, no_dot_segments, read, ssh_command, ssh_runner, write_payload,
)

SURICATA_SID = "1000012"
WAZUH_RULE = "120003"
SCENARIO = "scenarios/SCN-003-internal-deception.yaml"
PROFILE = "scenarios/profiles/scn-003/profile.json"
EXPECTED_LINES = {"filterlog.log": 1, "eve-alert.json": 1, "cowrie-session.jsonl": 2, "wazuh-alert.json": 1}
_NAME, _Path, _Closed = NAME, PosixPath, Closed
__all__ = ["CollectionError", "Scn003LabConfig", "collect_round", "load_config", "ssh_command", "ssh_runner"]


class Paths(_Closed):
    filterlog: str = _Path
    eve: str = _Path
    honeypot_log: str = _Path
    alerts: str = _Path

    _dots = field_validator("filterlog", "eve", "honeypot_log", "alerts")(no_dot_segments)


class Scn003LabConfig(_Closed):
    schema_version: Literal["0.1.0"]
    environment_id: str = Field(pattern=f"^{_NAME}$")
    firewall: SshTarget
    manager: SshTarget
    honeypot: SshTarget
    paths: Paths
    honeypot_read_as: str | None = Field(default=None, pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    initiator_ip: str
    decoy_ip: str
    decoy_port: int = Field(ge=1, le=65535)
    firewall_dst_ip: str
    firewall_dst_port: int = Field(ge=1, le=65535)
    cowrie_ip: str
    cowrie_port: int = Field(ge=1, le=65535)
    honeypot_protocol: Literal["telnet", "ssh"]
    firewall_rule_tracker: str = Field(pattern=r"^[0-9]{1,20}$")
    firewall_utc_offset: str = Field(pattern=r"^[+-](?:0[0-9]|1[0-4]):[0-5][0-9]$")
    honeypot_sensor_id: str = Field(pattern=f"^{_NAME}$")
    max_clock_offset_ms: int = Field(default=500, ge=1, le=5000)

    _ipv4 = field_validator("initiator_ip", "decoy_ip", "firewall_dst_ip", "cowrie_ip")(canonical_ipv4)


def load_config(raw: bytes) -> Scn003LabConfig:
    try:
        return Scn003LabConfig.model_validate_json(raw)
    except (ValidationError, ValueError):
        raise CollectionError("invalid_config") from None


@dataclass(frozen=True)
class Probe:
    initiator_ip: str
    source_port: int
    decoy_ip: str
    decoy_port: int
    run_id: str
    marker: str


_PROBE = re.compile(r"connected (\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5}) -> (\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})"
                    r"\s+run=([0-9a-f]{32})\s+user=(AEGIS-SCN003-[0-9a-f]{8})(?:\s|$)")


def parse_probe_line(line: str, config: Scn003LabConfig) -> Probe:
    match = _PROBE.search(line if isinstance(line, str) else "")
    if not match:
        raise CollectionError("invalid_probe_line")
    initiator, port, decoy, decoy_port, run_id, marker = match.groups()
    port, decoy_port = int(port), int(decoy_port)
    if not 1 <= port <= 65535:
        raise CollectionError("invalid_probe_line")
    if (initiator, decoy, decoy_port) != (config.initiator_ip, config.decoy_ip, config.decoy_port):
        raise CollectionError("probe_config_mismatch")
    return Probe(initiator, port, decoy, decoy_port, run_id, marker)


def preflight(config: Scn003LabConfig, runner: Runner) -> dict:
    offset = check_ntpq(runner, config.firewall, config.max_clock_offset_ms, "firewall")
    check_chrony(runner, config.manager, "manager")
    listening = read(runner, config.honeypot, "ss -ltn", "honeypot", grep=False).decode("utf-8", "replace")
    if not re.search(rf"[:.]{config.cowrie_port}\s", listening):
        raise CollectionError("honeypot_not_listening", "honeypot")
    return {"firewall_offset_ms": offset, "manager_leap": "Normal", "honeypot_listening": True}


def select_filterlog(raw: bytes, config: Scn003LabConfig, probe: Probe) -> list[bytes]:
    tuple_ = f",{probe.initiator_ip},{config.firewall_dst_ip},{probe.source_port},{config.firewall_dst_port},".encode()
    tracker = f",{config.firewall_rule_tracker},".encode()
    lines = [l for l in raw.splitlines(keepends=True) if tuple_ in l and tracker in l and b",pass," in l]
    return lines[:1]


def select_eve(raw: bytes, probe: Probe) -> list[bytes]:
    sid, port = f'"signature_id":{SURICATA_SID}'.encode(), f'"src_port":{probe.source_port},'.encode()
    return [l for l in raw.splitlines(keepends=True) if sid in l and port in l]


def select_cowrie(raw: bytes, probe: Probe) -> list[bytes]:
    lines = raw.splitlines(keepends=True)
    first = next((l for l in lines if f'"src_port":{probe.source_port},'.encode() in l), None)
    found = re.search(rb'"session":"([^"]+)"', first) if first else None
    if not found:
        return []
    session = b'"session":"' + found.group(1) + b'"'
    return [l for l in lines if session in l and re.search(rb"session\.connect|login\.failed", l)]


def select_alerts(raw: bytes, probe: Probe) -> list[bytes]:
    rule, marker = f'"id":"{WAZUH_RULE}"'.encode(), probe.marker.encode()
    return [l for l in raw.splitlines(keepends=True) if rule in l and marker in l]


def collect_evidence(config: Scn003LabConfig, probe: Probe, runner: Runner) -> dict[str, bytes]:
    reader = "cat" if config.honeypot_read_as is None else f"sudo -n -u {config.honeypot_read_as} /usr/bin/cat"
    found = {
        "filterlog.log": select_filterlog(read(
            runner, config.firewall, f"grep -F -- {config.firewall_rule_tracker} {config.paths.filterlog}",
            "firewall", grep=True), config, probe),
        "eve-alert.json": select_eve(read(
            runner, config.firewall, f"grep -F -- {SURICATA_SID} {config.paths.eve}", "firewall", grep=True), probe),
        "cowrie-session.jsonl": select_cowrie(read(
            runner, config.honeypot, f"{reader} {config.paths.honeypot_log}", "honeypot", grep=False), probe),
        "wazuh-alert.json": select_alerts(read(
            runner, config.manager, f"grep -F -- {probe.marker} {config.paths.alerts}", "manager", grep=True), probe),
    }
    counts = {name: len(lines) for name, lines in found.items()}
    if counts != EXPECTED_LINES:
        raise CollectionError("unexpected_line_count", detail={"counts": counts, "expected": EXPECTED_LINES})
    return {name: b"".join(lines) for name, lines in found.items()}


def _connect_time(cowrie: bytes) -> dt.datetime:
    for line in cowrie.splitlines():
        record = json.loads(line)
        if record.get("eventid") == "cowrie.session.connect":
            return dt.datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    raise CollectionError("unexpected_line_count")


def write_bundle(evidence: dict[str, bytes], config: Scn003LabConfig, probe: Probe, out: Path,
                 *, ingested_at: dt.datetime) -> dict:
    out = check_output(out)
    connect = _connect_time(evidence["cowrie-session.jsonl"])
    start = connect.replace(second=0, microsecond=0) - dt.timedelta(minutes=1)
    end = start + dt.timedelta(minutes=3)
    stamp = ingested_at.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    suffix = probe.run_id[-8:]
    sensor = config.honeypot_sensor_id
    specs = [
        ("filterlog.log", "pfsense-filterlog-bsd-ipv4-tcp-udp-v1", "pfsense", "pfSense filterlog",
         {"ingested_at": stamp, "sensor_id": "pfsense", "source_year": connect.year,
          "source_utc_offset": config.firewall_utc_offset}),
        ("eve-alert.json", "suricata-eve-jsonl-v1", "suricata", "Suricata",
         {"ingested_at": stamp, "sensor_id": "suricata", "deployment_mode": "ids"}),
        ("cowrie-session.jsonl", "cowrie-jsonl-v1", "cowrie", "Cowrie honeypot",
         {"ingested_at": stamp, "sensor_id": sensor}),
        ("wazuh-alert.json", "wazuh-cowrie-alert-v1", f"wazuh-{WAZUH_RULE}", f"Wazuh manager (rule {WAZUH_RULE})",
         {"ingested_at": stamp, "collection_mode": "direct", "sensor_id": sensor}),
    ]
    files = [{"path": name, "source_ref": f"{ref}-{suffix}", "display_label": label, "parser": parser,
              "sha256": hashlib.sha256(evidence[name]).hexdigest(), "context": context}
             for name, parser, ref, label, context in specs]
    bindings = [("initiator_ip", probe.initiator_ip), ("initiator_port", probe.source_port),
                ("decoy_ip", config.decoy_ip), ("decoy_port", config.decoy_port),
                ("firewall_dst_ip", config.firewall_dst_ip), ("firewall_dst_port", config.firewall_dst_port),
                ("cowrie_ip", config.cowrie_ip), ("cowrie_port", config.cowrie_port),
                ("honeypot_protocol", config.honeypot_protocol),
                ("firewall_rule_tracker", config.firewall_rule_tracker), ("username_marker", probe.marker)]
    context = {"run_id": f"scn003-control-{probe.run_id}", "environment_id": config.environment_id,
               "start": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "end": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "bindings": [{"name": n, "value": v} for n, v in bindings], "declarations": []}
    inputs = {"bundle_schema_version": "0.1.0", "environment_id": config.environment_id, "files": files}
    out.mkdir(parents=True, exist_ok=True)
    payload = {name: evidence[name] for name in EXPECTED_LINES}
    payload["inputs.json"] = (json.dumps(inputs, indent=2) + "\n").encode()
    payload["context.json"] = (json.dumps(context, indent=2) + "\n").encode()
    for name, data in payload.items():
        with (out / name).open("xb") as stream:
            stream.write(data)
    return {"kind": "collection", "scenario_id": "SCN-003", "run_id": context["run_id"], "out": str(out),
            "files": [{"path": f["path"], "sha256": f["sha256"], "lines": EXPECTED_LINES[f["path"]]} for f in files],
            "validate": {"scenario": SCENARIO, "profile": PROFILE}}


def collect_round(config: Scn003LabConfig, probe_line: str, out: Path, runner: Runner, *,
                  now: Callable[[], dt.datetime], check_preflight: bool = True) -> dict:
    probe = parse_probe_line(probe_line, config)
    checks = preflight(config, runner) if check_preflight else None
    evidence = collect_evidence(config, probe, runner)
    summary = write_bundle(evidence, config, probe, out, ingested_at=now())
    summary["preflight"] = checks
    return summary
