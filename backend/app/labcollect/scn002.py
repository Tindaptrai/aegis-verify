"""Read-only SCN-002 collector for one control or block round (issue #98).

The probe's own receipt, read on the sender, gives the source port and send time.
Sysmon event 3 comes from the manager archive, the Suricata LAN alert and (block
round only) the filterlog block line from the firewall, the Wazuh 86601 alert
from the manager. Records are selected locally, byte for byte.
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
    check_ntpq, check_output, check_w32tm, no_dot_segments, quoted, read, write_payload,
)

SURICATA_SID = "1000010"
WAZUH_RULE = "86601"
MARKER = "AEGIS-SCN002-TEST"
SCENARIO = "scenarios/SCN-002-attempted-exfiltration.yaml"
PROFILE = "scenarios/profiles/scn-002/profile.json"


class Scn002Paths(Closed):
    eve_lan: str = PosixPath
    filterlog: str = PosixPath
    archives: str = PosixPath
    alerts: str = PosixPath
    _dots = field_validator("eve_lan", "filterlog", "archives", "alerts")(no_dot_segments)


class Scn002LabConfig(Closed):
    schema_version: Literal["0.1.0"]
    environment_id: str = Field(pattern=f"^{NAME}$")
    firewall: SshTarget
    manager: SshTarget
    sender: SshTarget
    paths: Scn002Paths
    receipt_dir: str = Field(pattern=r"^[A-Za-z]:\\(?:[A-Za-z0-9._-]+\\)*[A-Za-z0-9._-]+$", max_length=200)
    sender_agent_id: str = Field(pattern=r"^[0-9]{3,8}$")
    sender_ip: str
    receiver_ip: str
    receiver_port: int = Field(ge=1, le=65535)
    block_rule_tracker: str = Field(pattern=r"^[0-9]{1,20}$")
    firewall_utc_offset: str = Field(pattern=r"^[+-](?:0[0-9]|1[0-4]):[0-5][0-9]$")
    clock_reference_ip: str
    max_clock_offset_ms: int = Field(default=500, ge=1, le=5000)
    _ipv4 = field_validator("sender_ip", "receiver_ip", "clock_reference_ip")(canonical_ipv4)

    @field_validator("receipt_dir")
    @classmethod
    def _no_windows_dot_segments(cls, value: str) -> str:
        if any(part in (".", "..") for part in value[3:].split("\\")):
            raise ValueError("dot segments are not allowed")
        return value


def load_config(raw: bytes) -> Scn002LabConfig:
    try:
        return Scn002LabConfig.model_validate_json(raw)
    except (ValidationError, ValueError):
        raise CollectionError("invalid_config") from None


@dataclass(frozen=True)
class Round:
    run_id: str
    label: str
    source_port: int
    sent_before: dt.datetime


_PROBE = re.compile(r"sent (\d{1,3}) bytes\s+run=([0-9a-f]{32})\s+label=(control|block)(?:\s|$)")


def parse_probe_line(line: str) -> tuple[str, str]:
    match = _PROBE.search(line if isinstance(line, str) else "")
    if not match:
        raise CollectionError("invalid_probe_line")
    return match.group(2), match.group(3)


def read_receipt(config: Scn002LabConfig, run_id: str, label: str, runner: Runner) -> Round:
    raw = read(runner, config.sender, f"type {config.receipt_dir}\\scn002-sender-{run_id}.json", "sender", grep=False)
    try:
        receipt = json.loads(raw.decode("ascii").strip())
        local_port = int(receipt["local_endpoint"].rsplit(":", 1)[1])
        sent = dt.datetime.fromisoformat(receipt["sent_before_utc"][:26] + "+00:00")
        ok = (receipt["kind"] == "scn002_sender_receipt" and receipt["run_id"] == run_id
              and receipt["label"] == label and receipt["marker"] == MARKER and 1 <= local_port <= 65535
              and receipt["remote_endpoint"] == f"{config.receiver_ip}:{config.receiver_port}")
    except (UnicodeError, ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise CollectionError("probe_config_mismatch", "sender") from None
    if not ok:
        raise CollectionError("probe_config_mismatch", "sender")
    return Round(run_id, label, local_port, sent)


def preflight(config: Scn002LabConfig, runner: Runner) -> dict:
    return {"firewall_offset_ms": check_ntpq(runner, config.firewall, config.max_clock_offset_ms, "firewall"),
            "manager_leap": check_chrony(runner, config.manager, "manager"),
            "sender_offset_ms": check_w32tm(runner, config.sender, config.clock_reference_ip,
                                            config.max_clock_offset_ms, "sender")}


def select_sysmon3(raw: bytes, config: Scn002LabConfig, rnd: Round) -> list[bytes]:
    want = {"sourceIp": config.sender_ip, "sourcePort": str(rnd.source_port),
            "destinationIp": config.receiver_ip, "destinationPort": str(config.receiver_port)}
    picked = []
    for line in raw.splitlines(keepends=True):
        try:
            record = json.loads(line)
            win = record["data"]["win"]
            system, data = win["system"], win["eventdata"]
        except (ValueError, KeyError, TypeError):
            continue
        if (record.get("agent", {}).get("id") == config.sender_agent_id
                and system.get("providerName") == "Microsoft-Windows-Sysmon" and system.get("eventID") == "3"
                and all(data.get(k) == v for k, v in want.items())):
            picked.append(line)
    return picked


def select_eve(raw: bytes, config: Scn002LabConfig, rnd: Round) -> list[bytes]:
    needles = (f'"signature_id":{SURICATA_SID}'.encode(), f'"src_port":{rnd.source_port},'.encode(),
               f'"dest_port":{config.receiver_port},'.encode())
    return [l for l in raw.splitlines(keepends=True) if all(n in l for n in needles)]


def select_filterlog(raw: bytes, config: Scn002LabConfig, rnd: Round) -> list[bytes]:
    needles = (f",{config.block_rule_tracker},".encode(), b",block,",
               f",{config.sender_ip},{config.receiver_ip},{rnd.source_port},{config.receiver_port},".encode())
    return [l for l in raw.splitlines(keepends=True) if all(n in l for n in needles)][:1]


def select_alerts(raw: bytes, rnd: Round) -> list[bytes]:
    rule, run = f'"id":"{WAZUH_RULE}"'.encode(), f"run={rnd.run_id}".encode()
    return [l for l in raw.splitlines(keepends=True) if rule in l and run in l]


def expected_lines(label: str) -> dict[str, int]:
    base = {"sysmon3-archive.json": 1, "eve-alert.json": 1, "wazuh-alert.json": 1}
    return base | ({"filterlog.log": 1} if label == "block" else {})


def collect_evidence(config: Scn002LabConfig, rnd: Round, runner: Runner) -> dict[str, bytes]:
    port_token = quoted('"sourcePort":"' + str(rnd.source_port) + '"')
    found = {
        "sysmon3-archive.json": select_sysmon3(read(
            runner, config.manager, f"grep -F -- {port_token} {config.paths.archives}", "manager", grep=True),
            config, rnd),
        "eve-alert.json": select_eve(read(
            runner, config.firewall, f"grep -F -- {SURICATA_SID} {config.paths.eve_lan}", "firewall", grep=True),
            config, rnd),
        "wazuh-alert.json": select_alerts(read(
            runner, config.manager, f"grep -F -- {rnd.run_id} {config.paths.alerts}", "manager", grep=True), rnd),
    }
    if rnd.label == "block":
        found["filterlog.log"] = select_filterlog(read(
            runner, config.firewall, f"grep -F -- {config.block_rule_tracker} {config.paths.filterlog}",
            "firewall", grep=True), config, rnd)
    counts, expected = {k: len(v) for k, v in found.items()}, expected_lines(rnd.label)
    if counts != expected:
        raise CollectionError("unexpected_line_count", detail={"counts": counts, "expected": expected})
    return {name: b"".join(lines) for name, lines in found.items()}


def write_bundle(evidence: dict[str, bytes], config: Scn002LabConfig, rnd: Round, out: Path, *,
                 ingested_at: dt.datetime) -> dict:
    out = check_output(out)
    sent = rnd.sent_before.astimezone(dt.timezone.utc)
    start = sent.replace(second=0, microsecond=0) - dt.timedelta(minutes=1)
    end = start + dt.timedelta(minutes=3)
    stamp = ingested_at.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    suffix = rnd.run_id[:8]
    specs = [
        ("sysmon3-archive.json", "wazuh-sysmon3-archive-v1", "sysmon3", "Sender (Sysmon 3)",
         {"ingested_at": stamp, "collection_mode": "direct"}),
        ("eve-alert.json", "suricata-eve-jsonl-v1", "suricata-lan", "Suricata LAN",
         {"ingested_at": stamp, "sensor_id": "suricata-lan", "deployment_mode": "ids"}),
        ("filterlog.log", "pfsense-filterlog-bsd-ipv4-tcp-udp-v1", "pfsense-lan", "pfSense LAN filterlog",
         {"ingested_at": stamp, "sensor_id": "pfsense-lan", "source_year": sent.year,
          "source_utc_offset": config.firewall_utc_offset}),
        ("wazuh-alert.json", "wazuh-suricata-alert-v1", f"wazuh-{WAZUH_RULE}", f"Wazuh manager (rule {WAZUH_RULE})",
         {"ingested_at": stamp, "collection_mode": "direct"}),
    ]
    files = [{"path": name, "source_ref": f"{ref}-{suffix}", "display_label": label, "parser": parser,
              "sha256": hashlib.sha256(evidence[name]).hexdigest(), "context": context}
             for name, parser, ref, label, context in specs if name in evidence]
    context = {"run_id": f"scn002-{rnd.label}-{rnd.run_id}", "environment_id": config.environment_id,
               "start": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "end": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "bindings": [{"name": "sender_ip", "value": config.sender_ip},
                            {"name": "receiver_ip", "value": config.receiver_ip},
                            {"name": "receiver_port", "value": config.receiver_port},
                            {"name": "block_rule_tracker", "value": config.block_rule_tracker}],
               "declarations": []}
    inputs = {"bundle_schema_version": "0.1.0", "environment_id": config.environment_id, "files": files}
    payload = {f["path"]: evidence[f["path"]] for f in files}
    payload["inputs.json"] = (json.dumps(inputs, indent=2) + "\n").encode()
    payload["context.json"] = (json.dumps(context, indent=2) + "\n").encode()
    write_payload(out, payload)
    return {"kind": "collection", "scenario_id": "SCN-002", "run_id": context["run_id"], "label": rnd.label,
            "out": str(out), "source_port": rnd.source_port,
            "files": [{"path": f["path"], "sha256": f["sha256"]} for f in files],
            "validate": {"scenario": SCENARIO, "profile": PROFILE}}


def collect_round(config: Scn002LabConfig, probe_line: str, out: Path, runner: Runner, *,
                  now: Callable[[], dt.datetime], check_preflight: bool = True) -> dict:
    run_id, label = parse_probe_line(probe_line)
    checks = preflight(config, runner) if check_preflight else None
    rnd = read_receipt(config, run_id, label, runner)
    evidence = collect_evidence(config, rnd, runner)
    summary = write_bundle(evidence, config, rnd, out, ingested_at=now())
    summary["preflight"] = checks
    return summary
