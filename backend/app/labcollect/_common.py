"""Shared pieces of the read-only lab collectors: config types, SSH, clock checks, bundle output."""

from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

HINTS = {
    "invalid_config": "Review the private collector config against the collector documentation.",
    "invalid_probe_line": "Paste the whole line the probe printed.",
    "probe_config_mismatch": "The probe or its receipt differs from the config; use the matching config.",
    "source_unreachable": "Check SSH reachability, the key, known_hosts and read access on that host.",
    "clock_not_synchronised": "Fix that host's clock before collecting (runbook section 0).",
    "honeypot_not_listening": "Start the honeypot before running the probe.",
    "unexpected_line_count": "Wait 30 s and collect again, or check the probe values; nothing was written.",
    "output_exists": "Choose a new, empty output directory.",
    "output_in_repository": "Write private evidence outside any Git working tree.",
}


class CollectionError(ValueError):
    """Safe diagnostic: a fixed code, a hint and at most one source name. Never lab values."""

    def __init__(self, code: str, source: str | None = None, detail: dict | None = None):
        if code not in HINTS:
            code = "invalid_config"
        super().__init__(code)
        self.code, self.source, self.detail = code, source, detail or {}

    def as_dict(self) -> dict:
        return {"kind": "error", "error": {"code": self.code, "source": self.source,
                                           "hint": HINTS[self.code], **self.detail}}


NAME = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
PosixPath = Field(pattern=r"^/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$", max_length=255)


class Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SshTarget(Closed):
    user: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    host: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
    jump: SshTarget | None = None

    def address(self) -> str:
        return f"{self.user}@{self.host}"


def no_dot_segments(value: str) -> str:
    if any(part in (".", "..") for part in value.split("/")):
        raise ValueError("dot segments are not allowed")
    return value


def canonical_ipv4(value: str) -> str:
    if str(ipaddress.IPv4Address(value)) != value:
        raise ValueError("canonical IPv4 required")
    return value


Runner = Callable[[SshTarget, str], tuple[int, bytes]]


def ssh_command(target: SshTarget, command: str, *, key_path: str, ssh: str = "ssh") -> list[str]:
    """Argument vector for OpenSSH; never a shell string on the local side."""
    if re.fullmatch(r"[A-Za-z0-9_:.\\/()~-]{1,260}", key_path) is None:
        raise CollectionError("invalid_config")
    base = [ssh, "-i", key_path, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR"]
    if target.jump is not None:
        base += ["-o", f"ProxyCommand={ssh} -i {key_path} -o BatchMode=yes -o StrictHostKeyChecking=yes "
                       f"-W %h:%p {target.jump.address()}"]
    return base + [target.address(), command]


def ssh_runner(key_path: str, *, ssh: str = "ssh", timeout: int = 300) -> Runner:
    def run(target: SshTarget, command: str) -> tuple[int, bytes]:
        try:
            done = subprocess.run(ssh_command(target, command, key_path=key_path, ssh=ssh),
                                  capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            return 255, b""
        return done.returncode, done.stdout
    return run


def read(runner: Runner, target: SshTarget, command: str, source: str, *, grep: bool) -> bytes:
    code, out = runner(target, command)
    if code == 0:
        return out
    if grep and code == 1:
        return b""
    raise CollectionError("source_unreachable", source)


def quoted(token: str) -> str:
    """Single-quote a grep token assembled only from validated pieces."""
    if re.fullmatch(r'[A-Za-z0-9":._-]{1,128}', token) is None:
        raise CollectionError("invalid_config")
    return "'" + token + "'"


def check_ntpq(runner: Runner, target: SshTarget, max_ms: int, source: str) -> float:
    peers = read(runner, target, "ntpq -pn", source, grep=False).decode("utf-8", "replace")
    selected = [line for line in peers.splitlines() if line.startswith("*")]
    try:
        offset = float(selected[0].split()[8]) if selected else None
    except (IndexError, ValueError):
        offset = None
    if offset is None or abs(offset) > max_ms:
        raise CollectionError("clock_not_synchronised", source)
    return offset


def check_chrony(runner: Runner, target: SshTarget, source: str) -> str:
    tracking = read(runner, target, "chronyc tracking", source, grep=False).decode("utf-8", "replace")
    if not re.search(r"^Leap status\s*:\s*Normal\s*$", tracking, re.MULTILINE):
        raise CollectionError("clock_not_synchronised", source)
    return "Normal"


def check_w32tm(runner: Runner, target: SshTarget, reference_ip: str, max_ms: int, source: str) -> float:
    out = read(runner, target, f"w32tm /stripchart /computer:{reference_ip} /samples:1 /dataonly",
               source, grep=False).decode("utf-8", "replace")
    found = re.findall(r",\s*([+-]\d+(?:\.\d+)?)s\s*$", out, re.MULTILINE)
    if not found or abs(float(found[-1]) * 1000) > max_ms:
        raise CollectionError("clock_not_synchronised", source)
    return round(float(found[-1]) * 1000, 3)


def check_output(out: Path) -> Path:
    out = Path(out).resolve()
    if any((parent / ".git").exists() for parent in (out, *out.parents)):
        raise CollectionError("output_in_repository")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise CollectionError("output_exists")
    return out


def write_payload(out: Path, payload: dict[str, bytes]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in payload.items():
        with (out / name).open("xb") as stream:
            stream.write(data)
