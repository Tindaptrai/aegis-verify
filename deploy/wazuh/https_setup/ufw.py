"""Read-only admission for one disabled-policy UFW vendor wrapper.

The reader owns bounded commands and held, no-follow reads beneath trusted root
directories (including explicit distro aliases). Local dpkg references establish
consistency at that OS trust boundary, not independent package authenticity.
This module never sources configuration, executes UFW, or changes host state.
"""
from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
from typing import Protocol

from .contracts import SetupError


@dataclass(frozen=True)
class RootFile:
    """Bytes and real fstat from one held, stable, no-follow regular-file read.

    The adapter must compare fstat before/after reading and the directory entry
    with the held descriptor, reject changes, and validate all ancestor paths.
    Canonical paths describe admitted aliases, never arbitrary resolve() output.
    The complete stat is admission evidence; only stable fields are persisted.
    """

    canonical_path: str
    body: bytes
    info: os.stat_result


class UfwReader(Protocol):
    """Trusted OS boundary; methods never invoke UFW or its hooks.

    backend_identity resolves the actually selected iptables/ip6tables alias
    through an explicit standard-distro allowlist, reads its held executable as
    a RootFile, and returns exactly {'file': RootFile, 'version': bytes}. The
    version bytes come from that selected tool's fixed --version invocation.
    properties returns exactly the requested systemctl scalar properties.
    run is limited to the dpkg-query and busctl argv emitted below.
    """
    def root_file(self, path: str, limit: int) -> RootFile: ...
    def properties(self, unit: str, keys: tuple[str, ...]) -> dict[str, str]: ...
    def run(self, name: str, *args: str) -> bytes: ...
    def backend_identity(self, name: str) -> dict: ...


VERSION = "0.36.2-6"
LIMIT = 1024 * 1024
UNIT_PATH = "/usr/lib/systemd/system/ufw.service"
INIT_PATH = "/usr/lib/ufw/ufw-init"
FUNCTIONS_PATH = "/usr/lib/ufw/ufw-init-functions"
DEFAULT_PATH = "/etc/default/ufw"
CONF_PATH = "/etc/ufw/ufw.conf"
SUMS_PATH = "/var/lib/dpkg/info/ufw.md5sums"

# SHA256 of the installed public files in the official Ubuntu archive package:
# https://archive.ubuntu.com/ubuntu/pool/main/u/ufw/ufw_0.36.2-6_all.deb
# package SHA256 096eb403ecaf6740d160bb306970f025222ef71324319cc1cb78d06dfa462ef1.
# These include the Debian optimize-boot patch and installed path substitutions.
# Hook hashes also match src/{before,after}.init in ufw_0.36.2.orig.tar.gz
# (archive SHA256 2a57a99eecef6b44db3537ed2520b30bae3759f8465456e22e404cd643838bf5).
VENDOR_SHA256 = {
    INIT_PATH: "c98f19dd0a68e94f729acdcba34fe48244dbfacdfa8943f257215d2ae351f80a",
    FUNCTIONS_PATH: "5865fbffc0c644d97e5fc6906c648ce6e4f23710ea0ff57c573ed680999d2cc4",
    UNIT_PATH: "efece4d41e747407ed7a02d217420cef9aa60ee84326a145de528400dc63419d",
    DEFAULT_PATH: "07db07bb07e5ac1388707b7c59dabfbce8ad06d5001236248fbf3f93b79c2ed7",
    "/etc/ufw/before.init": "a1936d13aadea73df4a8d91dfed3c0433467ab9da1c4f344a308c36e6a0559cf",
    "/etc/ufw/after.init": "1354ecc09be8b68eeb5d1d7b5f00af90bcbc6f53535b591546a6b4652ff5d807",
}
STATIC_PROPERTIES = {
    "Type": "oneshot", "RemainAfterExit": "yes", "User": "", "Group": "",
    "FragmentPath": UNIT_PATH, "DropInPaths": "", "RootDirectory": "",
    "RootImage": "", "PAMName": "",
}
RUNTIME_PROPERTIES = {
    "LoadState": "loaded", "ActiveState": "active", "SubState": "exited",
    "UnitFileState": "enabled", "NeedDaemonReload": "no", "Transient": "no",
}
PROPERTIES = (*STATIC_PROPERTIES, *RUNTIME_PROPERTIES)
EMPTY_ARRAYS = {
    "ExecCondition": "a(sasbttttuii)", "ExecStartPre": "a(sasbttttuii)",
    "ExecStartPost": "a(sasbttttuii)", "ExecStopPost": "a(sasbttttuii)",
    "ExecReload": "a(sasbttttuii)", "Environment": "as", "EnvironmentFiles": "a(sb)",
    "PassEnvironment": "as", "UnsetEnvironment": "as",
}
COMMANDS = {"ExecStart": [INIT_PATH, "start", "quiet"], "ExecStop": [INIT_PATH, "stop"]}


def file_identity(value: RootFile, *, path: str, limit: int = LIMIT) -> dict:
    """Validate a reader snapshot and select its stable, body-free identity."""
    if not isinstance(value, RootFile) or not isinstance(value.info, os.stat_result):
        raise SetupError("ufw_unsupported")
    info = value.info
    if (value.canonical_path != path or type(value.body) is not bytes or
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o7022 or
            info.st_size != len(value.body) or not 0 < info.st_size <= limit):
        raise SetupError("ufw_unsupported")
    return {"path": path, "sha256": hashlib.sha256(value.body).hexdigest(),
            "uid": info.st_uid, "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode), "size": info.st_size}


def _disabled_config(body):
    # Shell token whitespace is space/tab/newline, not Unicode str.strip() or
    # splitlines(). CR, BOM, VT and non-ASCII can change the executed shell text.
    text = body.decode("ascii")
    if any(ord(c) < 32 and c not in "\t\n" for c in text) or "\x7f" in text:
        raise ValueError
    values = {}
    for line in text.split("\n"):
        line = line.strip(" \t")
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(ENABLED|LOGLEVEL)=([a-z]+)(?:[ \t]+#[^\n]*)?", line)
        if not match or match[1] in values:
            raise ValueError
        values[match[1]] = match[2]
    if (set(values) != {"ENABLED", "LOGLEVEL"} or values["ENABLED"] != "no" or
            values["LOGLEVEL"] not in {"off", "low", "medium", "high", "full"}):
        raise ValueError


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _bus(reader, key, signature):
    # Closed property allowlist: caller cannot select a unit, interface or method.
    allowed = {**EMPTY_ARRAYS, "ExecStartEx": "a(sasasttttuii)",
               "ExecStopEx": "a(sasasttttuii)", "Job": "(uo)"}
    if allowed.get(key) != signature:
        raise ValueError
    interface = "Unit" if key == "Job" else "Service"
    raw = reader.run("busctl", "--system", "--json=short", "get-property",
                     "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/ufw_2eservice",
                     "org.freedesktop.systemd1." + interface, key)
    if type(raw) is not bytes or len(raw) > 65536:
        raise ValueError
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if (type(value) is not dict or set(value) != {"type", "data"} or
            value["type"] != signature or type(value["data"]) is not list):
        raise ValueError
    return value["data"]


def _unit(reader):
    expected = {**STATIC_PROPERTIES, **RUNTIME_PROPERTIES}
    props = reader.properties("ufw.service", PROPERTIES)
    if type(props) is not dict or props != expected:
        raise ValueError
    job = _bus(reader, "Job", "(uo)")
    if len(job) != 2 or type(job[0]) is not int or job != [0, "/"]:
        raise ValueError
    facts = dict(STATIC_PROPERTIES)
    for key, signature in EMPTY_ARRAYS.items():
        if _bus(reader, key, signature) != []:
            raise ValueError
        facts[key] = []
    for key, argv in COMMANDS.items():
        data = _bus(reader, key + "Ex", "a(sasasttttuii)")
        if (len(data) != 1 or type(data[0]) is not list or len(data[0]) != 10 or
                data[0][:3] != [INIT_PATH, argv, []] or
                any(type(n) is not int for n in data[0][3:]) or
                any(not 0 <= n < 2**64 for n in data[0][3:7]) or
                not 0 <= data[0][7] < 2**32 or
                any(not -(2**31) <= n < 2**31 for n in data[0][8:])):
            raise ValueError
        facts[key] = list(argv)
    return facts


def _loaders(value):
    if type(value) is not dict or set(value) != {"ufw.service", "nftables.service", "firewalld.service"}:
        raise ValueError
    for name, state in value.items():
        if type(state) is not dict or set(state) != {"LoadState", "ActiveState", "UnitFileState"}:
            raise ValueError
        if name == "ufw.service":
            if state != {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled"}:
                raise ValueError
        elif (state["LoadState"] not in {"loaded", "not-found", "masked"} or
              state["ActiveState"] not in {"inactive", "failed"} or
              state["UnitFileState"] not in {"disabled", "masked", ""}):
            raise ValueError


def _package(reader, snapshots):
    raw = reader.run("dpkg-query", "-W", "-f=${db:Status-Status}\n${Version}\n${Conffiles}\n", "ufw")
    if type(raw) is not bytes or len(raw) > 65536:
        raise ValueError
    lines = raw.decode("ascii").split("\n")
    if lines[:2] != ["installed", VERSION]:
        raise ValueError
    conffiles = {}
    for line in lines[2:]:
        if not line:
            continue
        match = re.fullmatch(r" (/[-A-Za-z0-9_./]+) ([0-9a-f]{32})", line)
        if not match or match[1] in conffiles:
            raise ValueError
        conffiles[match[1]] = match[2]
    refs = {}
    for line in snapshots[SUMS_PATH].body.decode("ascii").split("\n"):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{32})  ([-A-Za-z0-9_./]+)", line)
        if not match or match[2].startswith("/") or match[2] in refs:
            raise ValueError
        refs[match[2]] = match[1]
    wanted = {}
    for path in (INIT_PATH, FUNCTIONS_PATH, UNIT_PATH, DEFAULT_PATH):
        reference = conffiles.get(path) if path == DEFAULT_PATH else refs.get(path[1:])
        if reference != hashlib.md5(snapshots[path].body).hexdigest():
            raise ValueError
        wanted[path] = reference
    return wanted


def _backends(reader):
    result = {}
    for name in ("iptables", "ip6tables"):
        value = reader.backend_identity(name)
        if type(value) is not dict or set(value) != {"file", "version"}:
            raise ValueError
        identity = file_identity(value["file"], path="/usr/sbin/xtables-nft-multi", limit=8 * LIMIT)
        if not identity["mode"] & 0o100 or type(value["version"]) is not bytes:
            raise ValueError
        match = re.fullmatch(name.encode() + rb" v([0-9]+\.[0-9]+\.[0-9]+) \(nf_tables\)\n?", value["version"])
        if not match:
            raise ValueError
        result[name] = {"file": identity, "backend": "nf_tables", "version": match[1].decode("ascii")}
    if result["iptables"] != result["ip6tables"]:
        raise ValueError
    return result


def qualify_disabled_ufw(reader: UfwReader, loader_state: dict) -> dict:
    """Return a closed static fingerprint; refuse unsupported/unknown evidence.

    loader_state is the complete existing three-loader inventory. The caller
    independently captures the complete current nft ruleset; CLI status is never
    used as evidence of an empty firewall. Reader trusted-I/O SetupErrors retain
    their codes. No exception detail or configuration body crosses this API.
    """
    try:
        _loaders(loader_state)
        snapshots, files = {}, {}
        for path in (*VENDOR_SHA256, CONF_PATH, SUMS_PATH):
            value = reader.root_file(path, LIMIT)
            identity = file_identity(value, path=path)
            if path in VENDOR_SHA256 and identity["sha256"] != VENDOR_SHA256[path]:
                raise ValueError
            if path.endswith(".init") and identity["mode"] & 0o111:
                raise ValueError
            if path in {CONF_PATH, DEFAULT_PATH, SUMS_PATH} and identity["mode"] & 0o111:
                raise ValueError
            if path == INIT_PATH and not identity["mode"] & 0o100:
                raise ValueError
            snapshots[path], files[path] = value, identity
        _disabled_config(snapshots[CONF_PATH].body)
        refs = _package(reader, snapshots)
        unit = _unit(reader)
        unit["package_references"] = refs
        return {"schema_version": 1, "package_version": VERSION, "files": files,
                "unit": unit, "backends": _backends(reader)}
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise SetupError("ufw_unsupported") from None


def verify_disabled_ufw(reader: UfwReader, loader_state: dict, expected: dict) -> None:
    """Always requalify current eligibility and compare the complete pinned record.

    The complete typed comparison rejects partial/unknown fields, tuple arrays
    and Python's bool==int equality. No record is refreshed or returned.
    """
    current = qualify_disabled_ufw(reader, loader_state)
    try:
        if not _same_record(expected, current):
            raise ValueError
    except (ValueError, TypeError, RecursionError):
        raise SetupError("ufw_drift") from None


def _same_record(expected, current):
    if type(expected) is not type(current):
        return False
    if type(current) is dict:
        return (all(type(k) is str for k in expected) and set(expected) == set(current) and
                all(_same_record(expected[k], v) for k, v in current.items()))
    if type(current) is list:
        return len(expected) == len(current) and all(_same_record(a, b) for a, b in zip(expected, current))
    return expected == current
