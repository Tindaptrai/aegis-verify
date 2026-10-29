"""Read-only Linux boundary for the single disabled UFW wrapper exception.

Local package references are consistency anchors at the trusted-root OS boundary,
not independent package authenticity. No init, hook or mutating UFW command runs.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat

from .contracts import SetupError
from .transaction import digest
from .ufw import (RootFile, LIMIT, SUMS_PATH, FUNCTIONS_PATH, file_identity,
                  qualify_disabled_ufw, _same_record, _pairs)

RECORD_PATH = "/etc/aegis-wazuh-https/ufw-compat.json"
LOADER_KEYS = ("LoadState", "ActiveState", "UnitFileState")
LOADERS = ("nftables.service", "ufw.service", "firewalld.service")
GUARD = "aegis-wazuh-http-guard.service"
INDEXER = "wazuh-indexer.service"
DEPENDENCIES = ("Before", "After", "Requires", "Wants", "Requisite", "BindsTo",
                "PartOf", "Conflicts", "OnFailure", "OnSuccess", "Upholds")
# Ordered aliases only; no general resolve() of a root command or library path.
ALIASES = {"/lib": {"usr/lib", "/usr/lib"}, "/sbin": {"usr/sbin", "/usr/sbin"}}
for _name in ("iptables", "ip6tables"):
    ALIASES["/usr/sbin/" + _name] = {"/etc/alternatives/" + _name}
    ALIASES["/etc/alternatives/" + _name] = {"/usr/sbin/" + _name + "-nft"}
    ALIASES["/usr/sbin/" + _name + "-nft"] = {"xtables-nft-multi", "/usr/sbin/xtables-nft-multi"}


def _identity(info):
    return tuple(getattr(info, "st_" + k) for k in
                 ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"))


def _directory(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid or info.st_gid or info.st_mode & 0o7022:
        raise SetupError("path_untrusted")
    return tuple(getattr(info, "st_" + k) for k in ("dev", "ino", "mode", "uid", "gid"))


@contextmanager
def root_parent(path):
    """Hold each no-follow ancestor; verify its entry and descriptor on exit."""
    path = PurePosixPath(path)
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
        raise SetupError("path_untrusted")
    descriptors, links = [], []
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(fd)
        root_identity = _directory(os.fstat(fd))
        for name in path.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(child)
            links.append((fd, name, child, _directory(os.fstat(child))))
            fd = child
        yield fd, path.name
        if _directory(os.stat("/", follow_symlinks=False)) != root_identity:
            raise SetupError("state_changed")
        for parent, name, held, frozen in links:
            if (_directory(os.fstat(held)) != frozen or
                    _directory(os.stat(name, dir_fd=parent, follow_symlinks=False)) != frozen):
                raise SetupError("state_changed")
    except OSError:
        raise SetupError("path_untrusted") from None
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


class UfwHostReader:
    def __init__(self, host):
        self.host = host

    def root_file(self, path, limit):
        # Canonical paths have no symlinks. Alias reads are separate explicit gates.
        with root_parent(path) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd, "rb", buffering=0) as stream:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                        before.st_uid or before.st_gid or before.st_mode & 0o7022 or
                        not 0 < before.st_size <= limit):
                    raise SetupError("path_untrusted")
                body = stream.read(limit + 1)
                if (len(body) != before.st_size or _identity(before) != _identity(os.fstat(fd)) or
                        _identity(before) != _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))):
                    raise SetupError("state_changed")
                result = RootFile(str(path), body, before)
        return result

    def alias(self, path):
        if path not in ALIASES:
            raise SetupError("ufw_unsupported")
        with root_parent(path) as (parent, name):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISLNK(before.st_mode) or before.st_uid or before.st_gid or before.st_nlink != 1:
                raise SetupError("path_untrusted")
            target = os.readlink(name, dir_fd=parent)
            if target not in ALIASES[path]:
                raise SetupError("ufw_unsupported")
            if _identity(before) != _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)):
                raise SetupError("state_changed")
        return target

    def properties(self, unit, keys):
        return self.host.properties(unit, keys)

    def run(self, name, *args):
        return self.host.run(name, *args)

    def backend_identity(self, name):
        if name not in {"iptables", "ip6tables"}:
            raise SetupError("ufw_unsupported")
        paths = ("/sbin", "/usr/sbin/" + name, "/etc/alternatives/" + name, "/usr/sbin/" + name + "-nft")
        before = [self.alias(path) for path in paths]
        snapshot = self.root_file("/usr/sbin/xtables-nft-multi", 8 * LIMIT)
        identity = file_identity(snapshot, path=snapshot.canonical_path, limit=8 * LIMIT)
        if not identity["mode"] & 0o100:
            raise SetupError("ufw_unsupported")
        version = self.host.commands.run_selected(name, "--version")[0]
        if (before != [self.alias(path) for path in paths] or
                identity != file_identity(self.root_file(snapshot.canonical_path, 8 * LIMIT),
                                          path=snapshot.canonical_path, limit=8 * LIMIT)):
            raise SetupError("state_changed")
        return {"file": snapshot, "version": version}

    def validate_library_alias(self, wrapper):
        # Stock ufw-init sources /lib/ufw/ufw-init-functions. Require usr-merge;
        # the alias cannot redirect that source away from the frozen library.
        before = self.alias("/lib")
        actual = file_identity(self.root_file(FUNCTIONS_PATH, LIMIT), path=FUNCTIONS_PATH)
        if actual != wrapper["files"][FUNCTIONS_PATH] or self.alias("/lib") != before:
            raise SetupError("ufw_drift")

    def probe_identity(self, wrapper):
        path = "/usr/sbin/ufw"
        snapshot = self.root_file(path, LIMIT)
        identity = file_identity(snapshot, path=path)
        sums = self.root_file(SUMS_PATH, LIMIT)
        if (file_identity(sums, path=SUMS_PATH) != wrapper["files"][SUMS_PATH] or
                not identity["mode"] & 0o100 or not snapshot.body.startswith(b"#!/usr/bin/python3\n")):
            raise SetupError("ufw_unsupported")
        refs = {}
        try:
            for line in sums.body.decode("ascii").split("\n"):
                if not line:
                    continue
                match = re.fullmatch(r"([0-9a-f]{32})  ([-A-Za-z0-9_./]+)", line)
                if not match or match[2] in refs:
                    raise ValueError
                refs[match[2]] = match[1]
            reference = refs[path[1:]]
            if hashlib.md5(snapshot.body).hexdigest() != reference:
                raise ValueError
        except (ValueError, KeyError, UnicodeError):
            raise SetupError("ufw_unsupported") from None
        # Only after actual CLI provenance; Commands supplies bounded C-locale I/O.
        status = self.host.commands.run_selected("ufw", "status")[0]
        if status not in (b"Status: inactive", b"Status: inactive\n"):
            raise SetupError("ufw_unsupported")
        if (identity != file_identity(self.root_file(path, LIMIT), path=path) or
                file_identity(self.root_file(SUMS_PATH, LIMIT), path=SUMS_PATH) != wrapper["files"][SUMS_PATH]):
            raise SetupError("state_changed")
        return {"file": identity, "package_md5": reference}

    def dependency_facts(self):
        """Check the effective ordering closure plus proposed owned edges.

        Pin normalized UFW/Indexer relations only; unrelated loaded-unit inventory
        is boot-dependent. Rewalk the actual bounded graph for cycles every time.
        """
        graph, facts, pending = {}, {}, ["ufw.service", INDEXER, GUARD]
        if not self.host.guard_unit_present():
            # Before initial installation there is no effective guard to query.
            # The proposed edges below are still included in cycle validation.
            facts[GUARD] = {key: [] for key in DEPENDENCIES}
            graph[GUARD] = set()
        while pending:
            name = pending.pop()
            if name in facts:
                continue
            if len(facts) >= 512 or not re.fullmatch(r"[A-Za-z0-9_.@\\:-]+\.[a-z]+", name) or len(name) > 255:
                raise SetupError("ufw_unsupported")
            props = self.host.dependency_properties(name)
            if set(props) != set(DEPENDENCIES):
                raise SetupError("ufw_unsupported")
            current = {}
            for key in DEPENDENCIES:
                value = props[key]
                if type(value) is not str or len(value) > 65536:
                    raise SetupError("ufw_unsupported")
                words = value.split()
                if len(words) != len(set(words)) or len(words) > 512:
                    raise SetupError("ufw_unsupported")
                current[key] = sorted(words)
            facts[name] = current
            graph.setdefault(name, set())
            for other in current["Before"]:
                graph[name].add(other)
            for other in current["After"]:
                graph.setdefault(other, set()).add(name)
            pending.extend(other for values in current.values() for other in values)
            if sum(len(edges) for edges in graph.values()) > 8192:
                raise SetupError("ufw_unsupported")
        for name in (GUARD, INDEXER):
            if any("ufw.service" in facts[name][key] for key in DEPENDENCIES if key not in {"Before", "After"}):
                raise SetupError("ufw_unsupported")
            reachable, queue = set(), [name]
            while queue:
                unit = queue.pop()
                if unit in reachable:
                    continue
                reachable.add(unit)
                if unit == "ufw.service":
                    raise SetupError("ufw_unsupported")
                for key in ("Requires", "Wants", "BindsTo", "Upholds", "OnFailure", "OnSuccess"):
                    queue.extend(facts[unit][key])
        graph.setdefault("ufw.service", set()).update((GUARD, INDEXER))
        graph.setdefault(GUARD, set()).add(INDEXER)
        # Iterative topological sort: no recursion/depth guesses for a real graph.
        incoming = {name: 0 for name in graph}
        for edges in graph.values():
            for name in edges:
                incoming[name] = incoming.get(name, 0) + 1
        ready = [name for name, count in incoming.items() if not count]
        visited = 0
        while ready:
            name = ready.pop()
            visited += 1
            for child in graph.get(name, ()):
                incoming[child] -= 1
                if incoming[child] == 0:
                    ready.append(child)
        if visited != len(incoming):
            raise SetupError("ufw_unsupported")
        # Only the exact relations installed by our two units are normalized.
        result = {name: {key: list(value) for key, value in facts[name].items()} for name in ("ufw.service", INDEXER)}
        for key, other in (("Before", GUARD), ("Before", INDEXER)):
            result["ufw.service"][key] = [v for v in result["ufw.service"][key] if v != other]
        for key, other in (("After", GUARD), ("After", "ufw.service"), ("Requires", GUARD)):
            result[INDEXER][key] = [v for v in result[INDEXER][key] if v != other]
        return result


def strict_loaders(loaders):
    return (type(loaders) is dict and set(loaders) == set(LOADERS) and all(
        type(state) is dict and set(state) == set(LOADER_KEYS) and
        state["LoadState"] in {"loaded", "not-found", "masked"} and
        state["ActiveState"] in {"inactive", "failed"} and
        state["UnitFileState"] in {"disabled", "masked", ""} for state in loaders.values()))


def qualify_host(host, loaders, firewall):
    reader = host.ufw_reader()
    wrapper = qualify_disabled_ufw(reader, loaders)
    reader.validate_library_alias(wrapper)
    return {"wrapper": wrapper, "probe": reader.probe_identity(wrapper),
            "dependencies": reader.dependency_facts(), "foreign_firewall": firewall}


def compatibility_record(profile, fingerprint):
    return {"schema_version": 1, "profile_sha256": digest(profile.as_dict()), "fingerprint": fingerprint}


def validate_record(record, profile):
    if (type(record) is not dict or set(record) != {"schema_version", "profile_sha256", "fingerprint"} or
            type(record["schema_version"]) is not int or record["schema_version"] != 1 or
            record["profile_sha256"] != digest(profile.as_dict()) or
            type(record["fingerprint"]) is not dict or
            set(record["fingerprint"]) != {"wrapper", "probe", "dependencies", "foreign_firewall"}):
        raise SetupError("ufw_drift")


def read_record(host):
    parent = host.fs.trusted(PurePosixPath(RECORD_PATH).parent, missing=True)
    if parent is None:
        return None
    if not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700 or parent.st_gid:
        raise SetupError("path_untrusted")
    if host.fs.trusted(RECORD_PATH, missing=True, private=True) is None:
        return None
    snapshot = host.ufw_reader().root_file(RECORD_PATH, 8 * LIMIT)
    if stat.S_IMODE(snapshot.info.st_mode) != 0o600:
        raise SetupError("path_untrusted")
    try:
        result = json.loads(snapshot.body, object_pairs_hook=_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(result) is not dict or set(result) != {"schema_version", "profile_sha256", "fingerprint"}:
            raise ValueError
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise SetupError("ufw_drift") from None


def same_record(a, b):
    try:
        return _same_record(a, b)
    except (TypeError, ValueError, RecursionError):
        return False
