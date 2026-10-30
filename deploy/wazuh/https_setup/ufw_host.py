"""Read-only Linux boundary for the single disabled UFW wrapper exception.

Local package references are consistency anchors at the trusted-root OS boundary,
not independent package authenticity. No init, hook or mutating UFW command runs.
"""
from contextlib import contextmanager
import math
import json
import os
from pathlib import PurePosixPath
import re
import stat

from .contracts import SetupError
from .transaction import digest
from .ufw import (RootFile, LIMIT, FUNCTIONS_PATH, file_identity,
                  qualify_disabled_ufw, _same_record, _pairs)

RECORD_PATH = "/etc/aegis-wazuh-https/ufw-compat.json"
LOADER_KEYS = ("LoadState", "ActiveState", "UnitFileState")
LOADERS = ("nftables.service", "ufw.service", "firewalld.service")
GUARD = "aegis-wazuh-http-guard.service"
INDEXER = "wazuh-indexer.service"
DEPENDENCIES = ("Before", "After", "Requires", "Wants", "Requisite", "BindsTo",
                "PartOf", "Conflicts", "ConflictedBy", "OnFailure", "OnSuccess", "Upholds",
                "RequiredBy", "RequisiteOf", "BoundBy", "ConsistsOf",
                "PropagatesStopTo", "StopPropagatedFrom")
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
        # Conservative operation effects for this bounded relationship model,
        # not a systemd job simulator. In particular activation can stop a
        # conflicting unit; that stop can propagate or activate completion units.
        # Read both effective conflict directions (ConflictedBy is implicit).
        activating = {name: set() for name in facts}
        restarting = {name: set() for name in facts}
        stopping = {name: set() for name in facts}
        conflicts = {name: set() for name in facts}
        for name, relations in facts.items():
            for key in ("Requires", "Wants", "BindsTo", "Upholds", "OnFailure", "OnSuccess"):
                activating[name].update(relations[key])
            for key in ("RequiredBy", "BoundBy"):
                for dependent in relations[key]:
                    activating[dependent].add(name)
            for key in ("Requires", "Requisite", "BindsTo", "PartOf"):
                for source in relations[key]:
                    restarting[source].add(name)
            for key in ("RequiredBy", "RequisiteOf", "BoundBy", "ConsistsOf"):
                restarting[name].update(relations[key])
            stopping[name].update(relations["PropagatesStopTo"])
            for source in relations["StopPropagatedFrom"]:
                stopping[source].add(name)
            for key in ("Conflicts", "ConflictedBy"):
                for other in relations[key]:
                    conflicts[name].add(other)
                    conflicts[other].add(name)
        for name in facts:
            stopping[name].update(restarting[name])
        if any(sum(len(edges) for edges in model.values()) > 8192
               for model in (activating, restarting, stopping, conflicts)):
            raise SetupError("ufw_unsupported")
        for name in (GUARD, INDEXER):
            # Preserve direct unsupported requirements as well as the composed
            # effects below; Requisite/PartOf do not themselves start a unit.
            if any("ufw.service" in facts[name][key] for key in
                   ("Requires", "Wants", "Requisite", "BindsTo", "PartOf",
                    "Conflicts", "ConflictedBy", "OnFailure", "OnSuccess", "Upholds")):
                raise SetupError("ufw_unsupported")
            # At most three effects per observed unit. Restart propagates to
            # dependents, but an explicit/conflict stop must not invent a restart.
            reachable, queue = set(), [(name, "restart")]
            while queue:
                unit, effect = queue.pop()
                if (unit, effect) in reachable:
                    continue
                reachable.add((unit, effect))
                if unit == "ufw.service":
                    raise SetupError("ufw_unsupported")
                if effect == "restart":
                    queue.extend(((unit, "start"), (unit, "stop")))
                    queue.extend((other, "restart") for other in restarting[unit])
                elif effect == "start":
                    queue.extend((other, "start") for other in activating[unit])
                    queue.extend((other, "stop") for other in conflicts[unit])
                else:
                    queue.extend((other, "stop") for other in stopping[unit])
                    for key in ("OnSuccess", "OnFailure"):
                        queue.extend((other, "start") for other in facts[unit][key])
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


def decode_nft_json(raw):
    """Reject ambiguous/truncated command output before any consumer sees it."""
    def finite_number(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError
        return number
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 4 * LIMIT:
            raise ValueError
        document = json.loads(raw, object_pairs_hook=_pairs, parse_float=finite_number,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(document) is not dict or set(document) != {"nftables"} or type(document["nftables"]) is not list:
            raise ValueError
        return document
    except (ValueError, UnicodeError, RecursionError):
        raise SetupError("firewall_mismatch") from None


def validate_nft_observation(document):
    """Narrow complete-output shape, not an nft expression/policy evaluator.

    Only ordinary tables/chains/rules are initially qualified. Statements are
    preserved, not interpreted; stable_firewall still refuses dynamic state.
    Output metainfo and handles follow libnftables-json(5), schema version 1.
    """
    def name(value, *, limit=255, empty=False):
        if (type(value) is not str or not empty and not value or
                len(value.encode("utf-8")) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError
    def handle(value):
        if type(value) is not int or not 0 < value < 2**64:
            raise ValueError
    try:
        if (type(document) is not dict or set(document) != {"nftables"} or
                type(document["nftables"]) is not list or not 1 <= len(document["nftables"]) <= 16384):
            raise ValueError
        # Also validate synthetic/object callers: nonfinite values and excessive
        # nesting must not become absence evidence or exhaust recursive cleaning.
        pending, count = [(document, 0)], 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if depth > 64 or count > 131072:
                raise ValueError
            if type(value) is dict:
                if any(type(key) is not str for key in value):
                    raise ValueError
                pending.extend((item, depth + 1) for item in value.values())
            elif type(value) is list:
                pending.extend((item, depth + 1) for item in value)
            elif type(value) is float:
                if not math.isfinite(value):
                    raise ValueError
            elif type(value) not in (str, int, bool, type(None)):
                raise ValueError
        tables, chains, handles, references = set(), set(), set(), []
        for position, obj in enumerate(document["nftables"]):
            if type(obj) is not dict or len(obj) != 1:
                raise ValueError
            kind, body = next(iter(obj.items()))
            if type(body) is not dict:
                raise ValueError
            if position == 0:
                if (kind != "metainfo" or set(body) != {"version", "release_name", "json_schema_version"} or
                        type(body["json_schema_version"]) is not int or body["json_schema_version"] != 1):
                    raise ValueError
                name(body["version"], limit=128)
                name(body["release_name"], limit=128)
                continue
            required = {"family", "handle"}
            if kind == "table":
                required |= {"name"}
                optional = {"comment"}
            elif kind == "chain":
                required |= {"table", "name"}
                optional = {"type", "hook", "prio", "policy", "dev", "comment"}
            elif kind == "rule":
                required |= {"table", "chain", "expr"}
                optional = {"comment"}
            else:
                raise ValueError
            if not required <= set(body) or set(body) - required - optional:
                raise ValueError
            if body["family"] not in {"ip", "ip6", "inet", "arp", "bridge", "netdev"}:
                raise ValueError
            handle(body["handle"])
            for key in ("name", "table", "chain", "dev"):
                if key in body:
                    name(body[key])
            if "comment" in body:
                name(body["comment"], limit=256, empty=True)
            family = body["family"]
            identity = (kind, family, body.get("table"), body["handle"])
            if identity in handles:
                raise ValueError
            handles.add(identity)
            if kind == "table":
                key = (family, body["name"])
                if key in tables:
                    raise ValueError
                tables.add(key)
            elif kind == "chain":
                key = (family, body["table"], body["name"])
                if key in chains or body["name"].startswith(("ufw-", "ufw6-")):
                    raise ValueError
                chains.add(key)
                references.append(("table", key[:2]))
                base = {"type", "hook", "prio", "policy"}
                if base.intersection(body) or "dev" in body:
                    if (not base <= set(body) or body["type"] not in {"filter", "nat", "route"} or
                            body["hook"] not in {"prerouting", "input", "forward", "output", "postrouting", "ingress", "egress"} or
                            type(body["prio"]) is not int or not -(2**31) <= body["prio"] < 2**31 or
                            body["policy"] not in {"accept", "drop"} or family == "netdev" and "dev" not in body):
                        raise ValueError
            else:
                references.append(("chain", (family, body["table"], body["chain"])))
                if (type(body["expr"]) is not list or not body["expr"] or
                        any(type(statement) is not dict or len(statement) != 1 for statement in body["expr"])):
                    raise ValueError
                for statement in body["expr"]:
                    name(next(iter(statement)))
        if any(key not in (tables if kind == "table" else chains) for kind, key in references):
            raise ValueError
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise SetupError("ufw_unsupported") from None


def qualify_host(host, loaders, firewall=None):
    reader = host.ufw_reader()
    wrapper = qualify_disabled_ufw(reader, loaders)
    reader.validate_library_alias(wrapper)
    dependencies = reader.dependency_facts()
    # Always take the observation internally, after wrapper/backend qualification.
    # A caller's earlier dump is comparison evidence, never proof of absence.
    observation = host.firewall()
    validate_nft_observation(observation)
    current = host.foreign_firewall(observation)
    if firewall is not None and not same_record(firewall, current):
        raise SetupError("state_changed")
    after = qualify_disabled_ufw(reader, host.firewall_loaders())
    reader.validate_library_alias(after)
    if not same_record(wrapper, after) or not same_record(dependencies, reader.dependency_facts()):
        raise SetupError("state_changed")
    return {"wrapper": wrapper, "probe": {"method": "nft-no-ufw-chains-v1"},
            "dependencies": dependencies, "foreign_firewall": current}


def compatibility_record(profile, fingerprint):
    return {"schema_version": 1, "profile_sha256": digest(profile.as_dict()), "fingerprint": fingerprint}


def validate_record(record, profile):
    if (type(record) is not dict or set(record) != {"schema_version", "profile_sha256", "fingerprint"} or
            type(record["schema_version"]) is not int or record["schema_version"] != 1 or
            record["profile_sha256"] != digest(profile.as_dict()) or
            type(record["fingerprint"]) is not dict or
            set(record["fingerprint"]) != {"wrapper", "probe", "dependencies", "foreign_firewall"} or
            not same_record(record["fingerprint"]["probe"], {"method": "nft-no-ufw-chains-v1"})):
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
