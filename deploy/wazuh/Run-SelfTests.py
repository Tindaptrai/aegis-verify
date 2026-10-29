#!/usr/bin/env python3
"""Explicit operator-only qualification; portable results never imply native proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
PORTABLE = ("deploy.wazuh.tests.test_components", "deploy.wazuh.tests.test_transaction",
            "deploy.wazuh.tests.test_runner", "deploy.wazuh.tests.test_ufw")
NATIVE_MODULE = "deploy.wazuh.tests.test_native"
REQUIRED_NATIVE = tuple(NATIVE_MODULE + ".NativeTests." + name for name in (
    "test_openssl_signing_and_tls", "test_securefs_permissions_nofollow_and_inode",
    "test_journal_fsync_and_process_lock", "test_renameat2_publication_and_refusal",
    "test_publication_races_preserve_evidence", "test_nft_allowed_denied_sources",
    "test_systemd_every_start_guard", "test_ufw_disabled_wrapper_preserved"))


class ProofResult(unittest.TextTestResult):
    """Record IDs only: tracebacks/command output never enter the public proof."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes = {}

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes.setdefault(test.id(), "passed")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes[test.id()] = "failed"

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes[test.id()] = "error"

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes[test.id()] = "skipped"

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.outcomes[test.id()] = "failed"


def required_results(result, required):
    return {name: result.outcomes.get(name, "missing") for name in required}


def qualified(result, required):
    return (result.wasSuccessful() and not result.skipped and
            all(value == "passed" for value in required_results(result, required).values()))


def platform_errors(*, native, system=None):
    if not native:
        return []
    errors = []
    if (system or platform.system()) != "Linux":
        return ["linux_required"]
    if sys.version_info[:2] != (3, 12):
        errors.append("python312_required")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        errors.append("root_required")
    if not Path("/run/systemd/system").is_dir():
        errors.append("systemd_required")
    for tool in ("openssl", "nft", "ip", "systemctl", "systemd-analyze", "busctl", "ldd", "iptables", "ip6tables"):
        if not shutil.which(tool):
            errors.append(tool.replace("-", "_") + "_required")
    return errors


def proof_scope(*, native):
    return {"intended_scope": "synthetic_linux" if native else "portable",
            "vendor_lab_acceptance": False,
            "systemd_fixture_relocations": UFW_RELOCATIONS if native else []}


def source_snapshot(commit):
    """Compare executed bytes to Git blobs, including the gate itself."""
    from deploy.wazuh.https_setup.host import KIT_FILES
    if not re.fullmatch("[0-9a-f]{40}", commit or ""):
        raise ValueError("source_commit_required")
    prefix = "deploy/wazuh/"
    names = [prefix + name for name in KIT_FILES]
    names += [prefix + "Run-SelfTests.py", *(prefix + "tests/" + name + ".py" for name in
              ("test_components", "test_transaction", "test_runner", "test_native", "test_ufw")),
              ".github/workflows/wazuh-http-operator.yml", "docs/manager/wazuh-http-preparation.md"]
    def git(*args):
        return subprocess.run(["git", "-c", "safe.directory=" + str(ROOT), *args], cwd=ROOT,
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=20).stdout
    if git("rev-parse", "HEAD").decode().strip() != commit:
        raise ValueError("source_head_mismatch")
    hashes = {}
    for name in names:
        blob = git("show", commit + ":" + name)
        current = (ROOT / name).read_bytes()
        if blob != current:
            raise ValueError("source_bytes_mismatch")
        hashes[name] = hashlib.sha256(blob).hexdigest()
    return {"source_commit": commit, "files": hashes}


UFW_RELOCATIONS = ["owned_root:vendor_paths", "owned_units:wrapper_guard_indexer",
                   "wrapper:RootDirectory,NetworkNamespacePath", "host.INSTALL_ROOT", "host.PROFILE",
                   "host.RECORD_PATH", "ufw_host.RECORD_PATH", "loader_query:owned_inactive_inventory",
                   "dependency_roles:bijective_all_observed_units_readonly_external", "positive_reader:synthetic_package_unit_backend_dependencies",
                   "fixture.Commands:root_netns_before_each_execute",
                   "probe_root/dev/null:real_device_bind_in_child_private_mount_namespace"]
UFW_CHECKS = ("vendor_bytes_preserved", "vendor_state_preserved", "real_ufw_baseline_preserved",
              "namespace_assertion_before_mutations", "no_unintended_wrapper_start", "cold_guard_verified",
              "active_guard_verified", "concurrent_start_order_verified", "concurrent_stop_order_verified",
              "guard_stop_retained_table", "foreign_rules_preserved", "native_file_reads_verified",
              "native_typed_bus_verified", "native_modified_unit_refused", "native_backends_verified",
              "fresh_nft_observation_preserved", "ufw_lock_absent_preserved", "ufw_lock_present_preserved",
              "partial_ufw_chains_refused", "synthetic_positive_admission_verified",
              "enabled_policy_refused", "static_record_drift_refused", "deleted_table_refused", "modified_table_refused")
UFW_OPERATIONS = ("cold_guard", "concurrent_start", "normal_stop", "normal_restart",
                  "systemd_reload_refused", "direct_restart", "direct_force_reload", "active_guard_restart",
                  "concurrent_stop_start")


def validate_native_observations(observations):
    """Shared runner/CI/private-assembler boundary; missing proof never qualifies."""
    def require(condition):
        if not condition:
            raise ValueError("native_observation_invalid")
    def sha(value):
        return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    require(type(observations) is dict)
    prefix = NATIVE_MODULE + ".NativeTests."
    for method in ("test_nft_allowed_denied_sources", "test_systemd_every_start_guard", "test_ufw_disabled_wrapper_preserved"):
        item = observations.get(prefix + method, {})
        require(type(item) is dict)
        require(sha(item.get("host_firewall_before_sha256")))
        require(item.get("host_firewall_before_sha256") == item.get("host_firewall_after_sha256"))
        require(item.get("fixture_cleanup_verified") is True)
    strict = observations[prefix + "test_systemd_every_start_guard"]
    require(strict.get("loader_scope") == "owned_namespace_inventory_not_host_eligibility" and strict.get("strict_path_exception_not_used") is True)
    from deploy.wazuh.https_setup.ufw_host import LOADERS
    mapping = strict.get("loader_query_mapping", {})
    require(type(mapping) is dict and set(mapping) == set(LOADERS) and len(set(mapping.values())) == 3)
    for role, unit in mapping.items():
        require(re.fullmatch(r"aegis-native-[0-9a-f]{12}-loader-" + role.split(".")[0] + r"\.service", unit) is not None)
    require(strict.get("loader_facts") == {role: {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"} for role in LOADERS})
    from deploy.wazuh.tests.test_ufw import VENDOR
    item = observations[prefix + "test_ufw_disabled_wrapper_preserved"]
    require(set(item) == {"host_firewall_before_sha256", "host_firewall_after_sha256", "fixture_cleanup_verified",
                         "vendor_deb_sha256", "vendor_inputs", "relocations", "checks", "operations",
                         "scope", "unit_mapping", "dependency_cases", "preservation_hashes", "native_adapter", "nft_observations"})
    require(item["vendor_deb_sha256"] == "096eb403ecaf6740d160bb306970f025222ef71324319cc1cb78d06dfa462ef1")
    require(item["vendor_inputs"] == {path: hashlib.sha256(body).hexdigest() for path, body in VENDOR.items()})
    require(item["relocations"] == UFW_RELOCATIONS)
    require(item["scope"] == {"native": "vendor_lifecycle_packets_order_and_adapter_refusal",
                              "positive_admission": "synthetic_reader", "probe": "nft-no-ufw-chains-v1",
                              "owner_full_class_check": "pending", "vendor_lab_acceptance": False})
    require(item["scope"]["vendor_lab_acceptance"] is False)
    require(type(item["checks"]) is dict and set(item["checks"]) == set(UFW_CHECKS))
    require(all(value is True for value in item["checks"].values()))
    require(type(item["operations"]) is dict and set(item["operations"]) == set(UFW_OPERATIONS))
    require(all(value == {"allowed": True, "denied": True, "table": True, "foreign": True} and
                all(type(v) is bool for v in value.values()) for value in item["operations"].values()))
    require(set(item["preservation_hashes"]) == {"vendor", "foreign", "real_ufw", "fresh_nft"})
    for pair in item["preservation_hashes"].values():
        require(type(pair) is dict and set(pair) == {"before", "after"} and sha(pair["before"]) and pair["before"] == pair["after"])
    mapping = item["unit_mapping"]
    require(type(mapping) is dict and set(mapping) == {"ufw.service", "wazuh-indexer.service", "aegis-wazuh-http-guard.service"})
    require(len(set(mapping.values())) == 3 and all(re.fullmatch(r"aegis-native-[0-9a-f]{12}-(wrapper|ufw-indexer|ufw-guard)\.service", v) for v in mapping.values()))
    adapter = item["native_adapter"]
    from deploy.wazuh.https_setup import ufw
    require(type(adapter) is dict and set(adapter) == {"unit_properties", "typed_bus", "backend_sha256"})
    require(sha(adapter["backend_sha256"]))
    properties = adapter["unit_properties"]
    expected = {**ufw.STATIC_PROPERTIES, **ufw.RUNTIME_PROPERTIES,
                "FragmentPath": "/run/systemd/system/" + mapping["ufw.service"],
                "RootDirectory": "<owned_vendor_root>", "UnitFileState": "disabled"}
    require(properties == expected)
    bus = adapter["typed_bus"]
    require(set(bus) == set(ufw.EMPTY_ARRAYS) | {"ExecStartEx", "ExecStopEx", "Job"})
    require(bus["Job"] == {"type": "(uo)", "data": [0, "/"]} and type(bus["Job"]["data"][0]) is int)
    for key, signature in ufw.EMPTY_ARRAYS.items():
        require(bus[key] == {"type": signature, "data": []})
    for key, args in (("ExecStartEx", ["start", "quiet"]), ("ExecStopEx", ["stop"])):
        value = bus[key]
        require(set(value) == {"type", "data"} and value["type"] == "a(sasasttttuii)")
        require(type(value["data"]) is list and len(value["data"]) == 1)
        row = value["data"][0]
        require(type(row) is list and len(row) == 10 and row[:3] == [ufw.INIT_PATH, [ufw.INIT_PATH, *args], []])
        require(all(type(n) is int for n in row[3:]))
        require(all(0 <= n < 2**64 for n in row[3:7]) and 0 <= row[7] < 2**32 and
                all(-(2**31) <= n < 2**31 for n in row[8:]))
    from deploy.wazuh.https_setup.ufw_host import validate_nft_observation
    from deploy.wazuh.https_setup.contracts import SetupError
    from deploy.wazuh.https_setup.transaction import digest
    nft = item["nft_observations"]
    require(type(nft) is dict and set(nft) == {"empty", "foreign", "ufw-partial", "ufw6-partial"})
    for name, observed in nft.items():
        require(type(observed) is dict and set(observed) == {"document", "before_sha256", "after_sha256", "refused", "absent_lock_preserved", "present_lock_preserved", "resources"})
        resources = observed["resources"]
        isolation = {"child_mount_namespace_distinct", "recursive_private", "parent_namespace_unchanged",
                     "parent_target_unchanged", "parent_mounts_unchanged", "child_bind_released"}
        require(type(resources) is dict and set(resources) == isolation | {
            "stage", "euid", "source", "target_before", "target_bound", "nodev", "open_errno"})
        require(resources["stage"] == "complete" and type(resources["euid"]) is int and resources["euid"] == 0)
        require(all(resources[key] is True for key in isolation))
        for key in ("source", "target_before", "target_bound"):
            device = resources[key]
            require(type(device) is dict and set(device) == {"type", "mode", "uid", "gid", "rdev"})
            require(type(device["uid"]) is int and type(device["gid"]) is int and device["uid"] == device["gid"] == 0)
            require(type(device["mode"]) is int and 0 <= device["mode"] <= 0o7777)
            require(type(device["rdev"]) is list and all(type(n) is int for n in device["rdev"]))
            require(device["type"] == ("regular" if key == "target_before" else "char"))
            require(device["rdev"] == ([0, 0] if key == "target_before" else [1, 3]))
        require(resources["target_before"]["mode"] == 0o600 and resources["source"] == resources["target_bound"])
        require(type(resources["nodev"]) is dict and set(resources["nodev"]) == {"source", "target_before", "target_bound"})
        require(all(type(value) is bool for value in resources["nodev"].values()))
        require(resources["nodev"]["source"] is False and resources["nodev"]["target_bound"] is False)
        require(type(resources["open_errno"]) is dict and set(resources["open_errno"]) == {"source", "bound", "chroot"})
        require(all(type(value) is int and value == 0 for value in resources["open_errno"].values()))
        require(observed["absent_lock_preserved"] is True and observed["present_lock_preserved"] is True)
        require(sha(observed["before_sha256"]) and observed["before_sha256"] == observed["after_sha256"] == digest(observed["document"]))
        require(observed["refused"] is name.endswith("partial"))
        try:
            validate_nft_observation(observed["document"])
        except SetupError:
            require(name.endswith("partial"))
        else:
            require(not name.endswith("partial"))
        require(type(observed["document"]) is dict and set(observed["document"]) == {"nftables"})
        objects = observed["document"]["nftables"]
        require(type(objects) is list and all(type(obj) is dict and len(obj) == 1 and type(next(iter(obj.values()))) is dict for obj in objects))
        if name.endswith("partial"):
            removed = [obj for obj in objects if obj.get("chain", {}).get("name") == name]
            require(len(removed) == 1)
            try:
                validate_nft_observation({"nftables": [obj for obj in objects if obj not in removed]})
            except SetupError:
                require(False)
        require(len(objects) == (1 if name == "empty" else 4 if name == "foreign" else 5))
        # The only exported kernel objects are this closed synthetic fixture.
        for obj in objects[1:]:
            kind, body = next(iter(obj.items()))
            require(kind in {"table", "chain", "rule"} and body["family"] == "inet")
            require((body["name"] if kind == "table" else body["table"]) == "aegis_fixture_foreign")
            if kind == "chain":
                require(body["name"] in {"input", name} and type(body["handle"]) is int)
            if kind == "rule":
                require(body["chain"] == "input")
    require(item["preservation_hashes"]["fresh_nft"] == {"before": nft["foreign"]["before_sha256"], "after": nft["foreign"]["after_sha256"]})
    cases = item["dependency_cases"]
    require(type(cases) is dict and set(cases) == {"direct_indexer", "direct_guard", "transitive", "mixed", "activation", "ordering",
                                                 "conflict_indexer", "conflict_guard", "conflict_stop"})
    from deploy.wazuh.https_setup.ufw_host import DEPENDENCIES
    for name, case in cases.items():
        require(set(case) == {"mapping", "facts", "refused", "propagation_verified", "baseline", "identity_mapping", "raw_facts_sha256"} |
                ({"lifecycle"} if name.startswith("conflict_") else set()) and case["refused"] is True)
        if name.startswith("conflict_"):
            require(type(case["lifecycle"]) is dict and set(case["lifecycle"]) == {
                "source_active_before", "wrapper_active_before", "relay_inactive_before", "relay_active_after", "wrapper_inactive_after"})
            require(all(value is True for value in case["lifecycle"].values()))
        require(case["propagation_verified"] is (name not in {"activation", "ordering"}))
        roles = case["mapping"]
        require(set(roles) == {"ufw.service", "wazuh-indexer.service", "aegis-wazuh-http-guard.service", "bridge.service"})
        require(len(set(roles.values())) == 4 and set(case["facts"]) == set(roles.values()))
        baseline = case["baseline"]
        require(type(baseline) is dict and set(baseline) == {"identity_mapping", "raw_facts_sha256", "admitted"} and baseline["admitted"] is True)
        require(sha(baseline["raw_facts_sha256"]) and sha(case["raw_facts_sha256"]))
        for identities in (baseline["identity_mapping"], case["identity_mapping"]):
            require(type(identities) is dict and 4 <= len(identities) <= 512 and len(set(identities.values())) == len(identities))
            require(all(identities.get(role) == actual for role, actual in roles.items()))
            for logical, actual in identities.items():
                require(type(actual) is str and len(actual) <= 255 and re.fullmatch(r"[A-Za-z0-9_.@\\:-]+\.[a-z]+", actual) is not None)
                if logical not in roles:
                    stem = "aegis-fixture-external-" + hashlib.sha256(actual.encode("ascii")).hexdigest()
                    kind = actual.rsplit(".", 1)[1]
                    require(re.fullmatch(stem + r"(?:-[1-9][0-9]{0,2})?\." + kind, logical) is not None)
        for unit, facts in case["facts"].items():
            require(re.fullmatch(r"aegis-native-[0-9a-f]{12}-dep-[a-z_]+-[a-z]+\.service", unit) is not None)
            require(set(facts) == set(DEPENDENCIES))
            require(all(type(v) is list and len(v) <= 512 and all(type(n) is str for n in v) and v == sorted(set(v)) for v in facts.values()))
            for values in facts.values():
                require(all(n in case["identity_mapping"].values() for n in values))
        facts = {role: case["facts"][unit] for role, unit in roles.items()}
        ufw, indexer, guard, bridge = (roles[k] for k in ("ufw.service", "wazuh-indexer.service", "aegis-wazuh-http-guard.service", "bridge.service"))
        if name.startswith("direct_"):
            require((indexer if name == "direct_indexer" else guard) in facts["ufw.service"]["Requires"])
        elif name in {"transitive", "mixed"}:
            require(guard in facts["bridge.service"]["Requires"])
            require(bridge in facts["ufw.service"]["Requires"] if name == "transitive" else ufw in facts["bridge.service"]["PropagatesStopTo"])
        elif name == "activation":
            require(ufw in facts["aegis-wazuh-http-guard.service"]["Wants"])
        elif name.startswith("conflict_"):
            source = "aegis-wazuh-http-guard.service" if name == "conflict_guard" else "wazuh-indexer.service"
            require(bridge in facts[source]["Wants"])
            target = "aegis-wazuh-http-guard.service" if name == "conflict_stop" else "ufw.service"
            require(roles[target] in facts["bridge.service"]["ConflictedBy" if name == "conflict_guard" else "Conflicts"])
            require(bridge in facts[target]["Conflicts" if name == "conflict_guard" else "ConflictedBy"])
            if name == "conflict_stop":
                require(guard in facts["ufw.service"]["PartOf"])
        else:
            require(ufw in facts["aegis-wazuh-http-guard.service"]["Before"])


def write_proof(path, proof):
    """Publish only sanitized JSON as 0644, separate from root-only fixtures."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".proof-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(proof, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", action="store_true", help="required Linux native qualification")
    parser.add_argument("--source-commit", help="exact 40-character checked-out commit; required for native")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    errors = platform_errors(native=args.native)
    source = None
    if args.native or args.source_commit:
        try:
            source = source_snapshot(args.source_commit)
        except (ValueError, OSError, subprocess.SubprocessError):
            errors.append("source_verification_failed")
    proof = {"schema_version": 1, "mode": "native" if args.native else "portable",
             "platform": {"system": platform.system(), "python": platform.python_version()},
             "scope": proof_scope(native=args.native),
             "source": source, "status": "failed", "errors": errors,
             "native_observations": {},
             "counts": {"run": 0, "failures": 0, "errors": 0, "skipped": 0},
             "required": {name: "missing" for name in REQUIRED_NATIVE} if args.native else {}}
    if not errors:
        if args.native:
            os.environ["AEGIS_REQUIRE_NATIVE"] = "1"
            os.environ["AEGIS_NATIVE_SOURCE_COMMIT"] = args.source_commit
        else:
            os.environ.pop("AEGIS_REQUIRE_NATIVE", None)
        suite = unittest.defaultTestLoader.loadTestsFromNames((*PORTABLE, *((NATIVE_MODULE,) if args.native else ())))
        result = unittest.TextTestRunner(verbosity=1, resultclass=ProofResult).run(suite)
        proof["counts"] = dict(run=result.testsRun, failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped))
        proof["required"] = required_results(result, REQUIRED_NATIVE) if args.native else {}
        if args.native:
            proof["native_observations"] = getattr(sys.modules.get(NATIVE_MODULE), "OBSERVATIONS", {})
        proof["status"] = "passed" if qualified(result, REQUIRED_NATIVE if args.native else ()) else "failed"
        if args.native:
            try:
                validate_native_observations(proof["native_observations"])
            except (ValueError, KeyError, TypeError):
                proof["status"] = "failed"
                errors.append("native_observation_invalid")
        # Catch accidental source mutation by tests as well as pre-run drift.
        if source is not None:
            try:
                if source_snapshot(args.source_commit) != source:
                    raise ValueError
            except (ValueError, OSError, subprocess.SubprocessError):
                proof["status"] = "failed"
                errors.append("source_changed_during_tests")
    write_proof(args.output, proof)
    print(json.dumps({"status": proof["status"], "mode": proof["mode"], "counts": proof["counts"]}, sort_keys=True))
    return 0 if proof["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
