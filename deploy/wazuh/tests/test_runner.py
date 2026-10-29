"""Portable gate tests: missing, skipped or mismatched proof cannot qualify."""
import ast
import builtins
import copy
import hashlib
import importlib.util
from contextlib import nullcontext, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

RUNNER = Path(__file__).resolve().parents[1] / "Run-SelfTests.py"


class RunnerTests(unittest.TestCase):
    def runner(self):
        self.assertTrue(RUNNER.is_file(), "explicit native self-test runner is missing")
        spec = importlib.util.spec_from_file_location("wazuh_selftests", RUNNER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def result(self, outcome):
        class Sample(unittest.TestCase):
            def test_required(self):
                if outcome == "skip":
                    self.skipTest("synthetic missing prerequisite")
                if outcome == "fail":
                    self.fail("synthetic failed requirement")
        result = self.runner().ProofResult(io.StringIO(), True, 0)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Sample)
        required = [next(iter(suite)).id()]
        suite.run(result)
        return result, required

    def test_missing_required_is_failure(self):
        module = self.runner()
        result = module.ProofResult(io.StringIO(), True, 0)
        self.assertFalse(module.required_results(result, ["absent"])["absent"] == "passed")

    def test_skipped_required_is_failure(self):
        result, required = self.result("skip")
        self.assertEqual(self.runner().required_results(result, required)[required[0]], "skipped")
        self.assertFalse(self.runner().qualified(result, required))

    def test_failed_required_is_failure(self):
        result, required = self.result("fail")
        self.assertFalse(self.runner().qualified(result, required))

    def test_success_requires_all_named_ids(self):
        result, required = self.result("pass")
        self.assertTrue(self.runner().qualified(result, required))
        self.assertFalse(self.runner().qualified(result, required + ["absent"]))

    def test_failure_in_subtest_cannot_be_overwritten_as_success(self):
        module = self.runner()
        class Sample(unittest.TestCase):
            def test_required(self):
                with self.subTest(phase="fixture"):
                    self.fail("synthetic failure")
        case = Sample("test_required")
        result = module.ProofResult(io.StringIO(), True, 0)
        case.run(result)
        self.assertFalse(module.qualified(result, [case.id()]))

    def test_copied_child_subtest_failure_and_error_fail_required_id_and_proof(self):
        """Model only the forked unittest state; this is not native OS proof."""
        from deploy.wazuh.tests import test_native as native
        for kind in ("failure", "error"):
            with self.subTest(kind=kind):
                module = self.runner()
                identity = module.NATIVE_MODULE + ".NativeTests.test_publication_races_preserve_evidence"
                class Sample(unittest.TestCase):
                    def id(self):
                        return identity
                    def test_required(self):
                        parent_outcome = self._outcome
                        # A real independent unittest outcome models the child's
                        # copied result. Only an escaping exception reaches parent.
                        self._outcome = unittest.case._Outcome(unittest.TestResult())
                        try:
                            boundary = getattr(native, "child_assertions", lambda _: nullcontext())
                            with boundary(self):
                                with self.subTest(timing="window"):
                                    if kind == "error":
                                        raise RuntimeError("synthetic child race error")
                                    self.assertEqual(b"wrong snapshot", b"expected snapshot")
                        finally:
                            self._outcome = parent_outcome
                with tempfile.TemporaryDirectory() as temporary:
                    output = Path(temporary) / "synthetic-proof.json"
                    suite = unittest.TestSuite([Sample("test_required")])
                    source = {"source_commit": "f" * 40, "files": {}}
                    with patch.dict(os.environ), patch.object(module, "REQUIRED_NATIVE", (identity,)), \
                            patch.object(module, "platform_errors", return_value=[]), \
                            patch.object(module, "source_snapshot", return_value=source), \
                            patch.object(module.unittest.defaultTestLoader, "loadTestsFromNames", return_value=suite), \
                            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        code = module.main(["--native", "--source-commit", "f" * 40, "--output", str(output)])
                    proof = json.loads(output.read_text(encoding="utf-8"))
                    self.assertEqual(code, 1)
                    self.assertEqual(proof["status"], "failed")
                    self.assertEqual(proof["required"][identity], "failed" if kind == "failure" else "error")
                    self.assertEqual(proof["counts"]["failures" if kind == "failure" else "errors"], 1)

    def test_written_proof_is_sanitized_and_readable(self):
        module = self.runner()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "proof.json"
            module.write_proof(output, {"status": "failed", "required": {"synthetic": "missing"}})
            self.assertIn('"failed"', output.read_text(encoding="utf-8"))

    def test_portable_mode_cannot_claim_native(self):
        module = self.runner()
        self.assertEqual(module.platform_errors(native=False), [])
        self.assertTrue(module.platform_errors(native=True, system="Windows"))

    def test_source_gate_rejects_wrong_head_and_uncommitted_bytes(self):
        module = self.runner()
        from deploy.wazuh.https_setup.host import KIT_FILES
        names = ["deploy/wazuh/" + name for name in KIT_FILES]
        names += ["deploy/wazuh/Run-SelfTests.py", *("deploy/wazuh/tests/" + name + ".py" for name in
                  ("test_components", "test_transaction", "test_runner", "test_native", "test_ufw")),
                  ".github/workflows/wazuh-http-operator.yml", "docs/manager/wazuh-http-preparation.md"]
        sha = "f" * 40
        def git(argv, **kwargs):
            return SimpleNamespace(stdout=(sha + "\n").encode() if "rev-parse" in argv else b"canonical\n")
        with tempfile.TemporaryDirectory() as temporary:
            module.ROOT = Path(temporary)
            for name in names:
                path = module.ROOT / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"canonical\n")
            with patch.object(module.subprocess, "run", side_effect=git):
                source = module.source_snapshot(sha)
                self.assertEqual(set(source["files"]), set(names))
                self.assertEqual(source["source_commit"], sha)
                (module.ROOT / names[0]).write_bytes(b"canonical\r\n")
                with self.assertRaisesRegex(ValueError, "source_bytes_mismatch"):
                    module.source_snapshot(sha)
            with patch.object(module.subprocess, "run", return_value=SimpleNamespace(stdout=b"0" * 40 + b"\n")):
                with self.assertRaisesRegex(ValueError, "source_head_mismatch"):
                    module.source_snapshot(sha)

    def test_disabled_ufw_gate_and_vendor_sources_are_mandatory(self):
        gate = self.runner()
        self.assertEqual(len(gate.REQUIRED_NATIVE), 8)
        self.assertIn(gate.NATIVE_MODULE + ".NativeTests.test_ufw_disabled_wrapper_preserved", gate.REQUIRED_NATIVE)
        self.assertIn("deploy.wazuh.tests.test_ufw", gate.PORTABLE)

    def test_native_observation_gate_rejects_missing_preservation_evidence(self):
        gate = self.runner()
        self.assertTrue(hasattr(gate, "validate_native_observations"), "native observation validation missing")
        with self.assertRaisesRegex(ValueError, "native_observation"):
            gate.validate_native_observations({})

    def observation_fixture(self, gate):
        """Explicit synthetic proof for validator tests; never native evidence."""
        from deploy.wazuh.tests.test_ufw import VENDOR
        from deploy.wazuh.https_setup import ufw, ufw_host
        prefix = gate.NATIVE_MODULE + ".NativeTests."
        common = dict(host_firewall_before_sha256="a" * 64, host_firewall_after_sha256="a" * 64,
                      fixture_cleanup_verified=True)
        mapping = {"ufw.service": "aegis-native-0123456789ab-wrapper.service",
                   ufw_host.GUARD: "aegis-native-0123456789ab-ufw-guard.service",
                   ufw_host.INDEXER: "aegis-native-0123456789ab-ufw-indexer.service"}
        cases = {}
        for name in ("direct_indexer", "direct_guard", "transitive", "mixed", "activation", "ordering",
                     "conflict_indexer", "conflict_guard", "conflict_stop"):
            roles = {role: "aegis-native-0123456789ab-dep-" + name + "-" + suffix + ".service"
                     for role, suffix in (("ufw.service", "ufw"), (ufw_host.INDEXER, "indexer"), (ufw_host.GUARD, "guard"), ("bridge.service", "bridge"))}
            facts = {unit: {key: [] for key in ufw_host.DEPENDENCIES} for unit in roles.values()}
            def edge(role, key, target):
                facts[roles[role]][key] = [roles[target]]
            if name.startswith("direct_"):
                edge("ufw.service", "Requires", ufw_host.INDEXER if name == "direct_indexer" else ufw_host.GUARD)
            elif name in {"transitive", "mixed"}:
                edge("bridge.service", "Requires", ufw_host.GUARD)
                if name == "transitive": edge("ufw.service", "Requires", "bridge.service")
                else: edge("bridge.service", "PropagatesStopTo", "ufw.service")
            elif name == "activation": edge(ufw_host.GUARD, "Wants", "ufw.service")
            elif name.startswith("conflict_"):
                edge(ufw_host.GUARD if name == "conflict_guard" else ufw_host.INDEXER, "Wants", "bridge.service")
                target = ufw_host.GUARD if name == "conflict_stop" else "ufw.service"
                edge("bridge.service", "ConflictedBy" if name == "conflict_guard" else "Conflicts", target)
                edge(target, "Conflicts" if name == "conflict_guard" else "ConflictedBy", "bridge.service")
                if name == "conflict_stop": edge("ufw.service", "PartOf", ufw_host.GUARD)
            else: edge(ufw_host.GUARD, "Before", "ufw.service")
            cases[name] = dict(mapping=roles, facts=facts, refused=True, propagation_verified=name not in {"activation", "ordering"},
                               baseline={"identity_mapping": dict(roles), "raw_facts_sha256": "e" * 64, "admitted": True},
                               identity_mapping=dict(roles), raw_facts_sha256="f" * 64)
            if name.startswith("conflict_"):
                cases[name]["lifecycle"] = dict(source_active_before=True, wrapper_active_before=True,
                    relay_inactive_before=True, relay_active_after=True, wrapper_inactive_after=True)
        bus = {key: {"type": signature, "data": []} for key, signature in ufw.EMPTY_ARRAYS.items()}
        bus["Job"] = {"type": "(uo)", "data": [0, "/"]}
        for key, args in (("ExecStartEx", ["start", "quiet"]), ("ExecStopEx", ["stop"])):
            bus[key] = {"type": "a(sasasttttuii)", "data": [[ufw.INIT_PATH, [ufw.INIT_PATH, *args], [], 0, 0, 0, 0, 0, 0, 0]]}
        from deploy.wazuh.https_setup.transaction import digest
        metadata = {"metainfo": {"version": "synthetic", "release_name": "synthetic", "json_schema_version": 1}}
        foreign = {"nftables": [metadata, {"table": {"family": "inet", "name": "aegis_fixture_foreign", "handle": 1}},
                              {"chain": {"family": "inet", "table": "aegis_fixture_foreign", "name": "input", "handle": 2}},
                              {"rule": {"family": "inet", "table": "aegis_fixture_foreign", "chain": "input", "handle": 3, "expr": [{"counter": {"packets": 0, "bytes": 0}}]}}]}
        nft = {}
        for name in ("empty", "foreign", "ufw-partial", "ufw6-partial"):
            document = {"nftables": [metadata]} if name == "empty" else copy.deepcopy(foreign)
            if name.endswith("partial"):
                document["nftables"].append({"chain": {"family": "inet", "table": "aegis_fixture_foreign", "name": name, "handle": 4}})
            nft[name] = dict(document=document, before_sha256=digest(document), after_sha256=digest(document),
                             refused=name.endswith("partial"), absent_lock_preserved=True, present_lock_preserved=True,
                             resources=dict(stage="complete", euid=0,
                                source=dict(type="char", mode=0o666, uid=0, gid=0, rdev=[1, 3]),
                                target_before=dict(type="regular", mode=0o600, uid=0, gid=0, rdev=[0, 0]),
                                target_bound=dict(type="char", mode=0o666, uid=0, gid=0, rdev=[1, 3]),
                                nodev=dict(source=False, target_before=True, target_bound=False),
                                open_errno=dict(source=0, bound=0, chroot=0),
                                child_mount_namespace_distinct=True, recursive_private=True,
                                parent_namespace_unchanged=True, parent_target_unchanged=True,
                                parent_mounts_unchanged=True, child_bind_released=True))
        item = dict(common,
                    vendor_deb_sha256="096eb403ecaf6740d160bb306970f025222ef71324319cc1cb78d06dfa462ef1",
                    vendor_inputs={path: hashlib.sha256(body).hexdigest() for path, body in VENDOR.items()},
                    relocations=gate.UFW_RELOCATIONS,
                    checks={key: True for key in gate.UFW_CHECKS},
                    operations={name: dict(allowed=True, denied=True, table=True, foreign=True) for name in gate.UFW_OPERATIONS},
                    preservation_hashes={name: dict(before="b" * 64, after="b" * 64) for name in ("vendor", "foreign", "real_ufw", "fresh_nft")},
                    unit_mapping=mapping, dependency_cases=cases, nft_observations=nft,
                    native_adapter={"unit_properties": {**ufw.STATIC_PROPERTIES, **ufw.RUNTIME_PROPERTIES,
                                    "RootDirectory": "<owned_vendor_root>", "FragmentPath": "/run/systemd/system/" + mapping["ufw.service"], "UnitFileState": "disabled"},
                                    "typed_bus": bus, "backend_sha256": "c" * 64},
                    scope={"native": "vendor_lifecycle_packets_order_and_adapter_refusal", "positive_admission": "synthetic_reader",
                           "probe": "nft-no-ufw-chains-v1", "owner_full_class_check": "pending", "vendor_lab_acceptance": False})
        item["preservation_hashes"]["fresh_nft"] = {"before": nft["foreign"]["before_sha256"], "after": nft["foreign"]["after_sha256"]}
        strict = dict(common, loader_scope="owned_namespace_inventory_not_host_eligibility", strict_path_exception_not_used=True,
                      loader_query_mapping={role: "aegis-native-0123456789ab-loader-" + role.split(".")[0] + ".service" for role in ufw_host.LOADERS},
                      loader_facts={role: {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"} for role in ufw_host.LOADERS})
        return {prefix + "test_nft_allowed_denied_sources": dict(common), prefix + "test_systemd_every_start_guard": strict,
                prefix + "test_ufw_disabled_wrapper_preserved": item}

    def test_closed_ufw_observations_require_every_preservation_and_transition(self):
        gate = self.runner()
        observations = self.observation_fixture(gate)
        try:
            gate.validate_native_observations(observations)
        except ValueError:
            self.fail("complete synthetic resource/conflict observation must satisfy the proof schema")
        identity = gate.NATIVE_MODULE + ".NativeTests.test_ufw_disabled_wrapper_preserved"
        changes = []
        for name in gate.UFW_CHECKS:
            changes.append(lambda item, key=name: item["checks"].__setitem__(key, False))
        for operation in gate.UFW_OPERATIONS:
            for result in ("allowed", "denied", "table", "foreign"):
                changes.append(lambda item, op=operation, key=result: item["operations"][op].__setitem__(key, False))
        for name in observations[identity]["preservation_hashes"]:
            changes.append(lambda item, key=name: item["preservation_hashes"][key].__setitem__("after", "c" * 64))
        for name in observations[identity]["vendor_inputs"]:
            changes.append(lambda item, key=name: item["vendor_inputs"].__setitem__(key, "0" * 64))
        changes += [lambda item: item.__setitem__("unexpected", "private-data"),
                    lambda item: item["scope"].__setitem__("owner_full_class_check", "passed"),
                    lambda item: item["scope"].__setitem__("vendor_lab_acceptance", True),
                    lambda item: item["relocations"].pop(),
                    lambda item: item["native_adapter"]["unit_properties"].__setitem__("RootDirectory", ""),
                    lambda item: item["native_adapter"]["typed_bus"]["ExecReload"].__setitem__("data", [["injected"]]),
                    lambda item: item["dependency_cases"]["mixed"].__setitem__("propagation_verified", False),
                    lambda item: item["dependency_cases"]["mixed"]["baseline"].__setitem__("admitted", False),
                    lambda item: item["dependency_cases"]["direct_guard"]["identity_mapping"].__setitem__("ufw.service", "ufw.service"),
                    lambda item: item["nft_observations"]["empty"].__setitem__("absent_lock_preserved", False),
                    lambda item: item["nft_observations"]["foreign"].__setitem__("present_lock_preserved", False),
                    lambda item: item["nft_observations"]["ufw-partial"].__setitem__("refused", False),
                    lambda item: item["nft_observations"]["foreign"].__setitem__("after_sha256", "0" * 64),
                    lambda item: item["scope"].__setitem__("probe", "selected_backend_status_queries_not_ufw_cli"),
                    lambda item: item["native_adapter"]["typed_bus"].__setitem__("Job", {"type": "(uo)", "data": [1, "/pending"]})]
        for case in ("conflict_indexer", "conflict_guard", "conflict_stop"):
            changes.append(lambda item, case=case: item["dependency_cases"].pop(case))
            for key in observations[identity]["dependency_cases"][case]["lifecycle"]:
                changes.append(lambda item, case=case, key=key: item["dependency_cases"][case]["lifecycle"].__setitem__(key, False))
        changes.append(lambda item: item["dependency_cases"]["conflict_guard"]["facts"][item["dependency_cases"]["conflict_guard"]["mapping"]["bridge.service"]].__setitem__("ConflictedBy", []))
        for key in ("child_mount_namespace_distinct", "recursive_private", "parent_namespace_unchanged",
                    "parent_target_unchanged", "parent_mounts_unchanged", "child_bind_released"):
            changes.append(lambda item, key=key: item["nft_observations"]["empty"]["resources"].__setitem__(key, False))
        for key in ("source", "bound", "chroot"):
            changes.append(lambda item, key=key: item["nft_observations"]["empty"]["resources"]["open_errno"].__setitem__(key, 13))
        changes += [lambda item: item["nft_observations"]["empty"]["resources"]["source"].__setitem__("type", "regular"),
                    lambda item: item["nft_observations"]["empty"]["resources"]["nodev"].__setitem__("target_bound", True),
                    lambda item: item["nft_observations"]["empty"]["resources"].__setitem__("stage", "bind"),
                    lambda item: item["nft_observations"]["empty"]["resources"].__setitem__("private_path", "DO_NOT_EXPORT")]
        for index, change in enumerate(changes):
            with self.subTest(mutation=index):
                broken = copy.deepcopy(observations)
                change(broken[identity])
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    gate.validate_native_observations(broken)
        for key in observations[identity]:
            broken = copy.deepcopy(observations)
            del broken[identity][key]
            with self.subTest(missing=key), self.assertRaises((ValueError, KeyError, TypeError)):
                gate.validate_native_observations(broken)

    def test_missing_ufw_observation_fails_otherwise_successful_native_runner(self):
        module = self.runner()
        identity = module.REQUIRED_NATIVE[-1]
        class Sample(unittest.TestCase):
            def id(self): return identity
            def runTest(self): pass
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "proof.json"
            with patch.dict(os.environ), patch.object(module, "platform_errors", return_value=[]), \
                    patch.object(module, "source_snapshot", return_value={"source_commit": "f" * 40, "files": {}}), \
                    patch.object(module, "REQUIRED_NATIVE", (identity,)), \
                    patch.object(module.unittest.defaultTestLoader, "loadTestsFromNames", return_value=unittest.TestSuite([Sample()])), \
                    redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                code = module.main(["--native", "--source-commit", "f" * 40, "--output", str(path)])
            proof = json.loads(path.read_text())
            self.assertEqual(code, 1)
            self.assertEqual(proof["required"], {identity: "passed"})
            self.assertEqual(proof["errors"], ["native_observation_invalid"])

    def test_nft_only_observation_schema_replaces_compatibility_list_probe(self):
        gate = self.runner()
        self.assertIn("fresh_nft_observation_preserved", gate.UFW_CHECKS)
        self.assertNotIn("backend_status_queries_preserved", gate.UFW_CHECKS)
        self.assertIn("ufw_lock_absent_preserved", gate.UFW_CHECKS)
        self.assertIn("ufw_lock_present_preserved", gate.UFW_CHECKS)

    def test_source_gate_requires_full_lowercase_commit(self):
        module = self.runner()
        for commit in (None, "HEAD", "a" * 39, "A" * 40, "a" * 41):
            with self.subTest(commit=commit), self.assertRaisesRegex(ValueError, "source_commit_required"):
                module.source_snapshot(commit)

    def test_proof_scope_names_relocations_without_vendor_claim(self):
        module = self.runner()
        self.assertTrue(hasattr(module, "proof_scope"), "proof lacks explicit synthetic harness scope")
        native = module.proof_scope(native=True)
        self.assertFalse(native["vendor_lab_acceptance"])
        self.assertEqual(native["systemd_fixture_relocations"], module.UFW_RELOCATIONS)
        self.assertEqual(module.proof_scope(native=False)["systemd_fixture_relocations"], [])


class NativeFixtureSafety(unittest.TestCase):
    def stop_fixture(self):
        from deploy.wazuh.tests import test_native as native
        fixture = SimpleNamespace(test=self, token="0123456789ab", units=[], bodies={})
        def unit(role, body):
            name = "aegis-native-" + fixture.token + "-" + role + ".service"
            fixture.units.append((name, Path("/run/systemd/system") / name))
            fixture.bodies[name] = body
            return name
        fixture.unit = unit
        mapping = {role: unit(suffix, "") for role, suffix in
                   (("ufw.service", "wrapper"), (native.uh.GUARD, "guard"), (native.uh.INDEXER, "indexer"))}
        return fixture, mapping

    def test_stop_observer_has_only_owned_authored_ordering(self):
        from deploy.wazuh.tests import test_native as native
        self.assertTrue(hasattr(native, "make_stop_observer"), "retained stop observer missing")
        fixture, mapping = self.stop_fixture()
        observer = native.make_stop_observer(fixture, mapping)
        lines = fixture.bodies[observer].splitlines()
        self.assertIn("After=" + " ".join(mapping.values()), lines)
        for line in ("DefaultDependencies=no", "Type=oneshot", "RemainAfterExit=yes", "ExecStart=/usr/bin/true",
                     "StandardOutput=null", "StandardError=null", "TimeoutStartSec=10", "TimeoutStopSec=5"):
            self.assertIn(line, lines)
        self.assertFalse(any(line.startswith(key + "=") for line in lines for key in native.uh.DEPENDENCIES if key != "After"))
        self.assertEqual(len(fixture.units), 4)
        broken = dict(mapping, **{"ufw.service": "ufw.service"})
        with self.assertRaisesRegex(AssertionError, "owned_stop_participants_required"):
            native.make_stop_observer(fixture, broken)

    def test_retained_stop_keeps_one_transaction_and_rejects_bad_evidence(self):
        from deploy.wazuh.tests import test_native as native
        self.assertTrue(hasattr(native, "measure_retained_stop"), "retained stop measurement missing")
        for fault in (None, "zero", "missing", "reverse", "private", "observer_stopped", "external", "participant_inactive",
                      "After", "Requires", "Slice", *[key for key in native.uh.DEPENDENCIES if key not in {"After", "Requires"}]):
            fixture, mapping = self.stop_fixture()
            observer = native.make_stop_observer(fixture, mapping)
            actions, phase = [], {"stopped": False}
            def systemctl(*args, **kwargs):
                if args[0] != "show":
                    actions.append(args)
                    if args == ("stop", *mapping.values()): phase["stopped"] = True
                    return SimpleNamespace(stdout=b"", returncode=0)
                unit = args[1]
                active = unit == observer or not phase["stopped"]
                row = dict(LoadState="loaded", ActiveState="active" if active else "inactive",
                           SubState="exited" if active else "dead", ActiveEnterTimestampMonotonic="5",
                           ExecMainStartTimestampMonotonic="4", InactiveEnterTimestampMonotonic=str(
                               10 if unit == mapping[native.uh.INDEXER] else 20 if unit == mapping[native.uh.GUARD] else 30))
                if phase["stopped"] and unit == mapping[native.uh.INDEXER]:
                    if fault == "zero": row["InactiveEnterTimestampMonotonic"] = "0"
                    if fault == "missing": del row["InactiveEnterTimestampMonotonic"]
                    if fault == "reverse": row["InactiveEnterTimestampMonotonic"] = "99"
                    if fault == "private": row.update(ActiveState="/root/DO_NOT_EXPORT", InactiveEnterTimestampMonotonic="secret")
                if fault == "observer_stopped" and phase["stopped"] and unit == observer:
                    row.update(ActiveState="inactive", SubState="dead")
                if fault == "participant_inactive" and unit == mapping[native.uh.INDEXER]:
                    row.update(ActiveState="inactive", SubState="dead")
                return SimpleNamespace(stdout="".join(k + "=" + v + "\n" for k, v in row.items()).encode(), returncode=0)
            fixture.systemctl = systemctl
            relations = {key: "" for key in native.uh.DEPENDENCIES}
            relations.update(After=" ".join([*mapping.values(), "system.slice"]), Requires="system.slice")
            if fault in relations: relations[fault] += " unexpected.service"
            host = SimpleNamespace(dependency_properties=lambda unit: dict(relations),
                                   properties=lambda *args: {"Slice": "unexpected.slice" if fault == "Slice" else "system.slice"})
            if fault == "external": observer = "ufw.service"
            with self.subTest(fault=fault), patch.object(native.h, "LinuxHost", return_value=host):
                if fault:
                    with self.assertRaises(AssertionError) as caught:
                        native.measure_retained_stop(fixture, mapping, observer)
                    self.assertNotIn("DO_NOT_EXPORT", str(caught.exception))
                    if fault in {"zero", "missing", "reverse", "private", "observer_stopped"}:
                        payload = json.loads(str(caught.exception))
                        self.assertEqual(set(payload), {"stage", "units"})
                        self.assertEqual(set(payload["units"]), {"wrapper", "guard", "indexer", "observer"})
                        expected = 0 if fault == "zero" else "unavailable" if fault in {"missing", "private"} else 99 if fault == "reverse" else 10
                        self.assertEqual(payload["units"]["indexer"]["InactiveEnterTimestampMonotonic"], expected)
                        self.assertEqual(actions, [("start", observer), ("stop", *mapping.values())])
                    else:
                        self.assertEqual(actions, [])
                else:
                    native.measure_retained_stop(fixture, mapping, observer)
                    self.assertEqual(actions, [("start", observer), ("stop", *mapping.values()), ("stop", observer)])
                self.assertEqual(relations.get("Requires"), "system.slice unexpected.service" if fault == "Requires" else "system.slice")

    def test_conflict_final_state_poll_is_bounded_and_read_only(self):
        from deploy.wazuh.tests import test_native as native
        self.assertTrue(hasattr(native, "wait_conflict_states"), "bounded final-state poll missing")
        for succeeds in (True, False):
            calls, tick = [], {"value": 0}
            def clock():
                tick["value"] += 1
                return tick["value"]
            def systemctl(*args, **kwargs):
                calls.append(args)
                done = succeeds and len(calls) >= 3
                return SimpleNamespace(stdout=(b"active" if args[1] == "relay.service" else b"inactive") if done else b"activating")
            fixture = SimpleNamespace(systemctl=systemctl)
            with self.subTest(succeeds=succeeds), patch.object(native.time, "monotonic", side_effect=clock), patch.object(native.time, "sleep"):
                if succeeds: native.wait_conflict_states(fixture, "relay.service", "wrapper.service")
                else:
                    with self.assertRaisesRegex(AssertionError, "conflict_states_timeout"):
                        native.wait_conflict_states(fixture, "relay.service", "wrapper.service")
                self.assertTrue(all(call[0] == "show" for call in calls))
                self.assertLessEqual(len(calls), 10)

    def test_completed_probe_observations_survive_later_fixture_failure(self):
        from deploy.wazuh.tests import test_native as native
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SimpleNamespace(root=Path(temporary), nft=lambda *args, **kwargs: SimpleNamespace(stdout=b'{"nftables":[]}'),
                start_listener=lambda: (_ for _ in ()).throw(AssertionError("later_fixture_failure")))
            case = native.NativeTests("test_ufw_disabled_wrapper_preserved")
            facts = {"resources": {"stage": "complete"}, "document": {"nftables": []}}
            with patch.dict(native.OBSERVATIONS, clear=True), patch.object(native, "network_fixture", return_value=nullcontext(fixture)), \
                    patch.object(native, "real_ufw_baseline", return_value="synthetic"), \
                    patch.object(native, "vendor_tree", return_value=Path(temporary)), patch.object(native, "vendor_digest", return_value="synthetic"), \
                    patch.object(native, "copy_tool_closure"), patch.object(native, "private_file"), \
                    patch.object(native, "native_nft_read", return_value=facts):
                with self.assertRaisesRegex(AssertionError, "later_fixture_failure"):
                    case.test_ufw_disabled_wrapper_preserved()
                observed = native.OBSERVATIONS.get(case.id(), {})
                self.assertEqual(set(observed.get("nft_observations", {})), {"empty", "foreign", "ufw-partial", "ufw6-partial"})
                self.assertEqual(observed["nft_observations"]["empty"], facts)
                self.assertEqual(set(observed["checks"]), {"fresh_nft_observation_preserved", "ufw_lock_absent_preserved", "ufw_lock_present_preserved", "partial_ufw_chains_refused"})
                self.assertEqual(observed["operations"], {})
                with self.assertRaisesRegex(ValueError, "native_observation_invalid"):
                    RunnerTests().runner().validate_native_observations(native.OBSERVATIONS)

    def test_probe_null_requires_real_device_and_owned_regular_target(self):
        from deploy.wazuh.tests import test_native as native
        self.assertTrue(hasattr(native, "probe_null_metadata"), "checked null resource missing")
        import stat
        source = SimpleNamespace(st_mode=stat.S_IFCHR | 0o666, st_uid=0, st_gid=0, st_rdev=259, st_nlink=1, st_size=0)
        target = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_rdev=0, st_nlink=1, st_size=0)
        fake_os = SimpleNamespace(major=lambda n: 1 if n == 259 else 0, minor=lambda n: 3 if n == 259 else 0)
        with patch.object(native, "os", fake_os):
            self.assertEqual(native.probe_null_metadata(source, device=True)["rdev"], [1, 3])
            self.assertEqual(native.probe_null_metadata(target, device=False)["type"], "regular")
            for changes, device in ((dict(st_mode=stat.S_IFREG | 0o666), True), (dict(st_rdev=0), True),
                                    (dict(st_uid=1), True), (dict(st_mode=stat.S_IFLNK | 0o777), False),
                                    (dict(st_mode=stat.S_IFREG | 0o666), False), (dict(st_nlink=2), False),
                                    (dict(st_size=1), False)):
                info = SimpleNamespace(**{**vars(source if device else target), **changes})
                with self.subTest(changes=changes, device=device), self.assertRaisesRegex(AssertionError, "probe_null_untrusted"):
                    native.probe_null_metadata(info, device=device)

    def test_probe_mount_facts_distinguish_nodev_bind_and_shared_mounts(self):
        from deploy.wazuh.tests import test_native as native
        self.assertTrue(hasattr(native, "probe_mount_facts"), "bounded mount observation missing")
        raw = b"1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 0:1 / /run rw,nosuid,nodev shared:7 - tmpfs tmpfs rw\n"
        self.assertEqual(native.probe_mount_facts(raw, "/run/owned/probe-root/dev/null"),
                         {"nodev": True, "mounted": False, "private": False})
        private = raw.replace(b" shared:7", b"") + b"3 2 0:2 /null /run/owned/probe-root/dev/null rw,nosuid - tmpfs tmpfs rw\n"
        self.assertEqual(native.probe_mount_facts(private, "/run/owned/probe-root/dev/null"),
                         {"nodev": False, "mounted": True, "private": True})
        for malformed in (b"private-host-data", b"", b"x" * (1024 * 1024 + 1)):
            with self.assertRaisesRegex(AssertionError, "probe_mount_observation_required"):
                native.probe_mount_facts(malformed, "/run/owned/probe-root/dev/null")

    def test_probe_null_unshares_and_privatizes_before_exact_bind(self):
        from deploy.wazuh.tests import test_native as native
        self.assertTrue(hasattr(native, "bind_probe_null"), "private null bind missing")
        import ctypes
        import stat
        source = SimpleNamespace(st_mode=stat.S_IFCHR | 0o666, st_uid=0, st_gid=0, st_rdev=259, st_nlink=1, st_size=0)
        target = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_rdev=0, st_nlink=1, st_size=0)
        for fail in (None, "unshare", "private", "bind", "same_namespace", "source", "target", "open",
                     "parent_process", "nonroot", "wrong_root", "ancestor", "shared", "nodev", "eof"):
            events = []
            def unshare(flags):
                events.append(("unshare", flags))
                return -1 if fail == "unshare" else 0
            def mount(source_path, target_path, kind, flags, data):
                stage = "private" if source_path is None else "bind"
                events.append((stage, source_path, target_path, flags))
                return -1 if fail == stage else 0
            def opening(*args, **kwargs):
                events.append(("open",))
                if fail == "open": raise PermissionError(13, "DO_NOT_EXPORT")
                return 9
            count = {"value": 0}
            def metadata(info, *, device):
                count["value"] += 1
                if (fail == "source" and device) or (fail == "target" and not device):
                    raise AssertionError("probe_null_untrusted")
                return {"type": "char" if device else "regular", "mode": 438 if device else 384,
                        "uid": 0, "gid": 0, "rdev": [1, 3] if device else [0, 0]}
            fake_os = SimpleNamespace(geteuid=lambda: 1 if fail == "nonroot" else 0, getpid=lambda: 111 if fail == "parent_process" else 222,
                stat=lambda path, **kwargs: SimpleNamespace(st_ino=11 if fail == "same_namespace" else 22) if path == "/proc/self/ns/mnt" else source if str(path) == "/dev/null" else target,
                open=opening, close=lambda fd: events.append(("close",)), read=lambda *args: b"x" if fail == "eof" else b"", fstat=lambda fd: source,
                O_RDWR=2, O_NOFOLLOW=4)
            diagnostic = {}
            def parent(path):
                if fail == "ancestor": raise native.SetupError("path_untrusted")
                return nullcontext((3, "null"))
            with self.subTest(fail=fail), patch.object(native, "os", fake_os), \
                    patch.object(native.uh, "root_parent", side_effect=parent), \
                    patch.object(native.uh, "_identity", return_value=(1,)), \
                    patch.object(native, "probe_null_metadata", side_effect=metadata), \
                    patch.object(native, "probe_mount_table", return_value=b"mounts"), \
                    patch.object(native, "probe_mount_facts", return_value={"nodev": fail == "nodev", "mounted": True, "private": fail != "shared"}), \
                    patch.object(ctypes, "CDLL", return_value=SimpleNamespace(unshare=unshare, mount=mount)):
                args = (Path("/run/owned/other" if fail == "wrong_root" else "/run/owned/probe-root"), Path("/run/owned"), 111, 11, diagnostic)
                if fail:
                    with self.assertRaises((AssertionError, OSError, native.SetupError)):
                        native.bind_probe_null(*args)
                    if fail not in {"bind", "nodev"}:
                        self.assertNotIn("bind", [event[0] for event in events])
                else:
                    native.bind_probe_null(*args)
                    operations = [event for event in events if event[0] in {"unshare", "private", "bind"}]
                    self.assertEqual(operations, [("unshare", 0x20000), ("private", None, b"/", 0x44000),
                        ("bind", b"/dev/null", b"/run/owned/probe-root/dev/null", 0x1000)])
                    self.assertTrue(diagnostic["child_mount_namespace_distinct"])
                    self.assertTrue(diagnostic["recursive_private"])

    def test_probe_parent_checks_placeholder_mounts_and_namespace_after_child_exit(self):
        from deploy.wazuh.tests import test_native as native
        import stat
        root = Path("/run/owned/probe-root")
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_rdev=0, st_nlink=1, st_size=0)
        for changed in (None, "namespace", "target", "mounts", "child_failure"):
            calls = {"stat": 0, "mount": 0}
            def stat_path(path, **kwargs):
                if path == "/proc/self/ns/mnt":
                    calls["stat"] += 1
                    return SimpleNamespace(st_ino=99 if changed == "namespace" and calls["stat"] > 1 else 11)
                return info
            def mounts():
                calls["mount"] += 1
                return b"changed" if changed == "mounts" and calls["mount"] > 1 else b"original"
            result = dict(resources=dict(stage="complete"))
            if changed == "child_failure":
                result = dict(resources=dict(stage="bound_open", open_errno=dict(bound=13)), error_type="os_error", error_errno=13)
            fake_os = SimpleNamespace(getpid=lambda: 111, stat=stat_path, pipe=lambda: (5, 6), fork=lambda: 222,
                close=lambda fd: None, read=lambda *args: native.tx.encoded(result),
                waitpid=lambda *args: (222, 256 if changed == "child_failure" else 0))
            with self.subTest(changed=changed), patch.object(native, "os", fake_os), \
                    patch.object(native.uh, "root_parent", side_effect=lambda path: nullcontext((3, "null"))), \
                    patch.object(native.uh, "_identity", side_effect=[(2 if changed == "target" else 1,), (1,)]), \
                    patch.object(native, "probe_null_metadata", return_value={"type": "regular"}), \
                    patch.object(native, "probe_mount_table", side_effect=mounts), \
                    patch.object(native, "probe_mount_facts", return_value={"nodev": True, "mounted": False, "private": False}), \
                    patch.object(native.select, "select", return_value=([5], [], [])), patch.dict(native.OBSERVATIONS, clear=True):
                if changed:
                    with self.assertRaises(AssertionError):
                        native.native_nft_read(self, SimpleNamespace(), root)
                    if changed == "child_failure":
                        diagnostic = native.OBSERVATIONS[self.id()]["probe_resource_failure"]
                        self.assertEqual(diagnostic["error_errno"], 13)
                        self.assertTrue(diagnostic["resources"]["parent_mounts_unchanged"])
                        self.assertNotIn("/run", json.dumps(diagnostic))
                else:
                    observed = native.native_nft_read(self, SimpleNamespace(), root)
                    for key in ("parent_namespace_unchanged", "parent_target_unchanged", "parent_mounts_unchanged", "child_bind_released"):
                        self.assertTrue(observed["resources"][key])

    """Portable refusal tests only; these mocks supply no native OS proof."""
    def test_owned_nft_diagnostic_preserves_shape_and_redacts_fixture_data(self):
        from deploy.wazuh.tests import test_native as native
        self.assertTrue(hasattr(native, "fixture_nft_diagnostic"), "bounded synthetic nft diagnostics missing")
        p = SimpleNamespace(indexer_ip="10.21.22.10", manager_ip="10.21.22.20")
        document = {"nftables": [
            {"metainfo": {"private": "/root/do-not-export"}},
            {"table": {"family": "inet", "name": native.TABLE, "handle": 7}},
            {"rule": {"family": "inet", "table": native.TABLE, "chain": "input",
                      "comment": "DO_NOT_EXPORT", "expr": [
                          {"match": {"left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": p.indexer_ip}},
                          {"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": "unexpected-service-name"}}]}}]}
        captured = native.fixture_nft_diagnostic(document, p)
        text = json.dumps(captured)
        self.assertIn("unexpected-service-name", text)
        self.assertIn("<indexer_ip>", text)
        self.assertNotIn(p.indexer_ip, text)
        self.assertNotIn("DO_NOT_EXPORT", text)
        self.assertNotIn("/root/", text)
        document["nftables"][1]["table"]["name"] = "unrelated-host-table"
        self.assertEqual(native.fixture_nft_diagnostic(document, p), {"capture_error": "non_fixture_object"})

    def test_service_failure_capture_exports_only_fixed_status_and_cli_error(self):
        from deploy.wazuh.tests import test_native as native
        self.assertTrue(hasattr(native, "fixture_service_diagnostic"), "sanitized service diagnostic missing")
        properties = b"ActiveState=failed\nResult=exit-code\nExecMainStatus=1\nFragmentPath=/root/DO_NOT_EXPORT\n"
        journal = b'\n'.join([
            json.dumps({"MESSAGE": '{"status":"error","error":"firewall_mismatch"}'}).encode(),
            json.dumps({"MESSAGE": '{"status":"error","error":"DO_NOT_EXPORT"}'}).encode(),
            json.dumps({"MESSAGE": "/root/private-key DO_NOT_EXPORT"}).encode()])
        captured = native.fixture_service_diagnostic(properties, journal)
        self.assertEqual(captured["properties"], {"ActiveState": "failed", "Result": "exit-code", "ExecMainStatus": "1"})
        self.assertEqual(captured["cli_errors"], ["firewall_mismatch"])
        self.assertNotIn("DO_NOT_EXPORT", json.dumps(captured))

    def test_failed_owned_unit_captures_diagnostics_and_still_fails(self):
        from deploy.wazuh.tests import test_native as native
        fixture = object.__new__(native.NetworkFixture)
        fixture.test = self
        fixture.server = "synthetic-server"
        fixture.inode = 123
        fixture.namespaces = [fixture.server]
        fixture.units = [("synthetic-guard.service", Path("/run/synthetic-guard.service"))]
        fixture.unit_roles = {"synthetic-guard.service": "guard"}
        fixture.profile = SimpleNamespace(indexer_ip="10.21.22.10", manager_ip="10.21.22.20")
        document = {"nftables": [{"table": {"family": "inet", "name": native.TABLE}}]}
        def command(*args, **kwargs):
            if args[0] == "systemctl" and args[1] == "start":
                if kwargs.get("check", True):
                    raise AssertionError("native command failed: systemctl")
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"")
            if args[0] == "systemctl":
                return SimpleNamespace(returncode=0, stdout=b"ActiveState=failed\nExecMainStatus=1\n")
            if args[0] == "journalctl":
                return SimpleNamespace(returncode=0, stdout=b'{"MESSAGE":"{\\"status\\":\\"error\\",\\"error\\":\\"firewall_mismatch\\"}"}\n')
            return SimpleNamespace(returncode=0, stdout=json.dumps(document).encode())
        with patch.dict(native.OBSERVATIONS, clear=True), patch.object(native, "command", side_effect=command):
            with self.assertRaisesRegex(AssertionError, "native command failed: systemctl"):
                fixture.systemctl("start", "synthetic-guard.service")
            observed = native.OBSERVATIONS.get(self.id(), {})
            self.assertIn("fixture_nft_document", observed)
            self.assertEqual(observed["fixture_services"]["guard"]["cli_errors"], ["firewall_mismatch"])

    def test_fixture_actions_refuse_external_and_logical_role_units_before_command(self):
        from deploy.wazuh.tests import test_native as native
        fixture = object.__new__(native.NetworkFixture)
        fixture.units = [("aegis-native-0123456789ab-wrapper.service", Path("/run/systemd/system/owned.service"))]
        for unit in ("ufw.service", "wazuh-indexer.service", "aegis-wazuh-http-guard.service", "aegis-fixture-external-" + "a" * 64 + ".service"):
            with self.subTest(unit=unit), patch.object(native, "command", return_value=SimpleNamespace(returncode=0)) as command:
                with self.assertRaisesRegex(AssertionError, "owned_unit_action_required"):
                    fixture.systemctl("restart", unit)
                command.assert_not_called()

    def test_dependency_mapper_is_bijective_across_reserved_external_collisions(self):
        from deploy.wazuh.tests import test_native as native
        roles = {"ufw.service": "owned-ufw.service", native.uh.GUARD: "owned-guard.service",
                 native.uh.INDEXER: "owned-indexer.service", "bridge.service": "owned-bridge.service"}
        mapper = native.DependencyRoleMap(roles)
        for actual in ("ufw.service", native.uh.GUARD, native.uh.INDEXER, "system.slice"):
            logical = mapper.logical(actual)
            self.assertNotIn(logical, roles)
            self.assertEqual(mapper.actual(logical), actual)
            self.assertEqual(logical.rsplit(".", 1)[1], actual.rsplit(".", 1)[1])
        self.assertEqual(len(mapper.queries), len(set(mapper.queries.values())))
        with patch.object(native.hashlib, "sha256", return_value=SimpleNamespace(hexdigest=lambda: "a" * 64)):
            first, second = mapper.logical("external-one.service"), mapper.logical("external-two.service")
        self.assertNotEqual(first, second)
        self.assertEqual(mapper.actual(first), "external-one.service")
        self.assertEqual(mapper.actual(second), "external-two.service")
        with self.assertRaisesRegex(AssertionError, "unobserved_dependency_query"):
            mapper.actual("unknown.service")

    def test_dependency_mapper_bound_reports_only_measured_predicates(self):
        from deploy.wazuh.tests import test_native as native
        for count in (0, 512):
            for name, too_long, grammar in (("new.service", False, True),
                                           ("a" * 248 + ".service", True, True),
                                           ("private/path\nsecret.service", False, False),
                                           ("private/" + "a" * 256 + ".service", True, False)):
                with self.subTest(count=count, too_long=too_long, grammar=grammar):
                    mapper = native.DependencyRoleMap({})
                    for index in range(count):
                        mapper.logical(f"unit-{index}.service")
                    before = (dict(mapper.names), dict(mapper.queries))
                    if not count and not too_long and grammar:
                        self.assertEqual(mapper.actual(mapper.logical(name)), name)
                        continue
                    with self.assertRaises(AssertionError) as caught:
                        mapper.logical(name)
                    message = str(caught.exception)
                    self.assertTrue(message.startswith("{"), "fixed JSON mapping diagnostic missing")
                    self.assertEqual(json.loads(message), dict(stage="dependency_mapping_bound",
                                     mapped_count=count, name_length=len(name), count_limit_reached=count == 512,
                                     name_too_long=too_long, grammar_matches=grammar))
                    self.assertNotIn(name, message)
                    self.assertEqual((mapper.names, mapper.queries), before)
                    if count:
                        self.assertEqual(mapper.actual(mapper.logical("unit-0.service")), "unit-0.service")
        mapper = native.DependencyRoleMap({})
        longest = "a" * 247 + ".service"
        self.assertEqual(mapper.actual(mapper.logical(longest)), longest)

    def test_dependency_mapper_collision_bound_remains_separate(self):
        from deploy.wazuh.tests import test_native as native
        mapper = native.DependencyRoleMap({})
        base = "aegis-fixture-external-" + "a" * 64
        # Force the defensive collision branch independently of the name-count guard.
        mapper.queries = {base + ("" if index == 0 else "-" + str(index)) + ".service": "reserved"
                          for index in range(513)}
        before = dict(mapper.queries)
        with patch.object(native.hashlib, "sha256", return_value=SimpleNamespace(hexdigest=lambda: "a" * 64)):
            with self.assertRaisesRegex(AssertionError, "^dependency_mapping_bound$"):
                mapper.logical("new.service")
        self.assertEqual(mapper.queries, before)
        self.assertEqual(mapper.names, {})

    def test_dependency_mapper_preserves_mixed_edges_and_queries_real_names(self):
        from deploy.wazuh.tests import test_native as native
        roles = {"ufw.service": "owned-ufw.service", native.uh.GUARD: "owned-guard.service",
                 native.uh.INDEXER: "owned-indexer.service", "bridge.service": "owned-bridge.service"}
        actual = {unit: {key: "" for key in native.uh.DEPENDENCIES} for unit in [*roles.values(), "ufw.service", "system.slice"]}
        actual["owned-guard.service"]["RequiredBy"] = "owned-bridge.service"
        actual["owned-bridge.service"]["Requires"] = "owned-guard.service system.slice"
        actual["owned-bridge.service"]["PropagatesStopTo"] = "owned-ufw.service"
        actual["owned-ufw.service"]["StopPropagatedFrom"] = "owned-bridge.service"
        actual["system.slice"]["Before"] = "ufw.service"
        queries = []
        class Reader:
            def properties(self, name, keys): return {"LoadState": "loaded"}
            def dependency_properties(self, name):
                queries.append(name)
                return actual[name]
        host = native.MappedDependencyHost(Reader(), roles)
        bridge = host.dependency_properties("bridge.service")
        names = bridge["Requires"].split()
        self.assertIn(native.uh.GUARD, names)
        external = next(name for name in names if name != native.uh.GUARD)
        related = host.dependency_properties(external)["Before"]
        self.assertNotEqual(related, "ufw.service")
        self.assertEqual(host.mapping.actual(related), "ufw.service")
        self.assertEqual(queries, ["owned-bridge.service", "system.slice"])
        self.assertEqual(host.raw["owned-bridge.service"]["Requires"], ["owned-guard.service", "system.slice"])
        with self.assertRaisesRegex(native.SetupError, "ufw_unsupported"):
            native.uh.UfwHostReader(host).dependency_facts()

    def test_generated_guard_drivers_recheck_identity_at_later_nft_execution(self):
        from deploy.wazuh.tests import test_native as native
        module = ast.parse(Path(native.__file__).read_text(encoding="utf-8"))
        context = dict(vars(native), source=Path("/run/owned/source"), root=Path("/run/owned/root"),
                       profile=Path("/run/owned/profile"), record=Path("/run/owned/record"),
                       profile_path=Path("/run/owned/profile"), audit=Path("/run/owned/audit"),
                       fixture=SimpleNamespace(root=Path("/run/owned"), inode=123),
                       loader_mapping={"ufw.service": "owned-ufw.service"})
        programs = [eval(compile(ast.Expression(node.value), "fixture-expression", "eval"), context)
                    for node in ast.walk(module) if isinstance(node, ast.Assign) and
                    len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "driver"]
        self.assertEqual(len(programs), 2)
        raw = native.profile_dict()
        octet = native.secrets.randbelow(250) + 1
        raw.update(indexer_ip=f"10.{octet}.45.10", manager_ip=f"10.{octet}.45.20")
        profile = native.load_profile(native.tx.encoded(raw))
        for number, source in enumerate(programs):
            for later_uid, later_inode in ((0, 999), (1000, 123)):
                with self.subTest(driver=number, uid=later_uid, inode=later_inode):
                    identity = {"uid": 0, "inode": 123}
                    fake_os = SimpleNamespace(geteuid=lambda: identity["uid"],
                                              stat=lambda path: SimpleNamespace(st_ino=identity["inode"]))
                    fake_sys = SimpleNamespace(path=[], argv=["fixture-driver.py", "guard-ensure"])
                    host = SimpleNamespace(LinuxHost=native.h.LinuxHost, Commands=native.h.Commands)
                    def importing(name, *args, **kwargs):
                        if name == "os": return fake_os
                        if name == "sys": return fake_sys
                        if name == "https_setup": return SimpleNamespace(host=host, ufw=SimpleNamespace(), ufw_host=SimpleNamespace())
                        if name == "https_setup.cli": return SimpleNamespace(main=lambda: 71)
                        if name == "deploy.wazuh.tests.test_ufw":
                            return SimpleNamespace(FakeReader=type("FakeReader", (), {}), loaders=lambda: {})
                        return builtins.__import__(name, *args, **kwargs)
                    # Both generated startup checks succeed with the correct identity.
                    with self.assertRaises(SystemExit) as initialized:
                        exec(compile(source, "generated-guard-driver", "exec"),
                             {"__builtins__": {**vars(builtins), "__import__": importing}})
                    self.assertEqual(initialized.exception.code, 71)
                    instance = host.LinuxHost()
                    instance.verify_installed_firewall_compatibility = lambda p: None
                    instance.firewall = lambda: {"nftables": []}
                    # Model a later identity change, after driver/host initialization.
                    identity.update(uid=later_uid, inode=later_inode)
                    with patch.object(instance.fs, "trusted"), \
                            patch.object(native.h.Path, "resolve", return_value=Path("/usr/sbin/nft")), \
                            patch.object(native.h.subprocess, "Popen", side_effect=AssertionError("NFT_EXECUTED")) as execute:
                        with self.assertRaisesRegex(AssertionError, "fixture_namespace_required"):
                            instance.ensure_guard(profile)  # real guard -> run -> execution boundary
                        execute.assert_not_called()
                    identity.update(uid=0, inode=123)
                    with patch.object(native.h.Commands, "_execute", return_value=(b"observed", b"warning")) as inherited:
                        result = instance.commands._execute("/actual/nft", ("--file", "-"), data=b"batch", argv0="nft")
                    self.assertEqual(result, (b"observed", b"warning"))
                    inherited.assert_called_once_with("/actual/nft", ("--file", "-"), data=b"batch", argv0="nft")

    def test_generated_native_programs_compile_without_linux_execution(self):
        from deploy.wazuh.tests import test_native as native
        module = ast.parse(Path(native.__file__).read_text(encoding="utf-8"))
        context = dict(vars(native), source=Path("/run/owned/source"), root=Path("/run/owned/root"),
                       profile=Path("/run/owned/profile"), record=Path("/run/owned/record"),
                       profile_path=Path("/run/owned/profile"), audit=Path("/run/owned/audit"),
                       fixture=SimpleNamespace(root=Path("/run/owned"), inode=123),
                       loader_mapping={"ufw.service": "owned-ufw.service"})
        checked = []
        for node in ast.walk(module):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            name = node.targets[0].id
            if name not in {"driver", "code", "LISTENER", "CLIENT", "ASSERT_NAMESPACE"} or not isinstance(node.value, (ast.Constant, ast.JoinedStr)):
                continue
            value = eval(compile(ast.Expression(node.value), "fixture-expression", "eval"), context)
            if isinstance(value, str):
                compile(value, "fixture-program-" + name, "exec")
                checked.append(name)
        self.assertEqual(sorted(checked), sorted(["driver", "driver", "code", "LISTENER", "CLIENT", "ASSERT_NAMESPACE"]))
        # This inline executor verifies the namespace in the same process as nft.
        fixture = object.__new__(native.NetworkFixture)
        fixture.server, fixture.inode = "owned-server", 123
        calls = []
        fixture.net = lambda *args, **kwargs: calls.append(args)
        fixture.nft("list", "ruleset")
        program = calls[0][5]
        compile(program, "fixture-nft-executor", "exec")
        executed = []
        fake_os = SimpleNamespace(geteuid=lambda: 0, stat=lambda path: SimpleNamespace(st_ino=999),
                                  execvp=lambda *args: executed.append(args))
        fake_sys = SimpleNamespace(argv=["-c", "123", "list", "ruleset"])
        def importing(name, *args, **kwargs):
            return {"os": fake_os, "sys": fake_sys}[name]
        with self.assertRaises(AssertionError):
            exec(program, {"__builtins__": {**vars(builtins), "__import__": importing}})
        self.assertEqual(executed, [])

    def test_generated_synthetic_driver_binds_the_explicit_fixture_host(self):
        from deploy.wazuh.tests import test_native as native
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = SimpleNamespace(root=root, inode=123, server="synthetic-server",
                                      profile=SimpleNamespace(as_dict=lambda: {}), net=lambda *a, **k: None)
            def write(path, body, *args):
                path = Path(path)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
            with patch.dict(os.environ, {"AEGIS_NATIVE_SOURCE_COMMIT": "f" * 40}), patch.object(native, "private_file", side_effect=write):
                path, _, _ = native.synthetic_guard_driver(fixture, root / "vendor-root", {})
            source = path.read_text()
            host = SimpleNamespace(LinuxHost=type("OriginalHost", (), {}), Commands=native.h.Commands)
            fake_os = SimpleNamespace(geteuid=lambda: 0, stat=lambda path: SimpleNamespace(st_ino=123))
            fake_sys = SimpleNamespace(path=[], argv=["fixture-driver.py", "guard-verify"])
            def importing(name, *args, **kwargs):
                if name == "os": return fake_os
                if name == "sys": return fake_sys
                if name == "https_setup": return SimpleNamespace(host=host, ufw=SimpleNamespace(), ufw_host=SimpleNamespace())
                if name == "https_setup.cli":
                    captured = host.LinuxHost
                    return SimpleNamespace(main=lambda: captured.__name__)
                if name == "deploy.wazuh.tests.test_ufw":
                    return SimpleNamespace(FakeReader=type("FakeReader", (), {}), loaders=lambda: {})
                return builtins.__import__(name, *args, **kwargs)
            with self.assertRaises(SystemExit) as result:
                exec(compile(source, "generated-fixture-driver", "exec"),
                     {"__builtins__": {**vars(builtins), "__import__": importing}})
            self.assertEqual(result.exception.code, "FixtureHost")

    def test_unknown_systemd_state_refuses_before_namespace_mutation(self):
        from deploy.wazuh.tests import test_native as native
        with patch.object(native.os.path, "lexists", return_value=False), \
                patch.object(native, "command", return_value=SimpleNamespace(returncode=1, stdout=b"")):
            with self.assertRaisesRegex(AssertionError, "real_wazuh_unit_refused"):
                native.disposable_fence()

    def test_real_wazuh_path_refuses_without_host_commands(self):
        from deploy.wazuh.tests import test_native as native
        with patch.object(native.os.path, "lexists", return_value=True), patch.object(native, "command") as commands:
            with self.assertRaisesRegex(AssertionError, "real_wazuh_footprint_refused"):
                native.disposable_fence()
            commands.assert_not_called()

    def test_real_wazuh_unit_or_package_refuses(self):
        from deploy.wazuh.tests import test_native as native
        with patch.object(native.os.path, "lexists", return_value=False):
            with patch.object(native, "command", return_value=SimpleNamespace(returncode=0, stdout=b"loaded")):
                with self.assertRaisesRegex(AssertionError, "real_wazuh_unit_refused"):
                    native.disposable_fence()
            replies = [SimpleNamespace(returncode=0, stdout=b"not-found")] * 3
            replies += [SimpleNamespace(returncode=0, stdout=b"installed\n")]
            with patch.object(native, "command", side_effect=replies):
                with self.assertRaisesRegex(AssertionError, "real_wazuh_package_refused"):
                    native.disposable_fence()
