"""Portable synthetic operator tests: never invoke a live privileged command."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import stat
from unittest.mock import patch
import io
import zipfile
import sys
import gzip
import tarfile
import errno
from contextlib import contextmanager
import unittest

from deploy.wazuh.https_setup.contracts import Profile, SetupError
from deploy.wazuh.tests.test_components import profile_dict


class SyntheticHost:
    """External host boundary: files, services and firewall are synthetic state."""
    def __init__(self):
        self.p = Profile(**profile_dict())
        self.facts = {"hostname": self.p.hostname, "config": "a" * 64,
                      "firewall": {"nftables": []}, "archive": {"ino": 12}}
        self.events = []
        self.guard = False
        self.listener = "loopback"
        self.config = "old"
        self.fail = None
        self.interrupt = None

    def event(self, name):
        self.events.append(name)
        if self.interrupt == name:
            raise KeyboardInterrupt()
        if self.fail == name:
            raise SetupError("host_unsupported")

    def preflight(self, path):
        self.event("preflight")
        return self.p, "a" * 64, copy.deepcopy(self.facts)

    def prepare_state(self):
        self.event("prepare_state")

    def capture(self, p, facts, work):
        self.event("capture")
        return {"original": "old"}

    def stage(self, p, facts, work):
        self.event("stage")
        return {"staged": True}

    def install(self, p, staged, work):
        self.event("install")

    def ensure_guard(self, p):
        self.event("guard")
        self.guard = True

    def verify_guard(self, p):
        self.event("verify_guard")
        if not self.guard:
            raise SetupError("firewall_mismatch")

    def install_units(self, p, work):
        self.event("units")

    def patch_config(self, p, work):
        self.event("patch")
        if not self.guard:
            raise AssertionError("configuration changed without guard")
        self.config = "new"

    def restart(self):
        self.event("restart")
        if self.config == "new" and not self.guard:
            raise AssertionError("unguarded listener")
        self.listener = "approved" if self.config == "new" else "loopback"

    def verify(self, p, facts, work, *, restored=False):
        self.event("verify_old" if restored else "verify_new")
        if self.listener != ("loopback" if restored else "approved"):
            raise SetupError("verification_failed")

    def restore(self, p, snapshot, work):
        self.event("restore")
        self.config = snapshot["original"]

    def remove_guard(self, p):
        self.event("remove_guard")
        if self.listener != "loopback":
            raise AssertionError("guard removed before old service verified")
        self.guard = False

    def cleanup(self, work):
        self.events.append("cleanup")

    def restore_firewall_compatibility(self, p, snapshot, work):
        self.event("restore_compatibility")


class TransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.t = importlib.import_module("deploy.wazuh.https_setup.transaction")
            cls.h = importlib.import_module("deploy.wazuh.https_setup.host")
        except ModuleNotFoundError:
            cls.t = cls.h = None

    def setUp(self):
        self.assertIsNotNone(self.t, "Task 2 coordinator is not implemented")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.host = SyntheticHost()
        self.syncs = []
        self.store = self.t.DurableStore(Path(self.temp.name) / "state",
                                        sync_directory=lambda p: self.syncs.append(str(p)))
        self.c = self.t.Coordinator(self.host, self.store)

    def apply(self):
        check = self.c.check("profile")
        return self.c.apply("profile", check["profile_sha256"], check["check_sha256"])

    def test_check_is_stable_and_creates_no_files(self):
        first = self.c.check("profile")
        self.assertEqual(first, self.c.check("profile"))
        self.assertEqual(first["status"], "ready")
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])
        self.assertEqual(self.host.events, ["preflight", "preflight"])

    def test_frozen_profile_and_host_drift_refuse_before_mutations(self):
        frozen = self.c.check("profile")
        for profile_hash, check_hash in [("b" * 64, frozen["check_sha256"]),
                                          (frozen["profile_sha256"], "b" * 64)]:
            with self.assertRaisesRegex(SetupError, "state_changed"):
                self.c.apply("profile", profile_hash, check_hash)
        self.host.facts["config"] = "c" * 64
        with self.assertRaisesRegex(SetupError, "state_changed"):
            self.c.apply("profile", frozen["profile_sha256"], frozen["check_sha256"])
        self.assertNotIn("capture", self.host.events)
        self.assertIsNone(self.store.read())

    def test_guard_precedes_config_and_restart_success_stays_pending(self):
        result = self.apply()
        self.assertEqual(result["status"], "pending_external_validation")
        self.assertEqual(self.c.status()["status"], "pending_external_validation")
        self.assertTrue(self.host.guard)
        self.assertEqual(self.host.listener, "approved")
        events = self.host.events
        self.assertLess(events.index("guard"), events.index("patch"))
        self.assertLess(events.index("verify_guard"), events.index("restart"))
        self.assertGreater(len(self.syncs), 10)

    def test_unresolved_intent_blocks_blind_retry(self):
        self.apply()
        with self.assertRaisesRegex(SetupError, "intent_exists"):
            self.c.apply("profile", "a" * 64, "b" * 64)

    def test_concurrent_operators_refuse(self):
        self.host.prepare_state()
        with self.store.lock():
            with self.assertRaisesRegex(SetupError, "operation_locked"):
                self.c.rollback()

    def test_rollback_verifies_original_service_before_guard_removal(self):
        self.apply()
        result = self.c.rollback()
        self.assertEqual(result["status"], "rolled_back")
        self.assertFalse(self.host.guard)
        self.assertEqual(self.host.config, "old")
        self.assertLess(self.host.events.index("verify_old"), self.host.events.index("remove_guard"))
        self.assertLess(self.host.events.index("remove_guard"), self.host.events.index("restore_compatibility"))

    def test_failure_each_mutating_phase_rolls_back(self):
        for phase in ("stage", "install", "guard", "verify_guard", "units", "patch", "restart", "verify_new"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                host = SyntheticHost()
                store = self.t.DurableStore(Path(temporary) / "state", sync_directory=lambda p: None)
                c = self.t.Coordinator(host, store)
                frozen = c.check("profile")
                host.fail = phase
                with self.assertRaises(SetupError):
                    c.apply("profile", frozen["profile_sha256"], frozen["check_sha256"])
                # Restart failure also prevents recovery restart: retain guard.
                expected = "recovery_required" if phase == "restart" else "rolled_back"
                self.assertEqual(c.status()["status"], expected)
                if expected == "recovery_required":
                    self.assertTrue(host.guard)
                else:
                    self.assertEqual(host.listener, "loopback")
                self.assertIn("cleanup", host.events)

    def test_interruption_keeps_durable_phase_and_requires_explicit_recovery(self):
        frozen = self.c.check("profile")
        self.host.interrupt = "restart"
        with self.assertRaisesRegex(SetupError, "recovery_required"):
            self.c.apply("profile", frozen["profile_sha256"], frozen["check_sha256"])
        intent = self.store.read()
        self.assertEqual(intent["status"], "recovery_required")
        self.assertEqual(intent["phase"], "restart")
        self.assertTrue(self.host.guard)
        self.host.interrupt = None
        self.assertEqual(self.c.rollback()["status"], "rolled_back")

    def test_uncertain_recovery_never_removes_guard(self):
        for phase in ("restore", "restart", "verify_old", "remove_guard", "restore_compatibility"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                host = SyntheticHost()
                store = self.t.DurableStore(Path(temporary) / "state", sync_directory=lambda p: None)
                c = self.t.Coordinator(host, store)
                frozen = c.check("profile")
                c.apply("profile", frozen["profile_sha256"], frozen["check_sha256"])
                host.fail = phase
                with self.assertRaisesRegex(SetupError, "recovery_required"):
                    c.rollback()
                self.assertTrue(host.guard)
                self.assertEqual(c.status()["status"], "recovery_required")

    def test_intent_written_before_side_effect(self):
        original = self.host.event
        phases = {"capture": "backup", "stage": "stage", "install": "install",
                  "guard": "guard", "units": "units", "patch": "patch", "restart": "restart"}
        def observed(name):
            if name in phases:
                self.assertEqual(self.store.read()["phase"], phases[name])
            original(name)
        self.host.event = observed
        self.apply()

    def test_socket_mapped_ipv4_normalization_is_narrow(self):
        text = "LISTEN 0 4096 [::ffff:127.0.0.1]:9200 *:*\nLISTEN 0 4096 [::ffff:127.0.0.1]:9300 *:*\n"
        self.h.verify_listeners(text, self.host.p, expanded=False)
        text += "LISTEN 0 4096 [::ffff:192.0.2.10]:9200 *:*\n"
        self.h.verify_listeners(text, self.host.p, expanded=True)
        for bad in ("[::]:9200", "0.0.0.0:9200", "[::1]:9200", "*:9200"):
            with self.subTest(bad=bad), self.assertRaisesRegex(SetupError, "listeners_unsupported"):
                self.h.verify_listeners(text + f"LISTEN 0 128 {bad} *:*\n", self.host.p, expanded=True)

    def test_firewall_digest_discards_counter_values_not_semantics(self):
        original = {"nftables": [{"rule": {"handle": 4, "expr": [{"counter": {"packets": 2, "bytes": 5}}, {"drop": None}]}}]}
        advanced = copy.deepcopy(original)
        advanced["nftables"][0]["rule"]["expr"][0]["counter"]["packets"] = 100
        self.assertEqual(self.h.stable_firewall(original), self.h.stable_firewall(advanced))
        removed = copy.deepcopy(original)
        removed["nftables"][0]["rule"]["expr"].pop(0)
        self.assertNotEqual(self.h.stable_firewall(original), self.h.stable_firewall(removed))
        removed["nftables"][0]["rule"]["expr"] = [{"accept": None}]
        self.assertNotEqual(self.h.stable_firewall(original), self.h.stable_firewall(removed))

    def test_filesystem_rejects_links_writable_ancestors_and_wrong_owners(self):
        good = SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=0, st_gid=123, st_nlink=1)
        self.h.validate_metadata(good, owners={0, 123}, private=False)
        for changes in ({"st_uid": 456}, {"st_mode": stat.S_IFLNK | 0o777},
                        {"st_nlink": 2}, {"st_mode": stat.S_IFREG | 0o660}):
            with self.subTest(changes=changes), self.assertRaisesRegex(SetupError, "path_untrusted"):
                self.h.validate_metadata(SimpleNamespace(**(vars(good) | changes)), owners={0, 123})
        with self.assertRaisesRegex(SetupError, "path_untrusted"):
            self.h.validate_metadata(good, owners={0}, private=True)
        for mode, uid in [(0o777, 0), (0o775, 0), (0o755, 123)]:
            info = SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid, st_gid=0, st_nlink=2)
            with self.assertRaisesRegex(SetupError, "path_untrusted"):
                self.h.validate_metadata(info, owners={0}, directory=True)

    def test_unit_sandbox_rejects_root_prestart_incompatible_context(self):
        props = {"User": "wazuh-indexer", "Group": "wazuh-indexer", "ActiveState": "active",
                 "LoadState": "loaded", "FragmentPath": "/usr/lib/systemd/system/wazuh-indexer.service",
                 "CapabilityBoundingSet": "cap_net_admin cap_dac_override",
                 "RootDirectory": "", "RootImage": "", "ExecStartPre": "", "DropInPaths": "",
                 "ReadOnlyPaths": "", "InaccessiblePaths": "", "BindPaths": "", "BindReadOnlyPaths": "",
                 "RestrictAddressFamilies": "", "SystemCallFilter": "", "PrivateNetwork": "no",
                 "NoNewPrivileges": "no", "ProtectHome": "no", "ProtectSystem": "no", "DynamicUser": "no",
                 "PrivateUsers": "no", "IPAddressDeny": "", "NetworkNamespacePath": ""}
        self.h.validate_unit(props)
        for key, value in [("User", "root"), ("RootDirectory", "/alternate"),
                           ("PrivateNetwork", "yes"), ("NoNewPrivileges", "yes"),
                           ("ProtectHome", "yes"), ("ExecStartPre", "/arbitrary"),
                           ("DropInPaths", "/unreviewed.conf"), ("CapabilityBoundingSet", "CAP_CHOWN")]:
            with self.subTest(key=key), self.assertRaisesRegex(SetupError, "host_unsupported"):
                self.h.validate_unit(props | {key: value})

    def test_exact_identity_and_versions_required(self):
        p = self.host.p
        self.h.validate_identity(p, p.hostname, "4.14.4-1", "2.19.4", [p.indexer_ip])
        for hostname, wazuh, search, addresses in [("other", "4.14.4-1", "2.19.4", [p.indexer_ip]),
                (p.hostname, "4.14.3-1", "2.19.4", [p.indexer_ip]),
                (p.hostname, "4.14.4-1", "2.19.3", [p.indexer_ip]),
                (p.hostname, "4.14.4-1", "2.19.4", [])]:
            with self.assertRaisesRegex(SetupError, "host_unsupported"):
                self.h.validate_identity(p, hostname, wazuh, search, addresses)

    def test_cli_sanitizes_unexpected_errors_and_requires_frozen_arguments(self):
        try:
            cli = importlib.import_module("deploy.wazuh.https_setup.cli")
        except ModuleNotFoundError:
            self.fail("CLI has not been implemented")
        output = io.StringIO()
        with patch("sys.stdout", output):
            rc = cli.main(["apply", "--profile", "synthetic"], coordinator=self.c)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("synthetic", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["error"], "profile_invalid")
        self.host.preflight = lambda _: (_ for _ in ()).throw(ValueError("PRIVATE-MARKER"))
        output = io.StringIO()
        with patch("sys.stdout", output):
            rc = cli.main(["check", "--profile", "synthetic"], coordinator=self.c)
        self.assertEqual(json.loads(output.getvalue()), {"status": "error", "error": "setup_failed"})
        self.assertNotEqual(rc, 0)

    def test_guard_conflict_is_never_replaced_and_verify_never_adds_table(self):
        host = self.h.LinuxHost(fs=object(), commands=object())
        host.verify_installed_firewall_compatibility = lambda p: None  # Firewall-only boundary.
        mutations = []
        host.firewall = lambda: {"nftables": [{"table": {"family": "inet", "name": "aegis_wazuh_http_v1"}}]}
        host.run = lambda *args, **kwargs: mutations.append(args)
        with self.assertRaisesRegex(SetupError, "firewall_mismatch"):
            host.ensure_guard(self.host.p)
        self.assertEqual(mutations, [])
        host.firewall = lambda: {"nftables": []}
        with self.assertRaisesRegex(SetupError, "firewall_mismatch"):
            host.verify_guard(self.host.p)
        self.assertEqual(mutations, [])

    def test_manifest_rejects_extra_files_changed_code_and_missing_pins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bodies = {name: b"synthetic code" for name in self.h.KIT_FILES}
            manifest = {"schema_version": 1, "source_commit": "a" * 40, "native_proof": None,
                        "files": {name: hashlib.sha256(body).hexdigest() for name, body in bodies.items()}}
            class Files:
                def read(_, path, **kwargs):
                    return json.dumps(manifest).encode() if path.name == "KIT-MANIFEST.json" else bodies[str(path.relative_to(root)).replace("\\", "/")]
            host = self.h.LinuxHost(fs=Files(), commands=object(), bundle=root)
            self.assertEqual(len(self.h.KIT_FILES), 10)
            self.assertEqual(len(host.bundle_files()), 11)
            for name in ("https_setup/ufw.py", "https_setup/ufw_host.py"):
                pin = manifest["files"].pop(name)
                with self.assertRaisesRegex(SetupError, "manifest_invalid"):
                    host.bundle_files()
                manifest["files"][name] = pin
            manifest["files"]["unrelated.py"] = "b" * 64
            with self.assertRaisesRegex(SetupError, "manifest_invalid"):
                host.bundle_files()
            del manifest["files"]["unrelated.py"]
            bodies["Setup-Wazuh-HTTPS.py"] = b"changed"
            with self.assertRaisesRegex(SetupError, "manifest_invalid"):
                host.bundle_files()

    def test_archive_inode_swap_is_refused_before_and_after_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "archive.tar"
            path.write_bytes(b"synthetic archive")
            frozen = self.h.identity(path.stat())
            fs = self.h.SecureFS()
            fs.archive_stat = lambda _: frozen
            with patch.object(self.h.os, "O_NOFOLLOW", 0, create=True), patch.object(self.h.os, "fstat", lambda _: path.stat()):
                with fs.archive(path, frozen) as stream:
                    self.assertEqual(stream.read(2), b"sy")
                with self.assertRaisesRegex(SetupError, "state_changed"):
                    with fs.archive(path, frozen | {"ino": -1}):
                        self.fail("changed inode was opened")
                with self.assertRaisesRegex(SetupError, "state_changed"):
                    with fs.archive(path, frozen):
                        path.write_bytes(b"altered")

    def test_vendor_exception_requires_exact_service_identity_and_no_other_write(self):
        good = SimpleNamespace(st_mode=stat.S_IFREG | 0o660, st_uid=123, st_gid=123, st_nlink=1)
        self.h.validate_vendor_metadata(good, uid=123, gid=123)
        for change in ({"st_gid": 456}, {"st_uid": 456}, {"st_mode": stat.S_IFREG | 0o662},
                       {"st_mode": stat.S_IFLNK | 0o777}, {"st_nlink": 2}):
            with self.subTest(change=change), self.assertRaisesRegex(SetupError, "path_untrusted"):
                self.h.validate_vendor_metadata(SimpleNamespace(**(vars(good) | change)), uid=123, gid=123)

    def test_guard_profile_has_root_controlled_parent(self):
        from deploy.wazuh.https_setup.firewall import guard_unit, indexer_dropin
        for unit in (guard_unit(), indexer_dropin()):
            self.assertIn("--profile /etc/aegis-wazuh-https/profile.json", unit)
            self.assertNotIn("--profile /etc/wazuh-indexer/", unit)

    def test_interrupt_after_each_side_effect_retains_recoverable_state(self):
        for phase in ("capture", "stage", "install", "ensure_guard", "install_units", "patch_config", "restart", "verify"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                host = SyntheticHost()
                store = self.t.DurableStore(Path(temporary) / "state", sync_directory=lambda p: None)
                c = self.t.Coordinator(host, store)
                frozen = c.check("profile")
                original = getattr(host, phase)
                def interrupted(*args, **kwargs):
                    original(*args, **kwargs)
                    raise KeyboardInterrupt()
                setattr(host, phase, interrupted)
                with self.assertRaisesRegex(SetupError, "recovery_required"):
                    c.apply("profile", frozen["profile_sha256"], frozen["check_sha256"])
                self.assertEqual(c.status()["status"], "recovery_required")
                self.assertTrue(host.guard or host.listener == "loopback")
                setattr(host, phase, original)
                # An interrupt before capture returns leaves an incomplete backup;
                # retain evidence for human inspection, never invent a snapshot.
                if phase != "capture":
                    self.assertEqual(c.rollback()["status"], "rolled_back")

    def test_preflight_reads_no_archive_or_private_key_and_requires_exact_versions(self):
        raw = profile_dict() | {"indexer_ip": "10.23.45.10", "manager_ip": "10.23.45.20",
              "expected_ca_file_sha256": hashlib.sha256(b"-----BEGIN CERTIFICATE-----\nY2E=\n-----END CERTIFICATE-----\n").hexdigest(),
              "expected_ca_der_sha256": hashlib.sha256(b"ca").hexdigest(),
              "expected_leaf_der_sha256": hashlib.sha256(b"leaf").hexdigest()}
        files = {"profile": json.dumps(raw).encode(), raw["ca_path"]: b"-----BEGIN CERTIFICATE-----\nY2E=\n-----END CERTIFICATE-----\n",
                 raw["leaf_path"]: b"-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----\n"}
        config = ("network.host: 127.0.0.1\nplugins.security.ssl.http.enabled: true\n"
                  "plugins.security.ssl.http.pemcert_filepath: certs/indexer.pem\n"
                  "plugins.security.ssl.http.pemkey_filepath: certs/indexer-key.pem\n"
                  "plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem\n"
                  "plugins.security.ssl.transport.pemcert_filepath: certs/indexer.pem\n"
                  "plugins.security.ssl.transport.pemkey_filepath: certs/indexer-key.pem\n"
                  "plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem\n").encode()
        files[raw["config_path"]] = config
        props = {k: "" for k in self.h.UNIT_EMPTY} | {k: "no" for k in self.h.UNIT_NO} | {
            "User": "wazuh-indexer", "Group": "wazuh-indexer", "ActiveState": "active", "LoadState": "loaded",
            "FragmentPath": "/usr/lib/systemd/system/wazuh-indexer.service", "CapabilityBoundingSet": "cap_net_admin cap_dac_override"}
        files[props["FragmentPath"]] = (b"[Service]\nEnvironment=OPENSEARCH_PATH_CONF=/etc/wazuh-indexer\n"
            b"ExecStart=/usr/share/wazuh-indexer/bin/systemd-entrypoint -p ${PID_DIR}/wazuh-indexer.pid --quiet\n")
        jar = io.BytesIO()
        with zipfile.ZipFile(jar, "w") as zipped:
            zipped.writestr("META-INF/MANIFEST.MF", "Implementation-Version: 2.19.4\n")
        files["/usr/share/wazuh-indexer/lib/opensearch-2.19.4.jar"] = jar.getvalue()
        calls = []
        class Files:
            def read(_, path, **kwargs):
                name = str(path).replace("\\", "/")
                calls.append(("read", name))
                return files[name]
            def vendor_read(_, path, uid, gid):
                return _.read(path)
            def trusted(_, path, **kwargs):
                return SimpleNamespace(**{"st_" + k: v for k, v in dict(dev=1, ino=1, mode=stat.S_IFREG | 0o660,
                    uid=123, gid=123, nlink=1, size=123, mtime_ns=100, ctime_ns=100).items()})
            def vendor_stat(_, path, uid, gid):
                return _.trusted(path)
            def resolve(_, path):
                return Path(path)
            def archive_stat(_, path):
                calls.append(("archive_stat", str(path)))
                return {"ino": 77, "size": 1234}
        host = self.h.LinuxHost(fs=Files(), commands=object())
        host.require_root = lambda: None
        def account():
            host.uid = host.gid = 123
        host.service_identity = account
        host.bundle_files = lambda **kwargs: {"synthetic.py": b"synthetic"}
        host.properties = lambda unit, keys: props if unit == "wazuh-indexer.service" else {
            "ActiveState": "inactive", "UnitFileState": "disabled", "LoadState": "loaded"}
        version = "4.14.4-1"
        def run(name, *args, **kwargs):
            if name == "dpkg-query":
                return version.encode()
            if name == "ip":
                return json.dumps([{"addr_info": [{"family": "inet", "local": raw["indexer_ip"]}]}]).encode()
            if name == "ss":
                return b"LISTEN 0 128 [::ffff:127.0.0.1]:9200 *:*\nLISTEN 0 128 [::ffff:127.0.0.1]:9300 *:*\n"
            if name == "nft":
                return b'{"nftables":[]}'
            self.fail("unexpected command")
        host.run = run
        with patch.object(self.h.socket, "gethostname", return_value=raw["hostname"]):
            p, pin, facts = host.preflight("profile")
            self.assertEqual(pin, hashlib.sha256(files["profile"]).hexdigest())
            self.assertEqual(facts["archive"], {"ino": 77, "size": 1234})
            self.assertNotIn(("read", raw["ca_archive"]), calls)
            self.assertFalse(any("key.pem" in path for action, path in calls if action == "read"))
            version = "4.14.3-1"
            with self.assertRaisesRegex(SetupError, "host_unsupported"):
                host.preflight("profile")

    def test_named_counter_values_do_not_change_frozen_firewall(self):
        a = {"nftables": [{"counter": {"family": "inet", "table": "other", "name": "hits", "packets": 1, "bytes": 42}}]}
        b = copy.deepcopy(a)
        b["nftables"][0]["counter"]["packets"] = 900
        self.assertEqual(self.h.stable_firewall(a), self.h.stable_firewall(b))

    def test_uncertain_guard_removal_rearms_rules(self):
        self.apply()
        original = self.host.remove_guard
        def failed_after_delete(p):
            original(p)
            raise OSError("synthetic lost acknowledgment")
        self.host.remove_guard = failed_after_delete
        with self.assertRaisesRegex(SetupError, "recovery_required"):
            self.c.rollback()
        self.assertTrue(self.host.guard)
        self.assertEqual(self.c.status()["status"], "recovery_required")

    def test_environment_override_refuses_without_returning_secret_body(self):
        bodies = {"/etc/default/wazuh-indexer": b"PRIVATE_TOKEN=PRIVATE-MARKER\nOPENSEARCH_PATH_CONF=/alternate\n"}
        class Files:
            def trusted(_, path, **kwargs):
                return object() if str(path) in bodies else None
            def read(_, path, **kwargs):
                return bodies[str(path)]
        host = self.h.LinuxHost(fs=Files(), commands=object())
        unit = (b"Environment=OPENSEARCH_PATH_CONF=/etc/wazuh-indexer\n"
                b"EnvironmentFile=-/etc/default/wazuh-indexer\n"
                b"ExecStart=/usr/share/wazuh-indexer/bin/systemd-entrypoint -p ${PID_DIR}/wazuh-indexer.pid --quiet\n")
        with self.assertRaisesRegex(SetupError, "host_unsupported"):
            host.startup_environment(unit, self.host.p)
        bodies["/etc/default/wazuh-indexer"] = b"PRIVATE_TOKEN=PRIVATE-MARKER\n"
        facts = host.startup_environment(unit, self.host.p)
        self.assertNotIn("PRIVATE", json.dumps(facts))
        bodies.clear()
        self.assertEqual(host.startup_environment(unit, self.host.p), {"/etc/default/wazuh-indexer": None})

    def test_key_read_group_must_have_no_other_members(self):
        service = SimpleNamespace(pw_name="wazuh-indexer", pw_uid=123, pw_gid=123)
        group = SimpleNamespace(gr_name="wazuh-indexer", gr_mem=[])
        users = [service]
        pwd = SimpleNamespace(getpwnam=lambda _: service, getpwall=lambda: users)
        grp = SimpleNamespace(getgrgid=lambda _: group)
        host = self.h.LinuxHost(fs=object(), commands=object())
        with patch.dict(sys.modules, {"pwd": pwd, "grp": grp}):
            host.service_identity()
            group.gr_mem = ["other-user"]
            with self.assertRaisesRegex(SetupError, "host_unsupported"):
                host.service_identity()
            group.gr_mem = []
            users.append(SimpleNamespace(pw_name="other-user", pw_uid=456, pw_gid=123))
            with self.assertRaisesRegex(SetupError, "host_unsupported"):
                host.service_identity()

    def test_guard_creation_uses_exclusive_batch(self):
        from deploy.wazuh.https_setup.firewall import _expected
        host = self.h.LinuxHost(fs=object(), commands=object())
        host.verify_installed_firewall_compatibility = lambda p: None  # Firewall-only boundary.
        state = {"nftables": []}
        host.firewall = lambda: state
        observed = []
        def run(name, *args, data=None):
            nonlocal state
            observed.append(data)
            if "--check" not in args:
                state = {"nftables": _expected(self.host.p)}
        host.run = run
        host.ensure_guard(self.host.p)
        self.assertEqual(len(observed), 2)
        for body in observed:
            lines = body.splitlines()
            self.assertEqual(lines[0], b"create table inet aegis_wazuh_http_v1")
            self.assertTrue(lines[1].startswith(b"add chain inet aegis_wazuh_http_v1 input "))
            self.assertEqual(sum(line.startswith(b"add rule inet aegis_wazuh_http_v1 input ") for line in lines), 3)
        self.assertEqual(observed[0], observed[1])

    def test_config_metadata_drift_after_signing_refuses_patch(self):
        from deploy.wazuh.https_setup.contracts import patch_http_config
        original = b"network.host: 127.0.0.1\n"
        props = dict(dev=1, ino=1, mode=stat.S_IFREG | 0o660, uid=123, gid=123,
                     nlink=1, size=len(original), mtime_ns=1, ctime_ns=1)
        bodies = {"original.yml": original, "patched.yml": patch_http_config(original, self.host.p),
                  "original-metadata.json": json.dumps(props).encode()}
        writes = []
        class Files:
            def read(_, path, **kwargs):
                return bodies[path.name]
            def vendor_write(_, *args, **kwargs):
                writes.append(kwargs)
        host = self.h.LinuxHost(fs=Files(), commands=object())
        host.uid = host.gid = 123
        host.vstat = lambda _: SimpleNamespace(**{"st_" + k: v for k, v in props.items()})
        host.patch_config(self.host.p, Path("synthetic"))
        self.assertEqual(writes[0]["mode"], 0o660)
        writes.clear()
        props["mode"] = stat.S_IFREG | 0o640
        with self.assertRaisesRegex(SetupError, "vendor_drift"):
            host.patch_config(self.host.p, Path("synthetic"))
        self.assertEqual(writes, [])

    def test_stage_streams_selected_ca_only_and_never_persists_signing_key(self):
        from deploy.wazuh.tests.test_components import archive
        ca, key = b"synthetic CA", b"synthetic signing key"
        p = Profile(**(self.host.p.as_dict() | {"expected_ca_file_sha256": hashlib.sha256(ca).hexdigest()}))
        source = gzip.compress(archive([(p.ca_member, ca, tarfile.REGTYPE),
            ("unrelated/credentials.txt", b"UNRELATED-PRIVATE-MARKER", tarfile.REGTYPE),
            (p.key_member, key, tarfile.REGTYPE)]))
        writes = {}
        class Files:
            @contextmanager
            def archive(_, path, frozen):
                self.assertEqual(path, p.ca_archive)
                self.assertEqual(frozen, {"ino": 77})
                yield io.BytesIO(source)
            def vendor_read(_, path, uid, gid):
                return ca if path == p.ca_path else b"old synthetic leaf"
            def write(_, path, body):
                writes[path.name] = body
        host = self.h.LinuxHost(fs=Files(), commands=object())
        host.uid = host.gid = 123
        host.firewall = lambda: {"nftables": []}
        host.admit_firewall_loaders = lambda: None  # Signing-only boundary.
        facts = {"archive": {"ino": 77}, "firewall": {"nftables": []}, "bundle": {}, "ufw_compatibility": None}
        def signer(work, profile, actual_ca, actual_key, old):
            self.assertEqual((actual_ca, actual_key, old), (ca, key, b"old synthetic leaf"))
            return b"new leaf", b"new HTTP key"
        with patch.object(self.h, "create_http_certificate", signer):
            host.stage(p, facts, Path("synthetic"))
        self.assertEqual(writes, {"http.pem": b"new leaf", "http-key.pem": b"new HTTP key"})
        self.assertNotIn(key, writes.values())
        writes.clear()
        with patch.object(self.h, "create_http_certificate", side_effect=SetupError("certificate_invalid")):
            with self.assertRaisesRegex(SetupError, "certificate_invalid"):
                host.stage(p, facts, Path("synthetic"))
        self.assertEqual(writes, {})

    def test_recovery_unlinks_orphaned_ca_key_without_reading_it(self):
        work = Path(self.temp.name) / "work"
        issue = work / "issue-synthetic"
        issue.mkdir(parents=True)
        (issue / "ca-key.pem").write_bytes(b"SYNTHETIC-PRIVATE-KEY")
        (issue / "old.pem").write_bytes(b"synthetic public")
        class Files:
            def trusted(_, path):
                return path.stat()
            def unlink(_, path):
                path.unlink()
            def read(_, *args, **kwargs):
                self.fail("cleanup must not read signing material")
        host = self.h.LinuxHost(fs=Files(), commands=object())
        with patch.object(self.h, "fsync_directory", lambda _: None):
            host.cleanup(work)
        self.assertEqual(list(work.iterdir()), [])

    def test_refused_vendor_publication_never_overwrites_intervening_edit_in_recovery(self):
        frozen = self.c.check("profile")
        def refused(p, work):
            self.host.config = "intervening operator edit"
            raise SetupError("vendor_drift")
        self.host.patch_config = refused
        with self.assertRaisesRegex(SetupError, "recovery_required"):
            self.c.apply("profile", frozen["profile_sha256"], frozen["check_sha256"])
        self.assertEqual(self.host.config, "intervening operator edit")
        self.assertNotIn("restart", self.host.events)
        self.assertNotIn("restore", self.host.events)
        self.assertTrue(self.host.guard)
        with self.assertRaisesRegex(SetupError, "recovery_required"):
            self.c.rollback()
        self.assertEqual(self.host.config, "intervening operator edit")


class UfwHostIntegrationTests(unittest.TestCase):
    """Synthetic OS evidence; these are not native UFW qualification results."""
    def setUp(self):
        from deploy.wazuh.tests.test_ufw import FakeReader, loaders
        self.h = importlib.import_module("deploy.wazuh.https_setup.host")
        self.u = importlib.import_module("deploy.wazuh.https_setup.ufw")
        self.reader = FakeReader(self.u)
        self.states = loaders()
        self.host = self.h.LinuxHost(fs=object(), commands=object())
        self.p = Profile(**profile_dict())
        self.rules = {"nftables": [{"table": {"family": "ip", "name": "foreign"}}]}
        self.host.firewall = lambda: copy.deepcopy(self.rules)
        self.host.properties = lambda unit, keys: {k: self.states[unit][k] for k in keys}
        self.probe = {"file": {"sha256": "a" * 64}, "package_md5": "b" * 32}
        self.reader.probe_identity = lambda wrapper: copy.deepcopy(self.probe)
        self.reader.dependency_facts = lambda: {"ufw.service": {"After": []}}
        self.reader.validate_library_alias = lambda wrapper: None
        self.host.ufw_reader = lambda: self.reader
        self.record = None
        self.host.read_firewall_compatibility = lambda: copy.deepcopy(self.record)

    def admission(self):
        self.assertTrue(hasattr(self.host, "admit_firewall_loaders"), "Task 2 host admission missing")
        return self.host.admit_firewall_loaders()

    def pin(self):
        from deploy.wazuh.https_setup.transaction import digest
        self.record = {"schema_version": 1, "profile_sha256": digest(self.p.as_dict()),
                       "fingerprint": self.admission()}

    def test_strict_old_path_has_no_exception_record(self):
        self.states["ufw.service"].update(ActiveState="inactive", UnitFileState="disabled")
        self.assertIsNone(self.admission())

    def test_qualified_host_envelope_preserves_wrapper_and_foreign_rules(self):
        result = self.admission()
        self.assertEqual(set(result), {"wrapper", "probe", "dependencies", "foreign_firewall"})
        self.assertEqual(set(result["wrapper"]), {"schema_version", "package_version", "files", "unit", "backends"})
        self.assertEqual(result["foreign_firewall"], self.rules)
        self.assertEqual(result["probe"], self.probe)

    def test_active_wrapper_startup_cannot_bootstrap_missing_record(self):
        self.admission()
        with self.assertRaisesRegex(SetupError, "ufw_drift"):
            self.host.verify_installed_firewall_compatibility(self.p)

    def test_startup_requalifies_pinned_record_even_with_active_guard(self):
        from deploy.wazuh.https_setup.firewall import _expected
        self.pin()
        self.rules["nftables"].extend(_expected(self.p))
        self.host.verify_installed_firewall_compatibility(self.p)
        self.probe["package_md5"] = "c" * 32
        with self.assertRaisesRegex(SetupError, "ufw_drift"):
            self.host.verify_installed_firewall_compatibility(self.p)

    def test_partial_malformed_profile_mismatch_and_unknown_fields_refuse(self):
        self.pin()
        valid = copy.deepcopy(self.record)
        for record in ({}, [], valid | {"schema_version": True}, valid | {"profile_sha256": "f" * 64},
                       valid | {"extra": 1}, valid | {"fingerprint": {}},
                       valid | {"fingerprint": valid["fingerprint"] | {"extra": 1}}):
            with self.subTest(record=record):
                self.record = record
                with self.assertRaisesRegex(SetupError, "ufw_drift"):
                    self.host.verify_installed_firewall_compatibility(self.p)

    def test_present_record_does_not_fall_back_when_wrapper_disabled(self):
        self.pin()
        self.states["ufw.service"].update(ActiveState="inactive", UnitFileState="disabled")
        with self.assertRaises(SetupError):
            self.host.verify_installed_firewall_compatibility(self.p)
        self.record = {}
        with self.assertRaisesRegex(SetupError, "ufw_drift"):
            self.host.verify_installed_firewall_compatibility(self.p)

    def test_conflicting_loaders_and_foreign_drift_refuse(self):
        self.pin()
        self.states["nftables.service"]["ActiveState"] = "active"
        with self.assertRaises(SetupError):
            self.host.verify_installed_firewall_compatibility(self.p)
        self.states["nftables.service"]["ActiveState"] = "inactive"
        self.rules["nftables"].append({"table": {"family": "ip6", "name": "new"}})
        with self.assertRaisesRegex(SetupError, "ufw_drift"):
            self.host.verify_installed_firewall_compatibility(self.p)

    def test_both_guard_entrypoints_validate_before_table_io(self):
        self.admission()
        calls = []
        def refuse(p):
            calls.append("compatibility")
            raise SetupError("ufw_drift")
        self.host.verify_installed_firewall_compatibility = refuse
        self.host.firewall = lambda: self.fail("table read before admission")
        for operation in (self.host.ensure_guard, self.host.verify_guard):
            with self.assertRaisesRegex(SetupError, "ufw_drift"):
                operation(self.p)
        self.assertEqual(calls, ["compatibility", "compatibility"])

    def test_both_units_order_after_ufw_without_start_dependency(self):
        from deploy.wazuh.https_setup.firewall import guard_unit, indexer_dropin
        for text in (guard_unit(), indexer_dropin()):
            after = [line for line in text.splitlines() if line.startswith("After=")]
            self.assertIn("ufw.service", " ".join(after))
            for line in text.splitlines():
                if line.startswith(("Requires=", "Wants=", "BindsTo=", "ExecStop=")):
                    self.assertNotIn("ufw.service", line)

    def test_record_install_revalidates_before_write_and_never_replaces(self):
        self.assertTrue(hasattr(self.host, "install_firewall_compatibility"), "record install missing")
        fingerprint = self.admission()
        events = []
        def write(path, body):
            events.append("write")
            self.record = json.loads(body)
        self.host.fs = SimpleNamespace(write=write)
        self.host.install_firewall_compatibility(self.p, fingerprint)
        self.assertEqual(events, ["write"])
        self.assertEqual(self.record["fingerprint"], fingerprint)
        with self.assertRaisesRegex(SetupError, "ufw_drift"):
            self.host.install_firewall_compatibility(self.p, fingerprint)
        self.record = None
        self.probe["package_md5"] = "f" * 32
        with self.assertRaisesRegex(SetupError, "state_changed"):
            self.host.install_firewall_compatibility(self.p, fingerprint)
        self.assertEqual(events, ["write"])

    def test_partial_record_write_never_reaches_guard(self):
        self.assertTrue(hasattr(self.host, "install_firewall_compatibility"), "record install missing")
        fingerprint = self.admission()
        for when in ("before", "after"):
            self.record = None
            def write(path, body):
                if when == "after":
                    self.record = json.loads(body)
                raise KeyboardInterrupt()
            self.host.fs = SimpleNamespace(write=write)
            with self.assertRaises(KeyboardInterrupt):
                self.host.install_firewall_compatibility(self.p, fingerprint)
            if when == "before":
                with self.assertRaisesRegex(SetupError, "ufw_drift"):
                    self.host.verify_installed_firewall_compatibility(self.p)
            else:
                self.host.verify_installed_firewall_compatibility(self.p)

    def test_compatibility_is_part_of_frozen_check_digest(self):
        self.pin()
        from deploy.wazuh.https_setup.transaction import Coordinator
        synthetic = SyntheticHost()
        synthetic.facts["ufw_compatibility"] = copy.deepcopy(self.record["fingerprint"])
        c = Coordinator(synthetic)
        first = c.check("profile")["check_sha256"]
        synthetic.facts["ufw_compatibility"]["probe"]["package_md5"] = "d" * 32
        self.assertNotEqual(first, c.check("profile")["check_sha256"])

    def test_install_record_precedes_any_vendor_file_or_guard(self):
        fingerprint = self.admission()
        self.host.uid = self.host.gid = 123
        self.host.bundle_files = lambda: {"synthetic.py": b"synthetic"}
        events = []
        def write(path, body):
            events.append(("write", str(path)))
            if Path(path).name == "ufw-compat.json":
                self.record = json.loads(body)
        def vendor_mkdir(*args):
            self.assertIsNotNone(self.record)
            events.append(("vendor_mkdir", str(args[0])))
        self.host.fs = SimpleNamespace(mkdir=lambda *args: None, write=write,
            vendor_mkdir=vendor_mkdir, read=lambda *args, **kwargs: b"synthetic",
            vendor_write=lambda *args: self.assertIsNotNone(self.record))
        staged = {"bundle": {"synthetic.py": self.h.sha(b"synthetic")}, "ufw_compatibility": fingerprint,
                  "certificate_sha256": self.h.sha(b"synthetic"), "key_sha256": self.h.sha(b"synthetic")}
        self.host.install(self.p, staged, Path("synthetic"))
        record_event = next(i for i, event in enumerate(events) if event[1].endswith("ufw-compat.json"))
        self.assertLess(record_event, next(i for i, event in enumerate(events) if event[0] == "vendor_mkdir"))

    def recovery_fixture(self):
        self.pin()
        raw = self.h.encoded(self.record)
        snapshot = {"ufw_compatibility_original": None, "ufw_compatibility_sha256": self.h.sha(raw),
                    "original_sha256": self.h.sha(b"original")}
        self.host.fs = SimpleNamespace(read=lambda *args, **kwargs: raw,
            unlink=lambda path: setattr(self, "record", None))
        self.host.vread = lambda path: b"original"
        return snapshot

    def test_recovery_restores_original_absence_and_retains_unknown_record(self):
        snapshot = self.recovery_fixture()
        self.host.restore_firewall_compatibility(self.p, snapshot, Path("synthetic"))
        self.assertIsNone(self.record)
        # Interrupted cleanup is idempotent once old config/units/table are absent.
        with patch.object(self.h, "GUARD_UNIT", Path("synthetic-absent-guard")), patch.object(self.h, "DROPIN", Path("synthetic-absent-dropin")):
            self.host.restore_firewall_compatibility(self.p, snapshot, Path("synthetic"))
        snapshot = self.recovery_fixture()
        self.record["fingerprint"]["probe"]["package_md5"] = "d" * 32
        changed = copy.deepcopy(self.record)
        with self.assertRaisesRegex(SetupError, "ufw_drift"):
            self.host.restore_firewall_compatibility(self.p, snapshot, Path("synthetic"))
        self.assertEqual(self.record, changed)

    def test_recovery_missing_record_with_expanded_state_retains_protection(self):
        from deploy.wazuh.https_setup.firewall import _expected
        snapshot = self.recovery_fixture()
        self.rules["nftables"].extend(_expected(self.p))
        self.record = None
        with self.assertRaisesRegex(SetupError, "recovery_required"):
            self.host.check_recovery_firewall_compatibility(self.p, snapshot, Path("synthetic"))
        self.assertTrue(self.host.table(self.rules)["nftables"])

    def test_host_gate_drift_after_capture_stops_before_signing_archive(self):
        fingerprint = self.admission()
        facts = {"firewall": copy.deepcopy(self.rules), "ufw_compatibility": fingerprint}
        self.probe["package_md5"] = "f" * 32
        self.host.fs = SimpleNamespace(archive=lambda *args: self.fail("CA archive opened after host drift"))
        with self.assertRaisesRegex(SetupError, "state_changed"):
            self.host.stage(self.p, facts, Path("synthetic"))


class UfwAdapterTests(unittest.TestCase):
    def setUp(self):
        from deploy.wazuh.tests.test_ufw import FakeReader, snapshot
        self.a = importlib.import_module("deploy.wazuh.https_setup.ufw_host")
        self.u = importlib.import_module("deploy.wazuh.https_setup.ufw")
        self.h = importlib.import_module("deploy.wazuh.https_setup.host")
        self.snapshot = lambda path, body, **kwargs: snapshot(self.u, path, body, **kwargs)
        self.host = self.h.LinuxHost(fs=object(), commands=object())
        self.reader = self.a.UfwHostReader(self.host)
        self.fake = FakeReader(self.u)
        self.reader.root_file = self.fake.root_file

    def test_probe_provenance_precedes_inactive_command_and_is_frozen(self):
        body = b"#!/usr/bin/python3\n# synthetic CLI, never executed\n"
        self.fake.files["/usr/sbin/ufw"] = self.snapshot("/usr/sbin/ufw", body, mode=0o755)
        sums = self.fake.files[self.u.SUMS_PATH].body + hashlib.md5(body).hexdigest().encode() + b"  usr/sbin/ufw\n"
        self.fake.files[self.u.SUMS_PATH] = self.snapshot(self.u.SUMS_PATH, sums)
        wrapper = {"files": {self.u.SUMS_PATH: self.u.file_identity(self.fake.files[self.u.SUMS_PATH], path=self.u.SUMS_PATH)}}
        calls = []
        self.host.commands = SimpleNamespace(run_selected=lambda *args: (calls.append(args) or b"Status: inactive\n", b""))
        identity = self.reader.probe_identity(wrapper)
        self.assertEqual(calls, [("ufw", "status")])
        self.assertEqual(identity["package_md5"], hashlib.md5(body).hexdigest())
        self.assertEqual(set(identity), {"file", "package_md5"})
        self.fake.files["/usr/sbin/ufw"] = self.snapshot("/usr/sbin/ufw", body + b"# drift\n", mode=0o755)
        with self.assertRaises(SetupError):
            self.reader.probe_identity(wrapper)
        self.assertEqual(len(calls), 1)

    def test_probe_active_localized_oversized_or_changed_status_refuses(self):
        body = b"#!/usr/bin/python3\n# synthetic\n"
        self.fake.files["/usr/sbin/ufw"] = self.snapshot("/usr/sbin/ufw", body, mode=0o755)
        sums = hashlib.md5(body).hexdigest().encode() + b"  usr/sbin/ufw\n"
        self.fake.files[self.u.SUMS_PATH] = self.snapshot(self.u.SUMS_PATH, sums)
        wrapper = {"files": {self.u.SUMS_PATH: self.u.file_identity(self.fake.files[self.u.SUMS_PATH], path=self.u.SUMS_PATH)}}
        for output in (b"Status: active\n", b"localized inactive\n", b"Status: inactive\nextra", b"x" * 65537):
            self.host.commands = SimpleNamespace(run_selected=lambda *args: (output, b""))
            with self.assertRaises(SetupError):
                self.reader.probe_identity(wrapper)
        def raced(*args):
            self.fake.files["/usr/sbin/ufw"] = self.snapshot("/usr/sbin/ufw", body + b"# drift\n", mode=0o755)
            return b"Status: inactive\n", b""
        self.host.commands = SimpleNamespace(run_selected=raced)
        with self.assertRaisesRegex(SetupError, "state_changed"):
            self.reader.probe_identity(wrapper)

    def test_backend_checks_wrapper_sbin_alias_and_preserves_selected_argv(self):
        paths = []
        self.reader.alias = lambda path: paths.append(path) or sorted(self.a.ALIASES[path])[0]
        self.reader.root_file = lambda path, limit: self.fake.backends["iptables"]["file"]
        calls = []
        self.host.commands = SimpleNamespace(run_selected=lambda *args: (calls.append(args) or b"iptables v1.8.10 (nf_tables)\n", b""))
        self.reader.backend_identity("iptables")
        self.assertIn("/sbin", paths)
        self.assertEqual(calls, [("iptables", "--version")])

    def graph(self, installed=False):
        self.facts = {name: {key: "" for key in self.a.DEPENDENCIES}
                      for name in ("ufw.service", self.a.INDEXER, self.a.GUARD, "network-pre.target")}
        self.facts["ufw.service"]["Before"] = "network-pre.target"
        self.facts[self.a.INDEXER]["After"] = "network-pre.target"
        self.host.guard_unit_present = lambda: installed
        def props(name):
            if not installed and name == self.a.GUARD:
                self.fail("absent guard must not be queried as an installed unit")
            return self.facts[name]
        self.host.dependency_properties = props

    def test_absent_guard_uses_proposed_edges_then_installed_graph_is_stable(self):
        self.graph()
        original = self.reader.dependency_facts()
        self.graph(installed=True)
        self.facts[self.a.GUARD]["After"] = "ufw.service"
        self.facts[self.a.GUARD]["Before"] = self.a.INDEXER
        self.facts[self.a.INDEXER]["After"] += " ufw.service " + self.a.GUARD
        self.facts[self.a.INDEXER]["Requires"] = self.a.GUARD
        self.facts["ufw.service"]["Before"] += " " + self.a.GUARD + " " + self.a.INDEXER
        self.assertEqual(original, self.reader.dependency_facts())

    def test_effective_transitive_cycle_and_ufw_start_dependency_refuse(self):
        self.graph(installed=True)
        self.facts["network-pre.target"]["After"] = self.a.INDEXER
        with self.assertRaisesRegex(SetupError, "ufw_unsupported"):
            self.reader.dependency_facts()
        for key in ("Requires", "Wants", "BindsTo", "Upholds"):
            self.graph(installed=True)
            self.facts[self.a.GUARD][key] = "ufw.service"
            with self.assertRaisesRegex(SetupError, "ufw_unsupported"):
                self.reader.dependency_facts()

    def test_reverse_stop_restart_requirements_refuse_for_both_operated_units(self):
        for operated in (self.a.INDEXER, self.a.GUARD):
            for key in ("Requires", "Requisite", "BindsTo", "PartOf"):
                with self.subTest(operated=operated, key=key):
                    self.graph(installed=True)
                    self.facts["ufw.service"][key] = operated
                    with self.assertRaisesRegex(SetupError, "ufw_unsupported"):
                        self.reader.dependency_facts()

    def test_transitive_reverse_stop_restart_requirements_refuse(self):
        for operated in (self.a.INDEXER, self.a.GUARD):
            for first in ("Requires", "Requisite", "BindsTo", "PartOf"):
                for second in ("Requires", "Requisite", "BindsTo", "PartOf"):
                    with self.subTest(operated=operated, first=first, second=second):
                        self.graph(installed=True)
                        self.facts["synthetic-relay.service"] = {k: "" for k in self.a.DEPENDENCIES}
                        self.facts["ufw.service"][first] = "synthetic-relay.service"
                        self.facts["synthetic-relay.service"][second] = operated
                        with self.assertRaisesRegex(SetupError, "ufw_unsupported"):
                            self.reader.dependency_facts()

    def test_stop_propagation_properties_are_mandatory_frozen_evidence(self):
        added = {"RequiredBy", "RequisiteOf", "BoundBy", "ConsistsOf",
                 "PropagatesStopTo", "StopPropagatedFrom"}
        self.assertTrue(added.issubset(self.a.DEPENDENCIES))
        self.assertEqual(len(self.a.DEPENDENCIES), 17)
        self.graph(installed=True)
        result = self.reader.dependency_facts()
        for root in ("ufw.service", self.a.INDEXER):
            self.assertEqual(set(result[root]), set(self.a.DEPENDENCIES))
        for key in added:
            self.graph(installed=True)
            del self.facts["ufw.service"][key]
            with self.assertRaisesRegex(SetupError, "ufw_unsupported"):
                self.reader.dependency_facts()

    def test_explicit_direct_and_mixed_direction_stop_propagation_refuse(self):
        for operated in (self.a.INDEXER, self.a.GUARD):
            for source, key, target in ((operated, "PropagatesStopTo", "ufw.service"),
                                        ("ufw.service", "StopPropagatedFrom", operated)):
                with self.subTest(source=source, key=key):
                    self.graph(installed=True)
                    self.facts[source][key] = target
                    with self.assertRaisesRegex(SetupError, "ufw_unsupported"):
                        self.reader.dependency_facts()
            for inverse in ("RequiredBy", "RequisiteOf", "BoundBy", "ConsistsOf"):
                with self.subTest(operated=operated, inverse=inverse):
                    self.graph(installed=True)
                    for unit in ("synthetic-source.service", "synthetic-sink.service"):
                        self.facts[unit] = {key: "" for key in self.a.DEPENDENCIES}
                    # Source is discoverable only through the effective inverse
                    # on the operated unit. Combine both edge directions.
                    self.facts[operated][inverse] = "synthetic-source.service"
                    self.facts["synthetic-source.service"]["PropagatesStopTo"] = "synthetic-sink.service"
                    self.facts["ufw.service"]["StopPropagatedFrom"] = "synthetic-sink.service"
                    with self.assertRaisesRegex(SetupError, "ufw_unsupported"):
                        self.reader.dependency_facts()

    def test_unrelated_requirements_and_reverse_wants_are_not_stop_edges(self):
        self.graph(installed=True)
        for name in ("synthetic-a.service", "synthetic-b.service"):
            self.facts[name] = {key: "" for key in self.a.DEPENDENCIES}
        self.facts["ufw.service"]["Requires"] = "synthetic-a.service"
        self.facts["ufw.service"]["Wants"] = self.a.INDEXER
        # UFW -> Indexer stop propagation alone cannot let kit operations stop
        # UFW. Keep the new properties directional, not a blanket relation ban.
        self.facts["ufw.service"]["PropagatesStopTo"] = self.a.INDEXER
        self.facts[self.a.INDEXER]["StopPropagatedFrom"] = "ufw.service"
        self.facts["synthetic-a.service"]["Requires"] = "synthetic-b.service"
        self.facts["synthetic-b.service"]["Requires"] = "synthetic-a.service"
        result = self.reader.dependency_facts()
        self.assertEqual(result["ufw.service"]["Requires"], ["synthetic-a.service"])
        self.assertEqual(result["ufw.service"]["Wants"], [self.a.INDEXER])

    def test_present_null_duplicate_or_nonobject_record_refuses(self):
        self.host.fs = SimpleNamespace(trusted=lambda *args, **kwargs: SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_gid=0))
        self.host.ufw_reader = lambda: self.reader
        for body in (b"null", b"[]", b"{}", b'{"schema_version":1,"schema_version":1}', b"{"):
            self.reader.root_file = lambda path, limit: self.snapshot(path, body, mode=0o600)
            with self.assertRaisesRegex(SetupError, "ufw_drift"):
                self.a.read_record(self.host)

    def test_held_file_reads_reject_fd_entry_content_metadata_races(self):
        # Synthetic syscall boundary, not a claim that Windows implements openat.
        path, body = "/usr/lib/ufw/synthetic", b"synthetic"
        frozen = self.snapshot(path, body).info
        @contextmanager
        def parent(path):
            yield 3, "synthetic"
        def kernel(held, entry, raw=body):
            calls = []
            module = SimpleNamespace(O_RDONLY=0, O_NONBLOCK=1, O_NOFOLLOW=2,
                open=lambda *args, **kwargs: calls.append((args, kwargs)) or 4,
                fdopen=lambda *args, **kwargs: io.BytesIO(raw),
                fstat=lambda fd: next(held), stat=lambda *args, **kwargs: entry)
            return module, calls
        for changed, entry, raw in (
                (self.snapshot(path, body, st_ino=2).info, frozen, body),
                (frozen, self.snapshot(path, body, st_ino=2).info, body),
                (self.snapshot(path, body, st_mode=stat.S_IFREG | 0o666).info, frozen, body),
                (frozen, frozen, body + b"x")):
            module, calls = kernel(iter((frozen, changed)), entry, raw)
            with patch.object(self.a, "os", module), patch.object(self.a, "root_parent", parent):
                with self.assertRaisesRegex(SetupError, "state_changed"):
                    self.a.UfwHostReader(self.host).root_file(path, 1024)
            self.assertEqual(calls[0][0][1], 3)  # NOFOLLOW | NONBLOCK
        atime_only = self.snapshot(path, body, st_atime=123).info
        module, _ = kernel(iter((frozen, atime_only)), atime_only)
        with patch.object(self.a, "os", module), patch.object(self.a, "root_parent", parent):
            self.assertEqual(self.a.UfwHostReader(self.host).root_file(path, 1024).body, body)

    def test_held_ancestor_paths_refuse_replacement_and_close_every_fd(self):
        directory = self.snapshot("/", b"x", st_mode=stat.S_IFDIR | 0o755).info
        moved = self.snapshot("/", b"x", st_mode=stat.S_IFDIR | 0o755, st_ino=2).info
        opened, closed = [], []
        def open_path(*args, **kwargs):
            opened.append((args, kwargs))
            return len(opened)
        entries = {"/": directory, "usr": directory, "lib": directory}
        module = SimpleNamespace(O_RDONLY=0, O_DIRECTORY=1, O_NOFOLLOW=2,
            open=open_path, close=closed.append, fstat=lambda fd: directory,
            stat=lambda name, **kwargs: entries[name])
        with patch.object(self.a, "os", module):
            with self.assertRaisesRegex(SetupError, "state_changed"):
                with self.a.root_parent("/usr/lib/synthetic") as (fd, name):
                    self.assertEqual((fd, name), (3, "synthetic"))
                    entries["usr"] = moved
        self.assertEqual(closed, [3, 2, 1])
        self.assertTrue(all(args[1] == 3 for args, kwargs in opened))

    def test_transitive_start_dependency_and_bounded_unknown_graph_refuse(self):
        self.graph(installed=True)
        self.facts[self.a.GUARD]["Wants"] = "network-pre.target"
        self.facts["network-pre.target"]["Requires"] = "ufw.service"
        with self.assertRaisesRegex(SetupError, "ufw_unsupported"):
            self.reader.dependency_facts()
        self.graph(installed=True)
        self.facts[self.a.INDEXER]["After"] = "not a valid/unit"
        with self.assertRaisesRegex(SetupError, "ufw_unsupported"):
            self.reader.dependency_facts()

    def test_aliases_refuse_nonstandard_targets_and_link_replacement(self):
        link = self.snapshot("/lib", b"x", st_mode=stat.S_IFLNK | 0o777).info
        replaced = self.snapshot("/lib", b"x", st_mode=stat.S_IFLNK | 0o777, st_ino=2).info
        @contextmanager
        def parent(path):
            yield 1, "lib"
        for target, entry in (("/untrusted/lib", link), ("usr/lib", replaced)):
            values = iter((link, entry))
            module = SimpleNamespace(stat=lambda *args, **kwargs: next(values),
                                     readlink=lambda *args, **kwargs: target)
            with patch.object(self.a, "os", module), patch.object(self.a, "root_parent", parent):
                with self.assertRaises(SetupError):
                    self.reader.alias("/lib")

    def test_commands_selected_allowlist_and_multicall_dispatch(self):
        command = self.h.Commands(SimpleNamespace(trusted=lambda path: None))
        calls = []
        command._execute = lambda *args, **kwargs: calls.append((args, kwargs)) or (b"", b"")
        command.run_selected("iptables", "--version")
        self.assertEqual(calls, [(("/usr/sbin/xtables-nft-multi", ("--version",)), {"argv0": "/usr/sbin/iptables"})])
        for name, argument in (("ufw", "enable"), ("ufw-init", "status"), ("iptables", "-F")):
            with self.assertRaisesRegex(SetupError, "ufw_unsupported"):
                command.run_selected(name, argument)
        self.assertEqual(len(calls), 1)

    def test_absent_guard_file_does_not_hide_loaded_or_transient_unit(self):
        self.host.fs = SimpleNamespace(trusted=lambda *args, **kwargs: None)
        self.host.properties = lambda *args: {"LoadState": "loaded", "FragmentPath": "", "Transient": "yes",
                                             "DropInPaths": "", "NeedDaemonReload": "no"}
        with self.assertRaisesRegex(SetupError, "ufw_unsupported"):
            self.host.guard_unit_present()
        self.host.properties = lambda *args: {"LoadState": "not-found", "FragmentPath": "", "Transient": "no",
                                             "DropInPaths": "", "NeedDaemonReload": "no"}
        self.assertFalse(self.host.guard_unit_present())


class PropertiesTests(unittest.TestCase):
    def setUp(self):
        self.h = importlib.import_module("deploy.wazuh.https_setup.host")
        self.host = self.h.LinuxHost(fs=object(), commands=object())
        self.props = {key: "" for key in self.h.UNIT_EMPTY}
        self.props.update({key: "no" for key in self.h.UNIT_NO})
        self.props.update(User="wazuh-indexer", Group="wazuh-indexer", LoadState="loaded", ActiveState="active",
                          FragmentPath="/usr/lib/systemd/system/wazuh-indexer.service",
                          CapabilityBoundingSet="cap_net_admin cap_dac_override")
        self.calls = []

    def reader(self, *, omitted=(), response=b"a(sasbttttuii) 0\n", failed=False):
        def run(name, *args, **kwargs):
            self.calls.append((name, args))
            if name == "systemctl":
                return "".join(key + "=" + value + "\n" for key, value in self.props.items() if key not in omitted).encode()
            self.assertEqual(name, "busctl")
            if failed:
                raise SetupError("command_failed")
            return response
        self.host.run = run
        return self.host

    def test_complete_output_does_not_query_dbus(self):
        actual = self.reader().properties("synthetic-unit.service", self.h.UNIT_PROPERTIES)
        self.assertEqual(actual, self.props)
        self.assertEqual([name for name, _ in self.calls], ["systemctl"])
        self.h.validate_unit(actual)

    def test_only_omitted_execstartpre_needs_exact_independent_empty(self):
        actual = self.reader(omitted={"ExecStartPre"}).properties("synthetic-unit.service", self.h.UNIT_PROPERTIES)
        self.assertEqual(actual, self.props)
        self.assertEqual(self.h.COMMANDS["busctl"], "/usr/bin/busctl")
        self.assertEqual(self.calls[-1], ("busctl", ("--system", "get-property", "org.freedesktop.systemd1",
                         "/org/freedesktop/systemd1/unit/synthetic_2dunit_2eservice",
                         "org.freedesktop.systemd1.Service", "ExecStartPre")))
        self.h.validate_unit(actual)

    def test_other_missing_fields_never_query_fallback(self):
        for omitted in ({"RootImage"}, {"ExecStartPre", "RootImage"}, {"User"}):
            with self.subTest(omitted=omitted):
                self.calls.clear()
                with self.assertRaisesRegex(SetupError, "host_unsupported"):
                    self.reader(omitted=omitted).properties("synthetic.service", self.h.UNIT_PROPERTIES)
                self.assertEqual([name for name, _ in self.calls], ["systemctl"])
        self.calls.clear()
        self.props["UnexpectedProperty"] = ""
        with self.assertRaisesRegex(SetupError, "host_unsupported"):
            self.reader(omitted={"ExecStartPre"}).properties("synthetic.service", self.h.UNIT_PROPERTIES)
        self.assertEqual([name for name, _ in self.calls], ["systemctl"])

    def test_nonempty_wrong_signature_or_malformed_dbus_refuses(self):
        for response in (b'a(sasbttttuii) 1 "/usr/bin/true"\n', b"as 0\n", b"a(sasbttttuii) 0 extra\n",
                         b"a(sasbttttuii) 00\n", b"a(sasbttttuii)  0\n", b"", b"a(sasbttttuii) 0\nextra"):
            with self.subTest(response=response), self.assertRaisesRegex(SetupError, "host_unsupported"):
                self.reader(omitted={"ExecStartPre"}, response=response).properties("synthetic.service", self.h.UNIT_PROPERTIES)

    def test_failed_dbus_lookup_refuses(self):
        with self.assertRaises(SetupError):
            self.reader(omitted={"ExecStartPre"}, failed=True).properties("synthetic.service", self.h.UNIT_PROPERTIES)

    def test_unsafe_unit_refuses_before_commands(self):
        for unit in (None, "--synthetic.service", "../synthetic.service", "synthetic\n.service", "synthetic.service;true",
                     "synthetic.timer", "a" * 256 + ".service"):
            with self.subTest(unit=unit):
                self.calls.clear()
                with self.assertRaisesRegex(SetupError, "host_unsupported"):
                    self.reader(omitted={"ExecStartPre"}).properties(unit, self.h.UNIT_PROPERTIES)
                self.assertEqual(self.calls, [])

    def test_dbus_object_path_escapes_punctuation_and_initial_digit(self):
        self.reader(omitted={"ExecStartPre"}).properties("1-fixture_name@demo.service", self.h.UNIT_PROPERTIES)
        self.assertIn("/org/freedesktop/systemd1/unit/_31_2dfixture_5fname_40demo_2eservice", self.calls[-1][1])

    def test_confirmed_empty_does_not_bypass_unit_sandbox_validation(self):
        self.props["RootImage"] = "/synthetic.img"
        actual = self.reader(omitted={"ExecStartPre"}).properties("synthetic.service", self.h.UNIT_PROPERTIES)
        with self.assertRaisesRegex(SetupError, "host_unsupported"):
            self.h.validate_unit(actual)


class PublicationKernel:
    """In-memory syscall adapter; names and held fds have independent lifetimes."""
    def __init__(self):
        self.entries = {}
        self.fds = {}
        self.serial = 10
        self.hook = lambda event: None
        self.metadata_changes = []
        self.snapshots = {}
        self.renames = []

    def node(self, *, directory=False, body=b"", uid=123, gid=123, mode=0o660):
        self.serial += 1
        return dict(ino=self.serial, directory=directory, body=body, uid=uid, gid=gid, mode=mode, mtime_ns=1, ctime_ns=1)

    def info(self, node):
        return SimpleNamespace(st_dev=1, st_ino=node["ino"], st_mode=(stat.S_IFDIR if node["directory"] else stat.S_IFREG) | node["mode"],
            st_uid=node["uid"], st_gid=node["gid"], st_nlink=2 if node["directory"] else 1,
            st_size=len(node["body"]), st_mtime_ns=node["mtime_ns"], st_ctime_ns=node["ctime_ns"])

    def stat(self, parent, name):
        node = self.entries.get((parent, name))
        return None if node is None else self.info(node)

    def open(self, parent, name, *, create=False, directory=False):
        if create:
            if (parent, name) in self.entries:
                raise FileExistsError()
            self.entries[parent, name] = self.node(directory=directory, uid=0, gid=0, mode=0o700 if directory else 0o600)
        node = self.entries[parent, name]
        if node["directory"] != directory:
            raise OSError()
        fd = len(self.fds) + 100
        self.fds[fd] = node
        self.hook("opened_stage" if parent == 2 else "opened_target")
        return fd

    def mkdir(self, parent, name):
        if (parent, name) in self.entries:
            raise FileExistsError()
        self.entries[parent, name] = self.node(directory=True, uid=0, gid=0, mode=0o700)
        self.hook("made_stage_directory")

    def fstat(self, fd):
        return self.info(self.fds[fd])

    def read(self, fd):
        return self.fds[fd]["body"]

    def write(self, fd, body):
        self.fds[fd]["body"] = body
        self.hook("wrote_stage")

    def metadata(self, fd, uid, gid, mode):
        node = self.fds[fd]
        self.metadata_changes.append(node["ino"])
        node.update(uid=uid, gid=gid, mode=mode)
        self.hook("metadata_stage")

    def sync(self, fd):
        pass

    def close(self, fd):
        pass

    def rename(self, src_parent, src, dst_parent, dst, *, exchange=False):
        self.hook("before_exchange" if exchange else "before_noreplace")
        self.renames.append(exchange)
        if exchange:
            self.entries[src_parent, src], self.entries[dst_parent, dst] = self.entries[dst_parent, dst], self.entries[src_parent, src]
        else:
            if (dst_parent, dst) in self.entries:
                raise SetupError("vendor_drift")
            self.entries[dst_parent, dst] = self.entries.pop((src_parent, src))
        self.hook("after_exchange" if exchange else "after_noreplace")

    def preserve(self, name, fd):
        self.snapshots[name] = self.read(fd)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.h = importlib.import_module("deploy.wazuh.https_setup.host")
        self.assertTrue(hasattr(self.h, "VendorPublisher"), "Root-staged publication is not implemented")
        self.ops = PublicationKernel()
        self.publisher = self.h.VendorPublisher(self.ops, stage_fd=2)

    def write(self):
        self.publisher.file(1, "config", b"patched", uid=123, gid=123, mode=0o660,
                            owner=123, group=123, expected={hashlib.sha256(b"original").hexdigest()})

    def test_directory_substitution_before_publication_never_changes_replacement_metadata(self):
        replacement = self.ops.node(directory=True, uid=123, gid=123, mode=0o500)
        self.ops.hook = lambda event: self.ops.entries.update({(1, "directory"): replacement}) if event == "made_stage_directory" else None
        with self.assertRaisesRegex(SetupError, "vendor_drift"):
            self.publisher.directory(1, "directory", gid=123)
        self.assertNotIn(replacement["ino"], self.ops.metadata_changes)
        self.assertEqual((replacement["uid"], replacement["gid"], replacement["mode"]), (123, 123, 0o500))

    def test_directory_substitution_after_publication_is_detected_without_metadata_repair(self):
        replacement = self.ops.node(directory=True, uid=123, gid=123, mode=0o500)
        self.ops.hook = lambda event: self.ops.entries.update({(1, "directory"): replacement}) if event == "after_noreplace" else None
        with self.assertRaisesRegex(SetupError, "vendor_drift"):
            self.publisher.directory(1, "directory", gid=123)
        self.assertNotIn(replacement["ino"], self.ops.metadata_changes)
        self.assertEqual(replacement["mode"], 0o500)

    def test_target_edit_or_replacement_during_construction_stays_at_target(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                self.ops = PublicationKernel()
                self.publisher = self.h.VendorPublisher(self.ops, stage_fd=2)
                self.ops.entries[1, "config"] = self.ops.node(body=b"original")
                def race(event):
                    if event == "wrote_stage":
                        if replacement:
                            self.ops.entries[1, "config"] = self.ops.node(body=b"intervening")
                        else:
                            self.ops.entries[1, "config"]["body"] = b"intervening"
                self.ops.hook = race
                with self.assertRaisesRegex(SetupError, "vendor_drift"):
                    self.write()
                self.assertEqual(self.ops.entries[1, "config"]["body"], b"intervening")
                self.assertEqual(self.ops.renames, [])

    def test_stage_name_substitution_is_refused_before_publication(self):
        self.ops.entries[1, "config"] = self.ops.node(body=b"original")
        self.ops.hook = lambda event: self.ops.entries.update({(2, "new"): self.ops.node(body=b"substituted")}) if event == "wrote_stage" else None
        with self.assertRaisesRegex(SetupError, "vendor_drift"):
            self.write()
        self.assertEqual(self.ops.entries[1, "config"]["body"], b"original")
        self.assertEqual(self.ops.renames, [])

    def test_exchange_window_edit_is_preserved_as_displaced_evidence(self):
        self.ops.entries[1, "config"] = self.ops.node(body=b"original")
        self.ops.hook = lambda event: self.ops.entries[1, "config"].update(body=b"intervening") if event == "before_exchange" else None
        with self.assertRaisesRegex(SetupError, "vendor_drift"):
            self.write()
        self.assertEqual(self.ops.entries[2, "new"]["body"], b"intervening")
        self.assertEqual(self.ops.snapshots["displaced"], b"intervening")

    def test_final_leaf_replacement_is_preserved_and_refused(self):
        self.ops.entries[1, "config"] = self.ops.node(body=b"original")
        replacement = self.ops.node(body=b"intervening final")
        self.ops.hook = lambda event: self.ops.entries.update({(1, "config"): replacement}) if event == "after_exchange" else None
        with self.assertRaisesRegex(SetupError, "vendor_drift"):
            self.write()
        self.assertIs(self.ops.entries[1, "config"], replacement)
        self.assertEqual(self.ops.snapshots["displaced"], b"original")

    def test_success_publishes_exact_content_and_metadata_and_preserves_old_inode(self):
        original = self.ops.node(body=b"original")
        self.ops.entries[1, "config"] = original
        self.write()
        final = self.ops.entries[1, "config"]
        self.assertEqual((final["body"], final["uid"], final["gid"], final["mode"]), (b"patched", 123, 123, 0o660))
        self.assertIs(self.ops.entries[2, "new"], original)

    def test_securefs_forward_and_rollback_use_same_publication_algorithm(self):
        self.ops.entries[1, "config"] = self.ops.node(body=b"original")
        self.ops.fds[2] = self.ops.node(directory=True, uid=0, gid=0, mode=0o700)
        fs = self.h.SecureFS()
        @contextmanager
        def parent(path, uid, gid):
            yield 1, "config"
        @contextmanager
        def publication(path, kind):
            yield self.publisher
        fs.vendor_parent, fs.publication = parent, publication
        with patch.object(self.h.os, "fstat", return_value=SimpleNamespace(st_dev=1)):
            fs.vendor_write("/etc/wazuh-indexer/opensearch.yml", b"patched", 123, 123, owner=123,
                mode=0o660, expected={hashlib.sha256(b"original").hexdigest()})
        old = self.ops.entries.pop((2, "new"))
        with patch.object(self.h.os, "fstat", return_value=SimpleNamespace(st_dev=1)):
            fs.vendor_write("/etc/wazuh-indexer/opensearch.yml", b"original", 123, 123, owner=123,
                mode=0o660, expected={hashlib.sha256(b"patched").hexdigest()})
        self.assertEqual(self.ops.entries[1, "config"]["body"], old["body"])
        self.assertEqual(self.ops.renames, [True, True])

    def test_unsupported_rename_primitive_has_no_fallback(self):
        calls = []
        class Rename:
            def __call__(_, *args):
                calls.append(args)
                self.h.ctypes.set_errno(errno.ENOSYS)
                return -1
        with patch.object(self.h.ctypes, "CDLL", return_value=SimpleNamespace(renameat2=Rename())):
            ops = self.h.PublicationOps(2)
            with self.assertRaisesRegex(SetupError, "filesystem_unsupported"):
                ops.rename(2, "new", 1, "config", exchange=True)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-1], 2)
        with patch.object(self.h.ctypes, "CDLL", return_value=object()):
            with self.assertRaisesRegex(SetupError, "filesystem_unsupported"):
                self.h.PublicationOps(2)

    def test_cross_filesystem_refuses_before_publication(self):
        self.ops.fds[2] = self.ops.node(directory=True, uid=0, gid=0, mode=0o700)
        fs = self.h.SecureFS()
        @contextmanager
        def parent(path, uid, gid):
            yield 1, "directory"
        @contextmanager
        def publication(path, kind):
            yield self.publisher
        fs.vendor_parent, fs.publication = parent, publication
        with patch.object(self.h.os, "fstat", return_value=SimpleNamespace(st_dev=99)):
            with self.assertRaisesRegex(SetupError, "filesystem_unsupported"):
                fs.vendor_mkdir("/etc/wazuh-indexer/aegis-http", 123, 123)
        self.assertEqual(self.ops.entries, {})
        self.assertEqual(self.ops.metadata_changes, [])

    def test_pending_publication_requires_reconciliation_before_restore(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fs = self.h.SecureFS()
            fs.trusted = lambda _: None
            fs.read = lambda path, **kwargs: path.read_bytes()
            with patch.object(self.h, "PROFILE_ROOT", root):
                fs.check_publications()
                publication = root / "publication-synthetic"
                publication.mkdir()
                for status in ("prepared", "failed"):
                    (publication / "publication.json").write_text(json.dumps({"status": status}))
                    with self.assertRaisesRegex(SetupError, "vendor_drift"):
                        fs.check_publications()
                (publication / "publication.json").write_text(json.dumps({"status": "complete"}))
                fs.check_publications()
            host = self.h.LinuxHost(fs=fs, commands=object())
            fs.check_publications = lambda: (_ for _ in ()).throw(SetupError("vendor_drift"))
            host.vread = lambda _: self.fail("restore must not access vendor content after pending exchange")
            with self.assertRaisesRegex(SetupError, "vendor_drift"):
                host.restore(None, {}, root)

    def test_restore_does_not_repair_intervening_metadata_on_original_content(self):
        original = b"original"
        metadata = {"uid": 123, "gid": 123, "mode": stat.S_IFREG | 0o660}
        snapshot = {"uid": 123, "gid": 123, "metadata": metadata, "original_sha256": hashlib.sha256(original).hexdigest(),
                    "patched_sha256": hashlib.sha256(b"patched").hexdigest(), "guard_unit_absent": True,
                    "dropin_absent": True, "table_absent": True}
        fs = SimpleNamespace(check_publications=lambda: None, read=lambda *args, **kwargs: original)
        host = self.h.LinuxHost(fs=fs, commands=object())
        host.vread = lambda _: original
        host.check_recovery_firewall_compatibility = lambda *args: None  # Publisher-only boundary.
        host.vstat = lambda _: SimpleNamespace(st_uid=123, st_gid=123, st_mode=stat.S_IFREG | 0o640)
        host.run = lambda *args, **kwargs: self.fail("metadata drift must stop before daemon reload/restart")
        with self.assertRaisesRegex(SetupError, "vendor_drift"):
            host.restore(SimpleNamespace(config_path="synthetic"), snapshot, Path("synthetic"))

    def _assert_patched_rollback_preserves_metadata_edit(self, *, handoff):
        transaction = importlib.import_module("deploy.wazuh.https_setup.transaction")
        cases = [({"uid": 123, "gid": 123, "mode": 0o660}, {"mode": 0o640}),
                 ({"uid": 123, "gid": 123, "mode": 0o660}, {"uid": 0}),
                 ({"uid": 123, "gid": 0, "mode": 0o640}, {"gid": 123})]
        for original_meta, edit in cases:
            with self.subTest(edit=edit, handoff=handoff), tempfile.TemporaryDirectory() as temporary:
                ops = PublicationKernel()
                target = ops.node(body=b"patched", **original_meta)
                ops.entries[1, "config"] = target
                ops.fds[2] = ops.node(directory=True, uid=0, gid=0, mode=0o700)
                publisher = self.h.VendorPublisher(ops, stage_fd=2)
                fs = self.h.SecureFS()
                journals = []
                @contextmanager
                def parent(path, uid, gid):
                    yield 1, "config"
                @contextmanager
                def publication(path, kind):
                    record = {"status": "prepared"}
                    journals.append(record)
                    if handoff:
                        target.update(edit)
                    try:
                        yield publisher
                        record["status"] = "complete"
                    except BaseException:
                        record["status"] = "failed"
                        raise
                fs.vendor_parent, fs.publication = parent, publication
                fs.check_publications = lambda: None
                fs.read = lambda path, **kwargs: b"original"
                linux = self.h.LinuxHost(fs=fs, commands=object())
                linux.check_recovery_firewall_compatibility = lambda *args: None  # Publisher-only boundary.
                linux.vread = lambda _: target["body"]
                linux.vstat = lambda _: ops.info(target)
                commands = []
                linux.run = lambda *args, **kwargs: commands.append(args)
                synthetic = SyntheticHost()
                store = transaction.DurableStore(Path(temporary) / "state", sync_directory=lambda _: None)
                coordinator = transaction.Coordinator(synthetic, store)
                checked = coordinator.check("profile")
                coordinator.apply("profile", checked["profile_sha256"], checked["check_sha256"])
                snapshot = {"uid": 123, "gid": 123,
                    "metadata": original_meta | {"mode": stat.S_IFREG | original_meta["mode"]},
                    "original_sha256": hashlib.sha256(b"original").hexdigest(),
                    "patched_sha256": hashlib.sha256(b"patched").hexdigest(),
                    "guard_unit_absent": True, "dropin_absent": True, "table_absent": True}
                intent = store.read()
                intent["snapshot"] = snapshot
                store.save(intent)
                synthetic.restore = linux.restore
                initial_restarts = synthetic.events.count("restart")
                if not handoff:
                    target.update(edit)
                with patch.object(self.h.os, "fstat", return_value=SimpleNamespace(st_dev=1)):
                    with self.assertRaisesRegex(SetupError, "recovery_required"):
                        coordinator.rollback()
                self.assertIs(ops.entries[1, "config"], target)
                self.assertEqual(target["body"], b"patched")
                for key, value in (original_meta | edit).items():
                    self.assertEqual(target[key], value)
                self.assertEqual(ops.renames, [])
                self.assertEqual(ops.metadata_changes, [])
                self.assertEqual(commands, [])
                self.assertEqual(synthetic.events.count("restart"), initial_restarts)
                self.assertTrue(synthetic.guard)
                self.assertEqual(store.read()["status"], "recovery_required")
                self.assertEqual(store.read()["snapshot"], snapshot)
                self.assertEqual(journals, [{"status": "failed"}])

    def test_patched_rollback_rejects_mode_owner_group_drift_without_repair(self):
        self._assert_patched_rollback_preserves_metadata_edit(handoff=False)

    def test_patched_rollback_rejects_metadata_change_during_publisher_handoff(self):
        self._assert_patched_rollback_preserves_metadata_edit(handoff=True)


if __name__ == "__main__":
    unittest.main()
