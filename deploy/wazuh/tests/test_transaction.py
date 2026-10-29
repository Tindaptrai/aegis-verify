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
        for phase in ("restore", "restart", "verify_old", "remove_guard"):
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
            self.assertEqual(len(host.bundle_files()), 9)
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
        self.assertTrue(all(body.startswith(b"create table inet aegis_wazuh_http_v1") for body in observed))

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
        with self.assertRaisesRegex(SetupError, "state_changed"):
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
        facts = {"archive": {"ino": 77}, "firewall": {"nftables": []}, "bundle": {}}
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


if __name__ == "__main__":
    unittest.main()
