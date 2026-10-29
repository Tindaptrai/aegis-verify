"""Required Linux qualification on a disposable VM, never vendor acceptance.

Opt in through Run-SelfTests.py --native. Missing capabilities are failures.
Filesystem tests chroot only a forked child. All nft mutations run in owned
network namespaces; systemd commands assert namespace identity before nft.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import secrets
import re
import select
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from deploy.wazuh.https_setup import host as h
from deploy.wazuh.https_setup import transaction as tx
from deploy.wazuh.https_setup.certificates import create_http_certificate
from deploy.wazuh.https_setup.contracts import SetupError, load_profile
from deploy.wazuh.https_setup.firewall import TABLE, firewall_text, verify_table, guard_unit, indexer_dropin
from deploy.wazuh.tests.test_components import profile_dict

KIT = Path(__file__).resolve().parents[1]
OBSERVATIONS = {}  # Sanitized test facts only; never paths, addresses or key material.


def fixture_nft_diagnostic(document, p):
    """Bounded owned-table shape only; this does not normalize verification."""
    try:
        if (type(document) is not dict or set(document) != {"nftables"} or
                type(document["nftables"]) is not list or len(document["nftables"]) > 16 or
                len(tx.encoded(document)) > 16384):
            return {"capture_error": "document_shape_or_size"}
        objects = []
        for item in document["nftables"]:
            if type(item) is not dict or len(item) != 1:
                return {"capture_error": "document_shape_or_size"}
            kind, body = next(iter(item.items()))
            if kind == "metainfo":
                continue
            if (kind not in {"table", "chain", "rule"} or type(body) is not dict or
                    body.get("family") != "inet" or
                    (body.get("name") if kind == "table" else body.get("table")) != TABLE):
                return {"capture_error": "non_fixture_object"}
            objects.append({kind: body})
        def scrub(value):
            if type(value) is dict:
                return {key: ("<redacted>" if key in {"comment", "userdata"} else scrub(item))
                        for key, item in value.items() if key != "handle"}
            if type(value) is list:
                return [scrub(item) for item in value]
            if type(value) is str:
                if value == p.indexer_ip:
                    return "<indexer_ip>"
                if value == p.manager_ip:
                    return "<manager_ip>"
                try:
                    ipaddress.ip_network(value, strict=False)
                    return "<other_ip>"
                except ValueError:
                    pass
                return value if re.fullmatch(r"[A-Za-z0-9_.:+<>=!@/-]{1,80}", value) and not value.startswith("/") else "<redacted>"
            return value
        return {"nftables": scrub(objects)}
    except (ValueError, TypeError, RecursionError):
        return {"capture_error": "document_shape_or_size"}


def fixture_service_diagnostic(properties, journal):
    """Never export raw journal, command text, unit names or filesystem paths."""
    fields = {"LoadState", "ActiveState", "SubState", "Result", "ExecMainCode", "ExecMainStatus"}
    clean = {}
    for line in properties[:8192].decode("ascii", "replace").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in fields and re.fullmatch(r"[a-z0-9-]{1,48}", value):
            clean[key] = value
    errors = []
    if len(journal) <= 65536:
        for line in journal.splitlines():
            try:
                message = json.loads(line).get("MESSAGE")
                if not isinstance(message, str) or len(message) > 256:
                    continue
                result = json.loads(message)
                if (type(result) is dict and set(result) == {"status", "error"} and
                        result["status"] == "error" and type(result["error"]) is str and
                        SetupError(result["error"]).code == result["error"] and result["error"] not in errors):
                    errors.append(result["error"])
            except (ValueError, TypeError, AttributeError):
                continue
    return {"properties": clean, "cli_errors": errors}


def command(*args, data=None, check=True, timeout=20):
    result = subprocess.run(list(map(str, args)), input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if check and result.returncode:
        raise AssertionError("native command failed: " + str(args[0]))
    return result


def disposable_fence():
    """Refuse any known real Wazuh footprint before making fixture changes."""
    for path in ("/etc/wazuh-indexer", "/etc/wazuh-manager", "/var/ossec",
                 "/usr/share/wazuh-indexer", "/var/lib/wazuh-indexer", "/usr/local/lib/aegis-wazuh-https",
                 "/etc/aegis-wazuh-https"):
        if os.path.lexists(path):
            raise AssertionError("real_wazuh_footprint_refused")
    for unit in ("wazuh-indexer.service", "wazuh-manager.service", "wazuh-dashboard.service"):
        result = command("systemctl", "show", unit, "--property=LoadState", "--value", check=False)
        if result.returncode != 0 or result.stdout.strip() != b"not-found":
            raise AssertionError("real_wazuh_unit_refused")
    result = command("dpkg-query", "-W", "-f=${db:Status-Status}\n", "wazuh-indexer", "wazuh-manager", "wazuh-dashboard", check=False)
    if result.returncode not in (0, 1) or b"installed" in result.stdout:
        raise AssertionError("real_wazuh_package_refused")


def private_file(path, body, mode=0o600, gid=0):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), 0, gid)
        os.fchmod(stream.fileno(), mode)
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def make_tls(root, *, indexer=None, manager=None):
    """Generate throwaway CA/old leaf, then call the real certificate component."""
    root = Path(root)
    root.mkdir(mode=0o700)
    def run(*args):
        return command("openssl", *args, timeout=60).stdout
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "ca.key",
        "-out", root / "ca.pem", "-subj", "/CN=Synthetic Native CA", "-days", "30",
        "-addext", "basicConstraints=critical,CA:TRUE")
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", root / "old.key",
        "-out", root / "old.pem", "-subj", "/CN=indexer.example.test", "-days", "30")
    raw = profile_dict()
    octets = (secrets.randbelow(250) + 1, secrets.randbelow(250) + 1)
    raw.update(indexer_ip=indexer or "10.%d.%d.10" % octets,
               manager_ip=manager or "10.%d.%d.20" % octets,
               expected_ca_file_sha256=h.sha((root / "ca.pem").read_bytes()),
               expected_ca_der_sha256=h.sha(run("x509", "-in", root / "ca.pem", "-outform", "DER")),
               expected_leaf_der_sha256=h.sha(run("x509", "-in", root / "old.pem", "-outform", "DER")))
    p = load_profile(tx.encoded(raw))
    leaf, key = create_http_certificate(root, p, (root / "ca.pem").read_bytes(),
                                        (root / "ca.key").read_bytes(), (root / "old.pem").read_bytes())
    private_file(root / "http.pem", leaf)
    private_file(root / "http.key", key)
    return p


@contextmanager
def child_assertions(test):
    """Subtests must raise in a child, never record into a copied parent result.

    Python 3.12's subTest yields without suppressing exceptions when _outcome is
    None. Restore it even on failure; only the pipe/status boundary reports the
    child result back to the parent's actual unittest result.
    """
    outcome = test._outcome
    test._outcome = None
    try:
        yield
    finally:
        test._outcome = outcome


def isolated_filesystem(test, operation, *, private_mounts=False):
    """Fork before chroot: the controller process can never inherit the root."""
    with tempfile.TemporaryDirectory(prefix="aegis-native-fs-", dir="/run") as temporary:
        os.chmod(temporary, 0o700)
        reader, writer = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(reader)
            try:
                os.setsid()
                if private_mounts:
                    import ctypes
                    libc = ctypes.CDLL(None, use_errno=True)
                    # CLONE_NEWNS, then MS_REC|MS_PRIVATE, before chroot. These
                    # alter only this child's new mount namespace, never host mounts.
                    if libc.unshare(0x20000) != 0 or libc.mount(None, b"/", None, 0x4000 | 0x40000, None) != 0:
                        raise AssertionError("private_mount_namespace_required")
                os.chroot(temporary)
                os.chdir("/")
                for name in ("/etc", "/var", "/var/backups"):
                    Path(name).mkdir(mode=0o755)
                    os.chmod(name, 0o755)
                Path("/etc/wazuh-indexer").mkdir(mode=0o750)
                os.chown("/etc/wazuh-indexer", 65534, 65534)
                os.chmod("/etc/wazuh-indexer", 0o750)
                Path("/etc/aegis-wazuh-https").mkdir(mode=0o700)
                with child_assertions(test):
                    operation()
                os.write(writer, b"ok")
                os._exit(0)
            except BaseException as exc:
                os.write(writer, (type(exc).__name__ + ": " + str(exc))[:3000].encode("utf-8", "replace"))
                os._exit(1)
        os.close(writer)
        try:
            ready, _, _ = select.select([reader], [], [], 40)
            if not ready:
                os.killpg(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
            text = os.read(reader, 4096).decode("utf-8", "replace")
            test.assertTrue(ready, "filesystem child timed out")
            test.assertEqual(status, 0, text)
            test.assertEqual(text, "ok")
        finally:
            os.close(reader)


LISTENER = '''import os, socket, ssl, sys
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((sys.argv[3], 9200))
server.listen(8)
while True:
    connection, _ = server.accept()
    connection.settimeout(2)
    try:
        with context.wrap_socket(connection, server_side=True) as tls:
            tls.sendall(b"synthetic-native-ok")
    except (OSError, ssl.SSLError):
        connection.close()
'''
CLIENT = '''import socket, ssl, sys
context = ssl.create_default_context(cafile=sys.argv[1])
connection = socket.socket()
connection.settimeout(1)
connection.bind((sys.argv[3], 0))
try:
    connection.connect((sys.argv[2], 9200))
    with context.wrap_socket(connection, server_hostname=sys.argv[2]) as tls:
        assert tls.recv(64) == b"synthetic-native-ok"
except (OSError, ssl.SSLError):
    raise SystemExit(2)
'''
ASSERT_NAMESPACE = '''import os, sys
if os.stat("/proc/self/ns/net").st_ino != int(sys.argv[1]) or os.geteuid() != 0:
    raise SystemExit(71)
if len(sys.argv) == 4:
    fd = os.open(sys.argv[2], os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.write(fd, (sys.argv[3] + "\\n").encode())
    os.fsync(fd)
    os.close(fd)
'''


class NetworkFixture:
    def __init__(self, test):
        self.test = test
        self.token = secrets.token_hex(6)
        self.server = "avn-s-" + self.token
        self.client = "avn-c-" + self.token
        self.namespaces = []
        self.units = []
        self.unit_roles = {}
        self.processes = []
        self.root = Path("/run/aegis-native-" + self.token)
        self.owns_root = False
        self.host_before = self.host_firewall()

    def host_firewall(self):
        return tx.digest(h.stable_firewall(json.loads(command("nft", "--json", "list", "ruleset").stdout)))

    def setup(self):
        self.root.mkdir(mode=0o755)
        self.owns_root = True
        os.chmod(self.root, 0o755)
        for name in (self.server, self.client):
            command("ip", "netns", "add", name)
            self.namespaces.append(name)
            self.net(name, "ip", "link", "set", "lo", "up")
        # Create veth entirely inside an owned namespace: no host-interface mutation.
        self.net(self.server, "ip", "link", "add", "srv0", "type", "veth", "peer", "name", "cli0")
        self.net(self.server, "ip", "link", "set", "cli0", "netns", self.client)
        octets = (secrets.randbelow(250) + 1, secrets.randbelow(250) + 1)
        prefix = "10.%d.%d." % octets
        self.indexer, self.allowed, self.denied = (prefix + n for n in ("10", "20", "30"))
        for namespace, interface, addresses in ((self.server, "srv0", [self.indexer]),
                                                (self.client, "cli0", [self.allowed, self.denied])):
            for address in addresses:
                self.net(namespace, "ip", "addr", "add", address + "/24", "dev", interface)
            self.net(namespace, "ip", "link", "set", interface, "up")
        self.inode = os.stat("/run/netns/" + self.server).st_ino
        self.test.assertNotEqual(self.inode, os.stat("/proc/self/ns/net").st_ino)
        self.profile = make_tls(self.root / "signing", indexer=self.indexer, manager=self.allowed)
        self.credentials = self.root / "tls"
        self.credentials.mkdir(mode=0o750)
        os.chown(self.credentials, 0, 65534)
        os.chmod(self.credentials, 0o750)
        for original, name in (("http.pem", "cert.pem"), ("http.key", "key.pem"), ("ca.pem", "ca.pem")):
            private_file(self.credentials / name, (self.root / "signing" / original).read_bytes(), 0o640, 65534)
        private_file(self.root / "listener.py", LISTENER.encode(), 0o644)
        private_file(self.root / "assert-namespace.py", ASSERT_NAMESPACE.encode(), 0o644)
        return self

    def net(self, namespace, *args, **kwargs):
        self.test.assertIn(namespace, self.namespaces)
        return command("ip", "netns", "exec", namespace, *args, **kwargs)

    def nft(self, *args, **kwargs):
        return self.net(self.server, "nft", *args, **kwargs)

    def table(self):
        return json.loads(self.nft("--json", "list", "table", "inet", TABLE).stdout)

    def verify_table(self):
        document = self.table()
        try:
            verify_table(document, self.profile)
        except SetupError:
            OBSERVATIONS.setdefault(self.test.id(), {})["fixture_nft_document"] = fixture_nft_diagnostic(document, self.profile)
            raise

    def reachable(self, source):
        return self.net(self.client, "/usr/bin/python3", "-I", "-B", "-c", CLIENT,
                        self.credentials / "ca.pem", self.indexer, source, check=False, timeout=5).returncode == 0

    def wait_reachable(self, source, expected=True):
        for _ in range(20):
            if self.reachable(source) == expected:
                return
            time.sleep(0.1)
        self.test.fail("synthetic TLS reachability mismatch")

    def start_listener(self):
        process = subprocess.Popen(["ip", "netns", "exec", self.server, "/usr/bin/python3", "-I", "-B",
                                    str(self.root / "listener.py"), str(self.credentials / "cert.pem"),
                                    str(self.credentials / "key.pem"), self.indexer],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(process)
        self.wait_reachable(self.allowed)
        self.wait_reachable(self.denied)

    def unit(self, name, body):
        full_name = "aegis-native-" + self.token + "-" + name + ".service"
        path = Path("/run/systemd/system") / full_name
        self.test.assertFalse(path.exists())
        private_file(path, body.encode(), 0o644)
        self.units.append((full_name, path))
        self.unit_roles[full_name] = name
        return full_name

    def systemctl(self, *args, check=True):
        result = command("systemctl", *args, check=False, timeout=25)
        if check and result.returncode:
            self.capture_service_failure()
            raise AssertionError("native command failed: systemctl")
        return result

    def capture_service_failure(self):
        observation = OBSERVATIONS.setdefault(self.test.id(), {})
        services = observation.setdefault("fixture_services", {})
        for name, _ in self.units:
            try:
                properties = command("systemctl", "show", name,
                                     "--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus",
                                     check=False, timeout=10).stdout
                journal = command("journalctl", "--unit", name, "--no-pager", "--output=json", "--lines=12",
                                  check=False, timeout=10).stdout
                services[self.unit_roles[name]] = fixture_service_diagnostic(properties, journal)
            except (OSError, AssertionError, subprocess.SubprocessError):
                services[self.unit_roles[name]] = {"capture_error": "service_query_failed"}
        try:
            result = self.nft("--json", "list", "table", "inet", TABLE, check=False, timeout=10)
            observation["fixture_nft_document"] = (fixture_nft_diagnostic(json.loads(result.stdout), self.profile)
                                                   if result.returncode == 0 else {"capture_error": "table_absent_or_unreadable"})
        except (OSError, AssertionError, subprocess.SubprocessError, ValueError):
            observation["fixture_nft_document"] = {"capture_error": "table_query_failed"}

    def cleanup(self):
        problems = []
        for name, path in reversed(self.units):
            try:
                if self.systemctl("stop", name, check=False).returncode:
                    problems.append("unit_stop_failed")
                state = self.systemctl("show", name, "--property=ActiveState", "--value").stdout.strip()
                if state not in (b"inactive", b"failed"):
                    problems.append("unit_still_active")
                self.systemctl("reset-failed", name, check=False)
                path.unlink()
            except (OSError, AssertionError, subprocess.SubprocessError):
                problems.append("unit_cleanup_failed")
        if self.units:
            try:
                self.systemctl("daemon-reload")
            except (OSError, AssertionError, subprocess.SubprocessError):
                problems.append("unit_reload_failed")
        for process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            except OSError:
                problems.append("listener_cleanup_failed")
        for name in reversed(self.namespaces):
            try:
                # Refuse to delete a namespace that still has processes attached.
                if command("ip", "netns", "pids", name).stdout.strip():
                    problems.append("namespace_process_left")
                else:
                    command("ip", "netns", "delete", name)
                    if Path("/run/netns", name).exists():
                        problems.append("namespace_left")
            except (OSError, AssertionError, subprocess.SubprocessError):
                problems.append("namespace_cleanup_failed")
        try:
            if self.owns_root:
                shutil.rmtree(self.root)
                if self.root.exists():
                    problems.append("fixture_tree_left")
        except OSError:
            problems.append("fixture_tree_cleanup_failed")
        try:
            after = self.host_firewall()
            OBSERVATIONS.setdefault(self.test.id(), {}).update(
                host_firewall_before_sha256=self.host_before, host_firewall_after_sha256=after)
            if after != self.host_before:
                problems.append("host_firewall_changed")
        except (OSError, AssertionError, subprocess.SubprocessError, SetupError, ValueError):
            problems.append("host_firewall_verification_failed")
        OBSERVATIONS.setdefault(self.test.id(), {})["fixture_cleanup_verified"] = not problems
        self.test.assertEqual(problems, [], "verified fixture teardown failed")


@contextmanager
def network_fixture(test):
    fixture = NetworkFixture(test)
    try:
        yield fixture.setup()
    finally:
        fixture.cleanup()


class NativeTests(unittest.TestCase):
    def setUp(self):
        if os.environ.get("AEGIS_REQUIRE_NATIVE") != "1":
            self.skipTest("explicit --native opt-in required")
        self.assertEqual(sys.platform, "linux", "Linux required")
        self.assertEqual(sys.version_info[:2], (3, 12), "Python 3.12 required")
        self.assertEqual(os.geteuid(), 0, "root required")
        disposable_fence()

    def test_openssl_signing_and_tls(self):
        with tempfile.TemporaryDirectory(prefix="aegis-native-tls-", dir="/run") as temporary:
            root = Path(temporary) / "signing"
            p = make_tls(root)
            leaf = ssl._ssl._test_decode_cert(str(root / "http.pem"))
            old = ssl._ssl._test_decode_cert(str(root / "old.pem"))
            self.assertEqual(leaf["subject"], old["subject"])
            self.assertEqual(leaf["subjectAltName"], (("IP Address", "127.0.0.1"), ("IP Address", p.indexer_ip)))
            self.assertTrue((root / "http.key").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----"))
            self.assertEqual(list(root.glob("issue-*")), [])
            for address in ("127.0.0.1", p.indexer_ip):
                command("openssl", "verify", "-CAfile", root / "ca.pem", "-purpose", "sslserver",
                        "-verify_ip", address, root / "http.pem")
            self.assertEqual(command("openssl", "verify", "-CAfile", root / "ca.pem", "-verify_ip",
                                     p.manager_ip, root / "http.pem", check=False).returncode, 2)

    def test_securefs_permissions_nofollow_and_inode(self):
        def exercise():
            fs = h.SecureFS()
            root = Path("/etc/aegis-wazuh-https")
            private_file(root / "safe", b"fixture")
            self.assertEqual(fs.read(root / "safe", private=True), b"fixture")
            (root / "link").symlink_to(root / "safe")
            with self.assertRaises((SetupError, OSError)):
                fs.read(root / "link", private=True)
            os.chmod(root / "safe", 0o660)
            with self.assertRaises(SetupError):
                fs.read(root / "safe", private=True)
            os.chmod(root / "safe", 0o600)
            class Swap(h.SecureFS):
                def trusted(inner, path, **kwargs):
                    before = super().trusted(path, **kwargs)
                    if Path(path).name == "safe":
                        private_file(root / "replacement", b"replacement")
                        os.replace(root / "replacement", root / "safe")
                    return before
            with self.assertRaises(SetupError) as caught:
                Swap().read(root / "safe", private=True)
            self.assertEqual(caught.exception.code, "state_changed")
            vendor = Path("/etc/wazuh-indexer")
            (vendor / "child").mkdir(mode=0o750)
            os.chown(vendor / "child", 65534, 65534)
            outside = Path("/etc/aegis-wazuh-https/outside")
            outside.mkdir(mode=0o700)
            with self.assertRaises(SetupError):
                with fs.vendor_parent(vendor / "child/leaf", 65534, 65534) as (parent, name):
                    (vendor / "child").rename(vendor / "held")
                    (vendor / "child").symlink_to(outside, target_is_directory=True)
                    fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                    os.write(fd, b"held inode")
                    os.close(fd)
            self.assertFalse((outside / "leaf").exists())
            self.assertEqual((vendor / "held/leaf").read_bytes(), b"held inode")
            with self.assertRaises((SetupError, OSError)):
                fs.vendor_read(vendor / "child/leaf", 65534, 65534)
        isolated_filesystem(self, exercise)

    def test_journal_fsync_and_process_lock(self):
        def exercise():
            root = Path("/var/backups/state")
            store = tx.DurableStore(root)
            with store.lock():
                reader, writer = os.pipe()
                child = os.fork()
                if child == 0:
                    os.close(reader)
                    try:
                        with tx.DurableStore(root).lock():
                            os.write(writer, b"unlocked")
                    except SetupError as exc:
                        os.write(writer, exc.code.encode())
                    os._exit(0)
                os.close(writer)
                ready, _, _ = select.select([reader], [], [], 5)
                self.assertTrue(ready)
                self.assertEqual(os.read(reader, 64), b"operation_locked")
                os.close(reader)
                self.assertEqual(os.waitpid(child, 0)[1], 0)
                intent = dict(schema_version=1, id="1" * 32, status="in_progress", phase="captured")
                observed = []
                original = os.fsync
                def synced(fd):
                    original(fd)
                    observed.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
                os.fsync = synced
                try:
                    store.save(intent)
                finally:
                    os.fsync = original
                self.assertEqual(store.read(), intent)
                self.assertEqual(observed, ["file", "directory", "file", "directory"])
                old_inode = (root / "intent.json").stat().st_ino
                intent["phase"] = "guarded"
                store.save(intent)
                self.assertNotEqual(old_inode, (root / "intent.json").stat().st_ino)
                self.assertEqual(stat.S_IMODE((root / "intent.json").stat().st_mode), 0o600)
                self.assertEqual((root / "intent.json").stat().st_uid, 0)
                self.assertEqual(len((root / "recovery.jsonl").read_text().splitlines()), 2)
                self.assertFalse(list(root.glob(".intent.json.*")))
            with store.lock():
                pass
        isolated_filesystem(self, exercise)

    def test_renameat2_publication_and_refusal(self):
        def exercise():
            fs = h.SecureFS()
            target = Path("/etc/wazuh-indexer/config")
            private_file(target, b"original", 0o640, 65534)
            os.chown(target, 65534, 65534)
            original_inode = target.stat().st_ino
            fs.vendor_write(target, b"patched", 65534, 65534, owner=65534, group=65534,
                            expected={h.sha(b"original")})
            self.assertEqual(target.read_bytes(), b"patched")
            self.assertEqual((target.stat().st_uid, target.stat().st_gid, stat.S_IMODE(target.stat().st_mode)), (65534, 65534, 0o640))
            stage = next(Path("/etc/aegis-wazuh-https").glob("publication-*"))
            self.assertEqual((stage / "new").stat().st_ino, original_inode)
            self.assertEqual((stage / "displaced.snapshot").read_bytes(), b"original")
            self.assertEqual(json.loads((stage / "publication.json").read_bytes())["status"], "complete")
            self.assertEqual((stage / "displaced.snapshot").stat().st_uid, 0)
            self.assertEqual(stat.S_IMODE((stage / "displaced.snapshot").stat().st_mode), 0o600)
            # Actual service identity can read its vendor file but cannot traverse
            # the root-only publication parent. No fake metadata adapter is used.
            os.chmod("/", 0o755)
            child = os.fork()
            if child == 0:
                try:
                    os.setgroups([])
                    os.setgid(65534)
                    os.setuid(65534)
                    if target.read_bytes() != b"patched":
                        os._exit(81)
                    try:
                        (stage / "displaced.snapshot").read_bytes()
                    except PermissionError:
                        os._exit(0)
                    os._exit(82)
                except BaseException:
                    os._exit(83)
            self.assertEqual(os.waitpid(child, 0)[1], 0)
            fs.vendor_mkdir("/etc/wazuh-indexer/tls", 65534, 65534)
            self.assertEqual(stat.S_IMODE(Path("/etc/wazuh-indexer/tls").stat().st_mode), 0o750)
            with self.assertRaises(SetupError):
                fs.vendor_mkdir("/etc/wazuh-indexer/tls", 65534, 65534)
            os.chmod("/etc/aegis-wazuh-https", 0o750)
            with self.assertRaises(SetupError):
                fs.vendor_write(target, b"refused", 65534, 65534, owner=65534, expected={h.sha(b"patched")})
            self.assertEqual(target.read_bytes(), b"patched")
            os.chmod("/etc/aegis-wazuh-https", 0o700)
            os.chmod("/etc", 0o777)
            with self.assertRaises(SetupError):
                fs.vendor_write(target, b"refused", 65534, 65534, owner=65534, expected={h.sha(b"patched")})
            os.chmod("/etc", 0o755)
            os.chown("/etc/aegis-wazuh-https", 65534, 65534)
            with self.assertRaises(SetupError):
                fs.vendor_write(target, b"refused", 65534, 65534, owner=65534, expected={h.sha(b"patched")})
            os.chown("/etc/aegis-wazuh-https", 0, 0)
            # Native NOREPLACE refuses existing names without changing either inode.
            with fs.publication(target, "file") as publisher:
                ops, stage_fd = publisher.ops, publisher.stage
                for name in ("a", "b"):
                    fd = ops.open(stage_fd, name, create=True)
                    ops.write(fd, name.encode())
                    ops.close(fd)
                with self.assertRaises(SetupError):
                    ops.rename(stage_fd, "a", stage_fd, "b")
                fd = os.open("a", os.O_RDONLY, dir_fd=stage_fd)
                try:
                    self.assertEqual(ops.read(fd), b"a")
                finally:
                    os.close(fd)
            # Unsupported primitive mapping has no fallback publication.
            with fs.publication(target, "file") as publisher:
                import ctypes
                import errno
                publisher.ops.renameat2 = lambda *args: (ctypes.set_errno(errno.ENOSYS) or -1)
                with self.assertRaises(SetupError) as caught:
                    publisher.ops.rename(publisher.stage, "absent", publisher.stage, "other")
                self.assertEqual(caught.exception.code, "filesystem_unsupported")
            # A real distinct mount must be rejected by SecureFS itself before
            # publication, in addition to the real EXDEV syscall check below.
            libc = ctypes.CDLL(None, use_errno=True)
            mounted = libc.mount(b"tmpfs", b"/etc/wazuh-indexer", b"tmpfs", 2 | 4, b"mode=0750")
            self.assertEqual(mounted, 0, "private fixture tmpfs mount required")
            try:
                with self.assertRaises(SetupError) as caught:
                    fs.vendor_write("/etc/wazuh-indexer/cross", b"refused", 65534, 65534)
                self.assertEqual(caught.exception.code, "filesystem_unsupported")
                self.assertFalse(Path("/etc/wazuh-indexer/cross").exists())
            finally:
                self.assertEqual(libc.umount2(b"/etc/wazuh-indexer", 0), 0)
        isolated_filesystem(self, exercise, private_mounts=True)
        # Actual same-device/cross-mount refusal, without mounting over any host path.
        with tempfile.TemporaryDirectory(prefix="aegis-native-cross-", dir="/run") as stage, \
                tempfile.TemporaryDirectory(prefix="aegis-native-cross-", dir="/dev/shm") as other:
            left = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
            right = os.open(other, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertNotEqual(os.fstat(left).st_dev, os.fstat(right).st_dev, "distinct mounts required")
                ops = h.PublicationOps(left)
                fd = ops.open(left, "new", create=True)
                ops.close(fd)
                with self.assertRaises(SetupError) as caught:
                    ops.rename(left, "new", right, "leaf")
                self.assertEqual(caught.exception.code, "filesystem_unsupported")
                self.assertTrue(Path(stage, "new").exists())
                self.assertFalse(Path(other, "leaf").exists())
            finally:
                os.close(left)
                os.close(right)

    def test_publication_races_preserve_evidence(self):
        # This real-fork regression must catch suppressed subtest failures/errors,
        # not just a direct self.fail (which the old pipe boundary already caught).
        spec = importlib.util.spec_from_file_location("wazuh_fork_proof", KIT / "Run-SelfTests.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        identity = self.id()
        for kind in ("failure", "error", "success"):
            class ChildRace(unittest.TestCase):
                def id(self):
                    return identity
                def runTest(case):
                    def child_operation():
                        with case.subTest(timing="window"):
                            if kind == "failure":
                                case.assertEqual(b"wrong snapshot", b"expected snapshot")
                            if kind == "error":
                                raise RuntimeError("synthetic child race error")
                    isolated_filesystem(case, child_operation)
            result = runner.ProofResult(io.StringIO(), True, 0)
            ChildRace().run(result)
            expected = "passed" if kind == "success" else "failed"
            self.assertEqual(runner.required_results(result, [identity])[identity], expected)
            self.assertEqual(runner.qualified(result, [identity]), kind == "success")

        def exercise():
            fs = h.SecureFS()
            target = Path("/etc/wazuh-indexer/config")
            base_ops = h.PublicationOps
            for timing in ("before", "target", "fifo", "window", "staged", "final", "directory"):
                with self.subTest(timing=timing):
                    target.unlink(missing_ok=True)
                    private_file(target, b"original", 0o640, 65534)
                    os.chown(target, 65534, 65534)
                    class RacingOps(base_ops):
                        def open(inner, parent, name, *, create=False, directory=False):
                            if timing == "fifo" and name == "config" and not create and not getattr(inner, "changed", False):
                                inner.changed = True
                                target.unlink()
                                os.mkfifo(target, 0o640)
                                os.chown(target, 65534, 65534)
                            return super().open(parent, name, create=create, directory=directory)
                        def read(inner, fd):
                            value = super().read(fd)
                            if timing in ("before", "target") and os.fstat(fd).st_ino == target.stat().st_ino and not getattr(inner, "changed", False):
                                inner.changed = True
                                if timing == "target":
                                    target.unlink()
                                    private_file(target, b"intervening", 0o640, 65534)
                                    os.chown(target, 65534, 65534)
                                else:
                                    target.write_bytes(b"intervening")
                            return value
                        def rename(inner, src_parent, src, dst_parent, dst, *, exchange=False):
                            if dst == "config" and timing == "window":
                                target.write_bytes(b"intervening")
                            if dst == "config" and timing == "staged":
                                os.unlink(src, dir_fd=src_parent)
                                fd = os.open(src, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=src_parent)
                                os.write(fd, b"staged replacement")
                                os.close(fd)
                            if dst == "newdir" and timing == "directory":
                                Path("/etc/wazuh-indexer/newdir").mkdir(mode=0o700)
                                os.chown("/etc/wazuh-indexer/newdir", 65534, 65534)
                            super().rename(src_parent, src, dst_parent, dst, exchange=exchange)
                            if dst == "config" and timing == "final":
                                target.unlink()
                                private_file(target, b"intervening", 0o640, 65534)
                                os.chown(target, 65534, 65534)
                    h.PublicationOps = RacingOps
                    previous = set(Path("/etc/aegis-wazuh-https").glob("publication-*"))
                    try:
                        with self.assertRaises(SetupError) as caught:
                            if timing == "directory":
                                fs.vendor_mkdir("/etc/wazuh-indexer/newdir", 65534, 65534)
                            else:
                                fs.vendor_write(target, b"patched", 65534, 65534, owner=65534,
                                                group=65534, expected={h.sha(b"original")})
                        self.assertEqual(caught.exception.code, "vendor_drift")
                    finally:
                        h.PublicationOps = base_ops
                    stage, = set(Path("/etc/aegis-wazuh-https").glob("publication-*")) - previous
                    self.assertEqual(json.loads((stage / "publication.json").read_bytes())["status"], "failed")
                    with self.assertRaises(SetupError):
                        fs.check_publications()
                    if timing == "window":
                        self.assertEqual((stage / "new").read_bytes(), b"intervening")
                        self.assertEqual((stage / "displaced.snapshot").read_bytes(), b"intervening")
                    if timing in ("before", "target", "final"):
                        self.assertEqual(target.read_bytes(), b"intervening")
                    if timing == "fifo":
                        self.assertTrue(stat.S_ISFIFO(target.lstat().st_mode))
                    if timing == "directory":
                        info = Path("/etc/wazuh-indexer/newdir").stat()
                        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (65534, 65534, 0o700))
            # Real process death immediately after the kernel exchange leaves a
            # prepared durable record. Later restore must stop before host ops.
            Path("/etc/aegis-wazuh-https").rename("/etc/retained-failed-evidence")
            Path("/etc/aegis-wazuh-https").mkdir(mode=0o700)
            target.unlink(missing_ok=True)
            private_file(target, b"original", 0o640, 65534)
            os.chown(target, 65534, 65534)
            previous = set(Path("/etc/aegis-wazuh-https").glob("publication-*"))
            child = os.fork()
            if child == 0:
                class InterruptOps(base_ops):
                    def rename(inner, src_parent, src, dst_parent, dst, *, exchange=False):
                        super().rename(src_parent, src, dst_parent, dst, exchange=exchange)
                        if dst == "config" and exchange:
                            os._exit(79)
                h.PublicationOps = InterruptOps
                fs.vendor_write(target, b"patched", 65534, 65534, owner=65534,
                                group=65534, expected={h.sha(b"original")})
                os._exit(80)
            self.assertEqual(os.waitpid(child, 0)[1], 79 << 8)
            stage, = set(Path("/etc/aegis-wazuh-https").glob("publication-*")) - previous
            self.assertEqual(json.loads((stage / "publication.json").read_bytes())["status"], "prepared")
            self.assertEqual((stage / "new").read_bytes(), b"original")
            frozen = (target.stat().st_ino, target.read_bytes())
            with self.assertRaises(SetupError):
                h.LinuxHost(fs=fs).restore(None, None, None)
            self.assertEqual((target.stat().st_ino, target.read_bytes()), frozen)
        isolated_filesystem(self, exercise)

    def test_nft_allowed_denied_sources(self):
        with network_fixture(self) as fixture:
            fixture.start_listener()
            # Both sources have already completed CA-verified TLS before guard.
            text = firewall_text(fixture.profile)
            fixture.nft("--check", "--file", "-", data=text.encode())
            # Match production's exclusive creation, then semantic verification.
            fixture.nft("--file", "-", data=text.replace("table inet", "create table inet", 1).encode())
            fixture.verify_table()
            self.assertNotEqual(fixture.nft("--file", "-", data=text.replace("table inet", "create table inet", 1).encode(), check=False).returncode, 0)
            self.assertTrue(fixture.reachable(fixture.allowed))
            self.assertFalse(fixture.reachable(fixture.denied))
            fixture.nft("delete", "table", "inet", TABLE)
            fixture.wait_reachable(fixture.denied)

    def test_systemd_every_start_guard(self):
        with network_fixture(self) as fixture:
            # Reachability proof precedes guard, with exactly the listener used by systemd.
            fixture.start_listener()
            fixture.processes[0].terminate()
            fixture.processes[0].wait(timeout=5)
            fixture.processes.clear()
            source = fixture.root / "source"
            source.mkdir(mode=0o755)
            for name in h.KIT_FILES:
                private_file(source / name, (KIT / name).read_bytes(), 0o644)
            for directory in source.rglob("*"):
                if directory.is_dir():
                    os.chmod(directory, 0o755)
            manifest = dict(schema_version=1, source_commit=os.environ["AEGIS_NATIVE_SOURCE_COMMIT"], native_proof=None,
                            files={name: h.sha((source / name).read_bytes()) for name in h.KIT_FILES})
            private_file(source / h.MANIFEST, tx.encoded(manifest))
            profile_path = fixture.root / "profile.json"
            private_file(profile_path, tx.encoded(fixture.profile.as_dict()))
            audit = fixture.root / "audit"
            # Only fixed path constants relocate. Actual CLI, manifest/ownership checks,
            # LinuxHost.guard, Commands and nft verifier run unchanged in copied modules.
            driver = f'''import os, sys
from pathlib import Path
sys.path.insert(0, {str(source)!r})
from https_setup import host
from https_setup.cli import main
host.INSTALL_ROOT = Path({str(source)!r})
host.PROFILE = {str(profile_path)!r}
if os.stat("/proc/self/ns/net").st_ino != {fixture.inode} or os.geteuid() != 0:
    raise SystemExit(71)
code = main()
if code == 0:
    fd = os.open({str(audit)!r}, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.write(fd, (sys.argv[1] + "-complete\\n").encode())
    os.fsync(fd)
    os.close(fd)
raise SystemExit(code)
'''
            private_file(source / "fixture-driver.py", driver.encode(), 0o644)
            assert_command = f"/usr/bin/python3 -I -B {fixture.root}/assert-namespace.py {fixture.inode} {audit}"
            entry = str(source / "fixture-driver.py")
            # Derive ordering and root '+' semantics from production renderers.
            guard_name = "aegis-native-" + fixture.token + "-guard.service"
            indexer_name = "aegis-native-" + fixture.token + "-indexer.service"
            guard = guard_unit().replace("wazuh-indexer.service", indexer_name)
            guard = guard.replace(h.ENTRYPOINT, entry).replace(h.PROFILE, str(profile_path))
            guard = guard.replace("[Service]\n", f"[Service]\nTimeoutStartSec=15\nTimeoutStopSec=5\nNetworkNamespacePath=/run/netns/{fixture.server}\nExecStartPre={assert_command} ensure-assert\n")
            self.assertEqual(fixture.unit("guard", guard), guard_name)
            dropin = indexer_dropin().replace("aegis-wazuh-http-guard.service", guard_name)
            dropin = dropin.replace(h.ENTRYPOINT, entry).replace(h.PROFILE, str(profile_path))
            dropin = dropin.replace("[Service]\n", f"[Service]\nExecStartPre=+{assert_command} verify-assert\n")
            service = f'''[Unit]
Description=Disposable synthetic Indexer (never Wazuh)

[Service]
Type=simple
TimeoutStartSec=15
TimeoutStopSec=5
User=nobody
Group=nogroup
NetworkNamespacePath=/run/netns/{fixture.server}
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
ExecStart=/usr/bin/python3 -I -B {fixture.root}/listener.py {fixture.credentials}/cert.pem {fixture.credentials}/key.pem {fixture.indexer}
'''
            self.assertEqual(fixture.unit("indexer", service + "\n" + dropin), indexer_name)
            fixture.systemctl("daemon-reload")
            # Negative safety proof: even root '+' must refuse the wrong namespace
            # before the driver could create a table. No nft mutation on this path.
            wrong = f'''[Service]
Type=oneshot
TimeoutStartSec=15
TimeoutStopSec=5
User=nobody
Group=nogroup
NetworkNamespacePath=/run/netns/{fixture.server}
ExecStartPre=+/usr/bin/python3 -I -B {fixture.root}/assert-namespace.py {fixture.inode + 1}
ExecStart=+/usr/bin/python3 -I -B {entry} guard-ensure --profile {profile_path}
'''
            wrong_name = fixture.unit("wrong-namespace", wrong)
            fixture.systemctl("daemon-reload")
            self.assertNotEqual(fixture.systemctl("start", wrong_name, check=False).returncode, 0)
            self.assertNotEqual(fixture.nft("list", "table", "inet", TABLE, check=False).returncode, 0)
            fixture.systemctl("start", indexer_name)
            fixture.wait_reachable(fixture.allowed)
            self.assertFalse(fixture.reachable(fixture.denied))
            fixture.verify_table()
            pid = int(fixture.systemctl("show", indexer_name, "--property=MainPID", "--value").stdout)
            self.assertEqual(Path(f"/proc/{pid}/status").read_text().split("Uid:")[1].split()[0], "65534")
            self.assertEqual(os.stat(f"/proc/{pid}/ns/net").st_ino, fixture.inode)
            lines = audit.read_text().splitlines()
            self.assertLess(lines.index("guard-ensure-complete"), lines.index("verify-assert"))
            fixture.systemctl("restart", indexer_name)
            fixture.wait_reachable(fixture.allowed)
            self.assertEqual(audit.read_text().count("guard-ensure-complete"), 1)
            self.assertEqual(audit.read_text().count("guard-verify-complete"), 2)
            self.assertEqual(fixture.systemctl("is-active", guard_name).stdout.strip(), b"active")
            # An already-active guard cannot hide deleted or drifted rules at restart.
            fixture.nft("delete", "table", "inet", TABLE)
            self.assertNotEqual(fixture.systemctl("restart", indexer_name, check=False).returncode, 0)
            self.assertFalse(fixture.reachable(fixture.allowed))
            self.assertEqual(fixture.systemctl("show", indexer_name, "--property=MainPID", "--value").stdout.strip(), b"0")
            fixture.nft("--file", "-", data=firewall_text(fixture.profile).replace("table inet", "create table inet", 1).encode())
            fixture.systemctl("reset-failed", indexer_name)
            fixture.systemctl("start", indexer_name)
            fixture.wait_reachable(fixture.allowed)
            fixture.nft("add", "rule", "inet", TABLE, "input", "counter", "accept")
            self.assertNotEqual(fixture.systemctl("restart", indexer_name, check=False).returncode, 0)
            self.assertFalse(fixture.reachable(fixture.allowed))
            self.assertEqual(fixture.systemctl("is-active", guard_name).stdout.strip(), b"active")
            # Stopping guard leaves the owned protection present, per production unit.
            fixture.systemctl("stop", guard_name)
            self.assertTrue(fixture.table()["nftables"])
            OBSERVATIONS.setdefault(self.id(), {}).update(
                namespace_assertion_before_nft=True, nonroot_service_uid=65534,
                root_plus_verifier=True, active_guard_restart_verified=True,
                deleted_table_refused=True, drifted_table_refused=True,
                guard_stop_retained_table=True)
