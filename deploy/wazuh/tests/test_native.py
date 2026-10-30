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
import shlex
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
from deploy.wazuh.https_setup import ufw as u
from deploy.wazuh.https_setup import ufw_host as uh
from deploy.wazuh.tests.test_ufw import VENDOR
from deploy.wazuh.https_setup.certificates import create_http_certificate
from deploy.wazuh.https_setup.contracts import SetupError, load_profile
from deploy.wazuh.https_setup.firewall import TABLE, firewall_create_text, verify_table, guard_unit, indexer_dropin
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


def replace_fixture_file(root, path, body, mode=0o600):
    path = Path(path)
    if not path.is_relative_to(root) or path.is_symlink() or not path.is_file():
        raise AssertionError("owned_existing_fixture_file_required")
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(fd, mode)
        stream.write(body)
        stream.flush()
        os.fsync(fd)


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
        self.unit_bodies = {}
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
        # The same process verifies its namespace immediately before exec(nft).
        return self.net(self.server, "/usr/bin/python3", "-I", "-B", "-c",
                        "import os,sys; assert os.geteuid()==0 and os.stat('/proc/self/ns/net').st_ino==int(sys.argv[1]); os.execvp('nft',['nft',*sys.argv[2:]])",
                        str(self.inode), *args, **kwargs)

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
        self.unit_bodies[full_name] = body.encode()
        return full_name

    def systemctl(self, *args, check=True, timeout=25):
        actions = {"start", "stop", "restart", "reload", "reset-failed"}
        if not args or args[0] not in actions | {"show", "is-active", "daemon-reload"}:
            raise AssertionError("owned_unit_action_required")
        if args[0] in actions:
            owned = {name for name, _ in self.units}
            if len(args) < 2 or any(name not in owned for name in args[1:]):
                raise AssertionError("owned_unit_action_required")
        result = command("systemctl", *args, check=False, timeout=timeout)
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
                    continue
                state = self.systemctl("show", name, "--property=ActiveState", "--value").stdout.strip()
                if state not in (b"inactive", b"failed"):
                    problems.append("unit_still_active")
                    continue
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
            if self.owns_root and not problems:
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



def inactive_loader_inventory(fixture):
    """Only query-identity relocation; returned inactive/disabled facts are real."""
    body = '''[Unit]
DefaultDependencies=no
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/true
[Install]
WantedBy=multi-user.target
'''
    mapping = {role: fixture.unit("loader-" + role.split(".")[0], body) for role in uh.LOADERS}
    fixture.systemctl("daemon-reload")
    facts = {role: h.LinuxHost().properties(unit, uh.LOADER_KEYS) for role, unit in mapping.items()}
    fixture.test.assertTrue(uh.strict_loaders(facts))
    fixture.test.assertTrue(all(v == {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"}
                                for v in facts.values()))
    return mapping


def copy_tool_closure(root, selected_tools=("/bin/sh", "/bin/echo", "/bin/grep")):
    """Copy trusted runner ELF dependencies as data; never install a package."""
    for selected in selected_tools:
        original = Path(selected).resolve(strict=True)
        dependencies = command("ldd", original).stdout.decode("ascii")
        if "not found" in dependencies:
            raise AssertionError("fixture_tool_dependency_missing")
        paths = {selected: original}
        for line in dependencies.splitlines():
            match = re.search(r"(?:=>\s+)?(/[^\s]+)\s+\(", line)
            if match:
                paths[match[1]] = Path(match[1]).resolve(strict=True)
        for destination, source in paths.items():
            info = source.stat()
            if info.st_uid or info.st_gid or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
                raise AssertionError("fixture_tool_untrusted")
            target = root / destination.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                private_file(target, source.read_bytes(), stat.S_IMODE(info.st_mode))


def vendor_tree(fixture):
    root = fixture.root / "vendor-root"
    root.mkdir(mode=0o755)
    (root / "usr/lib").mkdir(parents=True)
    (root / "lib").symlink_to("usr/lib", target_is_directory=True)
    for path, body in VENDOR.items():
        private_file(root / path.lstrip("/"), body, 0o755 if path == u.INIT_PATH else 0o644)
    private_file(root / "etc/ufw/ufw.conf", b"ENABLED=no\nLOGLEVEL=low\n", 0o644)
    for name in ("before.init", "after.init"):
        private_file(root / "etc/ufw" / name, VENDOR["/usr/share/ufw/" + name], 0o640)
    # Package-database data is explicitly synthetic; no dpkg installation occurred.
    sums = b"".join(hashlib.md5(VENDOR[path]).hexdigest().encode() + b"  " + path[1:].encode() + b"\n"
                    for path in (u.INIT_PATH, u.FUNCTIONS_PATH, u.UNIT_PATH))
    private_file(root / u.SUMS_PATH.lstrip("/"), sums, 0o644)
    copy_tool_closure(root)
    return root


def vendor_digest(root):
    paths = {*VENDOR, u.CONF_PATH, u.SUMS_PATH, "/etc/ufw/before.init", "/etc/ufw/after.init"}
    return tx.digest({path: u.file_identity(uh.UfwHostReader(h.LinuxHost()).root_file(str(root / path.lstrip("/")), u.LIMIT),
                                          path=str(root / path.lstrip("/"))) for path in sorted(paths)})


def real_ufw_baseline():
    """Read only the real unit/config footprint; never invoke its CLI or wrapper."""
    paths = ("/etc/ufw", "/etc/default/ufw", "/usr/lib/ufw", "/usr/lib/systemd/system/ufw.service",
             "/etc/systemd/system/ufw.service", "/etc/systemd/system/ufw.service.d",
             "/etc/systemd/system/multi-user.target.wants/ufw.service", "/var/lib/ufw", "/run/ufw.lock")
    files = {}
    for path in paths:
        base = Path(path)
        items = [base, *sorted(base.rglob("*"))] if base.is_dir() and not base.is_symlink() else [base]
        for item in items:
            if not os.path.lexists(item):
                files[str(item)] = None
                continue
            info = item.lstat()
            files[str(item)] = dict(mode=info.st_mode, uid=info.st_uid, gid=info.st_gid, nlink=info.st_nlink,
                                    mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns,
                                    body=hashlib.sha256(item.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else
                                    os.readlink(item) if stat.S_ISLNK(info.st_mode) else None)
    props = h.LinuxHost().properties("ufw.service", ("LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath"))
    return tx.digest({"files": files, "unit": props})


def wrapper_direct(fixture, root, operation):
    if operation not in {"start", "stop", "restart", "force-reload"}:
        raise AssertionError("disabled_operation_required")
    u._disabled_config((root / u.CONF_PATH.lstrip("/")).read_bytes())
    # Child asserts the namespace, then chroots and closes inherited descriptors.
    code = '''import os,sys
assert os.geteuid()==0 and os.stat('/proc/self/ns/net').st_ino==int(sys.argv[1])
os.chroot(sys.argv[2]); os.chdir('/')
os.closerange(3, 65536)
args=['/usr/lib/ufw/ufw-init', sys.argv[3]]
if sys.argv[3]=='start': args.append('quiet')
os.execv(args[0],args)
'''
    result = fixture.net(fixture.server, "/usr/bin/python3", "-I", "-B", "-c", code,
                         str(fixture.inode), root, operation, timeout=10)
    expected = {"start": b"", "stop": b"Skip stopping firewall: ufw (not enabled)\n",
                "restart": b"Skipping  (not enabled)\n", "force-reload": b"Skipping  (not enabled)\n"}
    fixture.test.assertEqual(result.stdout, expected[operation])
    fixture.test.assertEqual(result.stderr, b"")


class DependencyRoleMap:
    """Bijective unit identity translation only; no property or graph filtering."""
    def __init__(self, roles):
        if len(set(roles.values())) != len(roles):
            raise AssertionError("dependency_mapping_not_bijective")
        self.queries = dict(roles)  # logical -> actual
        self.names = {actual: logical for logical, actual in roles.items()}

    def logical(self, actual):
        if actual in self.names:
            return self.names[actual]
        count_limit = len(self.names) >= 512
        too_long = len(actual) > 255
        grammar_matches = re.fullmatch(r"[A-Za-z0-9_.@\\:-]+\.[a-z]+", actual) is not None
        if count_limit or too_long or not grammar_matches:
            raise AssertionError(tx.encoded(dict(stage="dependency_mapping_bound", mapped_count=len(self.names),
                                 name_length=len(actual), count_limit_reached=count_limit,
                                 name_too_long=too_long, grammar_matches=grammar_matches)).decode("ascii"))
        stem, kind = actual.rsplit(".", 1)
        base = "aegis-fixture-external-" + hashlib.sha256(actual.encode("ascii")).hexdigest()
        alias, suffix = base + "." + kind, 0
        while alias in self.queries:
            suffix += 1
            if suffix > 512:
                raise AssertionError("dependency_mapping_bound")
            alias = base + "-" + str(suffix) + "." + kind
        self.names[actual] = alias
        self.queries[alias] = actual
        return alias

    def actual(self, logical):
        if logical not in self.queries:
            raise AssertionError("unobserved_dependency_query")
        return self.queries[logical]


class MappedDependencyHost:
    def __init__(self, actual_host, roles):
        self.host = actual_host
        self.mapping = DependencyRoleMap(roles)
        self.raw = {}

    def guard_unit_present(self):
        observed = self.host.properties(self.mapping.actual(uh.GUARD), ("LoadState",))
        if observed != {"LoadState": "loaded"}:
            raise AssertionError("actual_owned_guard_required")
        return True

    def dependency_properties(self, logical):
        actual = self.mapping.actual(logical)
        values = self.host.dependency_properties(actual)
        self.raw[actual] = {key: sorted(value.split()) for key, value in values.items()}
        return {key: " ".join(self.mapping.logical(name) for name in value.split()) for key, value in values.items()}


def stop_participants(fixture, mapping):
    if (set(mapping) != {"ufw.service", uh.GUARD, uh.INDEXER} or len(set(mapping.values())) != 3 or
            not set(mapping.values()) <= {name for name, _ in fixture.units}):
        raise AssertionError("owned_stop_participants_required")
    return tuple(mapping[role] for role in ("ufw.service", uh.GUARD, uh.INDEXER))


def make_stop_observer(fixture, mapping, controller):
    participants = stop_participants(fixture, mapping)
    if (controller != "aegis-native-"+fixture.token+"-transaction-controller.service" or
            controller in participants or (controller,Path("/run/systemd/system")/controller) not in fixture.units):
        raise AssertionError("owned_stop_controller_required")
    # Active After references retain stopped units' runtime timestamps in v255.
    # Null output avoids the journal socket dependency of a journal-output service.
    return fixture.unit("stop-observer", "[Unit]\nDefaultDependencies=no\nAfter=" + " ".join((*participants,controller)) + '''
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/true
StandardOutput=null
StandardError=null
TimeoutStartSec=10
TimeoutStopSec=5
''')


def stop_unit_sample(fixture, unit):
    states = {"LoadState": {"loaded", "not-found", "error", "masked", "stub", "bad-setting", "merged"},
              "ActiveState": {"active", "inactive", "activating", "deactivating", "failed", "reloading", "maintenance"},
              "SubState": {"running", "exited", "dead", "failed", "start", "start-pre", "start-post", "stop", "stop-post", "stop-sigterm", "stop-sigkill"}}
    times = ("ActiveEnterTimestampMonotonic", "ExecMainStartTimestampMonotonic", "InactiveEnterTimestampMonotonic")
    sample = {key: "unavailable" for key in (*states, *times)}
    try:
        raw = fixture.systemctl("show", unit, "--all", "--property=" + ",".join(sample), timeout=2).stdout
        if len(raw) > 4096:
            return sample
        pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
        values = dict(pairs)
        if len(pairs) != len(values):
            return sample
        for key, allowed in states.items():
            if values.get(key) in allowed:
                sample[key] = values[key]
        for key in times:
            value = values.get(key, "")
            if re.fullmatch(r"[0-9]{1,20}", value) and int(value) < 2**64:
                sample[key] = int(value)
    except (OSError, AssertionError, subprocess.SubprocessError, ValueError, UnicodeError):
        pass
    return sample


class OwnedTransactionReader:
    """Fixed five owned identities and nine named intrinsic leaves; read-only."""
    def __init__(self, fixture, names, gate, deadline):
        self.fixture, self.names, self.gate, self.deadline = fixture, names, gate, deadline
        self.host = h.LinuxHost()
        self.host.run = lambda name, *args, **kwargs: self.query(name, *args)
        self.files = uh.UfwHostReader(self.host)

    def check(self):
        if time.monotonic() >= self.deadline:
            raise AssertionError("native_transaction_timeout")

    def query(self, name, *args):
        remaining = self.deadline-time.monotonic()
        if remaining <= 0:
            raise AssertionError("native_transaction_timeout")
        return command(name, *args, timeout=min(1, remaining)).stdout

    def properties(self, unit, keys):
        raw = self.query("systemctl", "show", "--all", "--no-pager", "--property="+",".join(keys), "--", unit)
        try:
            if len(raw) > 65536:
                raise ValueError
            pairs = [line.split("=",1) for line in raw.decode("ascii").splitlines()]
            values = dict(pairs)
            if len(pairs) != len(values) or set(values) != set(keys):
                raise ValueError
            if any(len(v)>4096 or "\0" in v for v in values.values()):
                raise ValueError
            return values
        except (ValueError, UnicodeError):
            raise AssertionError("native_transaction_properties_invalid") from None

    def job(self, unit):
        label = "".join(c if c.isalpha() or n>0 and c.isdigit() else "_%02x"%ord(c) for n,c in enumerate(unit))
        class Reader:
            def run(inner, name, *args):
                return self.query(name, *("/org/freedesktop/systemd1/unit/"+label if v=="/org/freedesktop/systemd1/unit/ufw_2eservice" else v for v in args))
        value = {"type":"(uo)", "data":u._bus(Reader(), "Job", "(uo)")}
        self.gate.transaction_job(value,idle=False)
        return value

    def body(self, unit):
        value = self.files.root_file("/run/systemd/system/"+unit,65536)
        if value.body != self.fixture.unit_bodies[unit]:
            raise AssertionError("native_transaction_body_changed")
        return value

    def facts(self, role, target):
        unit = self.names[role]
        keys = [k for k in self.gate.TRANSACTION_IDENTITY if k not in {"body_sha256","body_metadata"}]
        identity = target["identity"] = self.properties(unit,keys)
        for key in ("Names","DropInPaths"):
            identity[key] = shlex.split(identity[key],comments=False,posix=True)
        self.check()
        value = self.files.root_file("/run/systemd/system/"+unit,65536)
        identity.update(body_sha256=hashlib.sha256(value.body).hexdigest(),
                        body_metadata=dict(uid=value.info.st_uid,gid=value.info.st_gid,mode=stat.S_IMODE(value.info.st_mode),nlink=value.info.st_nlink,size=value.info.st_size))
        if value.body != self.fixture.unit_bodies[unit]:
            raise AssertionError("native_transaction_body_changed")
        self.check()
        target["dependencies"] = {k:sorted(v.split()) for k,v in self.host.dependency_properties(unit).items()}
        self.check()

    def external(self, target):
        for unit in self.gate.TRANSACTION_LEAVES:
            values = self.properties(unit,("Id","FragmentPath","DropInPaths","LoadState","ActiveState","SubState"))
            row = target[unit] = dict(id=values["Id"],fragment_path=values["FragmentPath"],
                drop_in_paths=shlex.split(values["DropInPaths"],comments=False,posix=True),
                load=values["LoadState"],active=values["ActiveState"],sub=values["SubState"])
            self.check()
            row["job"] = self.job(unit)
            self.check()

    def sample(self, role, target):
        keys = {"LoadState":"load","ActiveState":"active","SubState":"sub",
                "ActiveEnterTimestampMonotonic":"active_enter_us","ExecMainStartTimestampMonotonic":"exec_start_us",
                "InactiveEnterTimestampMonotonic":"inactive_enter_us"}
        values = self.properties(self.names[role],tuple(keys))
        for key, field in keys.items():
            value = values[key]
            if field.endswith("_us"):
                if not re.fullmatch(r"[0-9]{1,20}",value) or int(value)>=2**64:
                    raise AssertionError("native_transaction_timestamp_invalid")
                value = int(value)
            elif value not in self.gate.TRANSACTION_STATES[field]:
                raise AssertionError("native_transaction_state_invalid")
            target[field] = value
        self.check()
        target["job"] = self.job(self.names[role])
        self.check()

    def fence(self):
        if (not self.fixture.owns_root or self.fixture.server not in self.fixture.namespaces or os.geteuid()!=0 or
                os.stat("/run/netns/"+self.fixture.server).st_ino != self.fixture.inode):
            raise AssertionError("native_transaction_namespace_required")
        for unit in self.names.values():
            if (unit,Path("/run/systemd/system")/unit) not in self.fixture.units:
                raise AssertionError("native_transaction_owned_required")
            self.body(unit)
            self.check()


def measure_owned_transaction(fixture, mapping, proof, phase, gate):
    """One owned anchor, one deadline; an active observer retains all four units."""
    names = gate.transaction_names(mapping)
    expected_phases = list(gate.TRANSACTION_PHASES)
    if phase not in expected_phases or list(proof["phases"]) != expected_phases[:expected_phases.index(phase)]:
        raise AssertionError("native_transaction_phase_order")
    if proof["controller"] != names["controller"] or proof["observer"] != names["observer"]:
        raise AssertionError("native_transaction_owned_required")
    deadline = time.monotonic()+5
    reader = OwnedTransactionReader(fixture,names,gate,deadline)
    record = proof["phases"][phase] = dict(facts={},external_baseline={},before={},after={},observer_facts={},observer_before={},observer_after={},
        action={"operation":"stop" if phase=="concurrent_stop" else "start","unit":names["controller"]})
    stage = "identity"
    def check():
        if time.monotonic() >= deadline:
            raise AssertionError("native_transaction_timeout")
    def sample(role, target):
        reader.sample(role,target)
        check()
        gate.transaction_sample(target,role)
    try:
        for role in gate.TRANSACTION_ROLES:
            reader.facts(role,record["facts"].setdefault(role,{})); check()
        reader.facts("observer",record["observer_facts"]); check()
        stage = "external"
        reader.external(record["external_baseline"]); check()
        stage = "before"
        for role in gate.TRANSACTION_ROLES:
            sample(role,record["before"].setdefault(role,{}))
        sample("observer",record["observer_before"])
        stage = "graph"
        gate.validate_transaction_phase(record,phase,names,before_only=True)
        gate.validate_transaction_continuity(proof["phases"])
        reader.fence(); check()
        stage = "action"
        fixture.systemctl(record["action"]["operation"],names["controller"])
        check()
        stage = "after"
        active = phase != "concurrent_stop"
        while True:
            complete = True
            for role in gate.TRANSACTION_ROLES:
                row = record["after"][role] = {}
                sample(role,row)
                if row["load"] != "loaded" or row["active"] in {"failed","maintenance"}:
                    raise AssertionError("native_transaction_state_failed")
                complete &= (row["active"] == ("active" if active else "inactive") and
                             row["sub"] == (("running" if role=="indexer" else "exited") if active else "dead") and row["job"]["data"] == [0,"/"])
                # Observe retention throughout participant sampling, not just at CLI return.
                sample("observer",record["observer_after"])
                gate.transaction_sample(record["observer_after"],"observer",True)
            if complete:
                break
            time.sleep(min(0.1,max(0,deadline-time.monotonic())))
        stage = "order"
        gate.validate_transaction_phase(record,phase,names)
        gate.validate_transaction_continuity(proof["phases"])
        check()
    except Exception:
        proof["failure"] = {"phase":phase,"stage":stage}
        raise AssertionError("native_transaction_failed") from None


def wait_conflict_states(fixture, relay, wrapper):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        states = [fixture.systemctl("show", unit, "--property=ActiveState", "--value", timeout=1).stdout.strip()
                  for unit in (relay, wrapper)]
        if states == [b"active", b"inactive"]:
            return
        time.sleep(0.1)
    raise AssertionError("conflict_states_timeout")


def wait_propagated_state(fixture, wrapper, *, after=None):
    """Observe dependent jobs after one source action; never retry the action."""
    if after is not None and (type(after) is not int or not 0 < after < 2**64):
        raise AssertionError("propagation_observation_invalid")
    deadline = time.monotonic() + 5
    while (remaining := deadline - time.monotonic()) > 0:
        raw = fixture.systemctl("show", wrapper, "--all",
                                "--property=ActiveState,ActiveEnterTimestampMonotonic", timeout=min(1, remaining)).stdout
        try:
            if len(raw) > 256:
                raise ValueError
            pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
            values = dict(pairs)
            if len(pairs) != 2 or set(values) != {"ActiveState", "ActiveEnterTimestampMonotonic"}:
                raise ValueError
            state, stamp = values["ActiveState"], values["ActiveEnterTimestampMonotonic"]
            if (state not in {"active", "inactive", "activating", "deactivating", "failed", "reloading", "maintenance"} or
                    not re.fullmatch(r"[0-9]{1,20}", stamp) or int(stamp) >= 2**64):
                raise ValueError
        except (ValueError, UnicodeError):
            raise AssertionError("propagation_observation_invalid") from None
        complete = state == "inactive" if after is None else state == "active" and int(stamp) > after
        if complete and time.monotonic() <= deadline:
            return
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    raise AssertionError("propagation_observation_timeout")


def observe_mixed_runtime(fixture, mapping, item):
    """Measure ordinary and explicit graceful anchors; endpoints are not atomic."""
    units = {"guard": mapping[uh.GUARD], "bridge": mapping["bridge.service"], "wrapper": mapping["ufw.service"]}
    runtime = item["mixed_runtime"] = {"scope": "conservative_refusal_and_direct_edges"}
    for phase, action, source, changed in (
            ("guard_stop", "stop", "guard", {"guard": "inactive", "bridge": "inactive"}),
            ("guard_restart", "restart", "guard", {"guard": "active", "bridge": "active"}),
            ("bridge_stop", "stop", "bridge", {"bridge": "inactive", "wrapper": "inactive"}),
            ("bridge_restart", "restart", "bridge", {"bridge": "active", "wrapper": "inactive"})):
        record = runtime[phase] = {"before": {}, "after": {}}
        try:
            fixture.systemctl("start", *mapping.values())
            deadline = time.monotonic() + 5

            def read(role, target):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError("mixed_runtime_timeout")
                raw = fixture.systemctl("show", units[role], "--all",
                    "--property=ActiveState,ActiveEnterTimestampMonotonic", timeout=min(1, remaining)).stdout
                try:
                    if len(raw) > 256:
                        raise ValueError
                    pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
                    values = dict(pairs)
                    if len(pairs) != 2 or set(values) != {"ActiveState", "ActiveEnterTimestampMonotonic"}:
                        raise ValueError
                    state, stamp = values["ActiveState"], values["ActiveEnterTimestampMonotonic"]
                    if (state not in {"active", "inactive", "activating", "deactivating", "reloading", "failed", "maintenance"} or
                            not re.fullmatch(r"[0-9]{1,20}", stamp) or int(stamp) >= 2**64):
                        raise ValueError
                except (ValueError, UnicodeError):
                    raise AssertionError("mixed_runtime_invalid") from None
                sample = target[role] = dict(state=state, active_enter_us=int(stamp))
                if time.monotonic() >= deadline:
                    raise AssertionError("mixed_runtime_timeout")
                if state in {"failed", "maintenance"} or (state == "active" and int(stamp) == 0):
                    raise AssertionError("mixed_runtime_invalid")
                return sample

            for role in units:
                if read(role, record["before"])["state"] != "active":
                    raise AssertionError("mixed_runtime_baseline")
            fixture.systemctl(action, units[source])
            while True:
                complete = True
                for role, expected in changed.items():
                    sample = read(role, record["after"])
                    complete &= sample["state"] == expected and (expected == "inactive" or
                        sample["active_enter_us"] > record["before"][role]["active_enter_us"])
                if complete:
                    break
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
            # Read the unchanged endpoint only after both changed roles complete.
            unchanged = "wrapper" if source == "guard" else "guard"
            if read(unchanged, record["after"]) != record["before"][unchanged]:
                raise AssertionError("mixed_runtime_endpoint")
        except Exception:
            item["failure"] = dict(phase=phase, stage="mixed_runtime_failed")
            raise


def dependency_observations(fixture):
    """Actual D-Bus/systemctl graph and propagation; only disposable true units."""
    observations = OBSERVATIONS.setdefault(fixture.test.id(), {}).setdefault("dependency_cases", {})
    base = '''[Unit]
DefaultDependencies=no
{relations}
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/true
TimeoutStartSec=10
TimeoutStopSec=5
'''
    for case in ("direct_indexer", "direct_guard", "transitive", "mixed", "activation", "ordering",
                 "conflict_indexer", "conflict_guard", "conflict_stop"):
        mapping = {role: f"aegis-native-{fixture.token}-dep-{case}-{name}.service"
                   for role, name in (("ufw.service", "ufw"), (uh.INDEXER, "indexer"), (uh.GUARD, "guard"), ("bridge.service", "bridge"))}
        item = observations[case] = {"mapping": mapping}
        ufw, indexer, guard, bridge = (mapping[k] for k in ("ufw.service", uh.INDEXER, uh.GUARD, "bridge.service"))
        def record_bridge_active(key):
            sample = stop_unit_sample(fixture, bridge)
            item["mixed_context"][key] = all(sample[field] == value for field, value in
                                            (("LoadState", "loaded"), ("ActiveState", "active"), ("SubState", "exited")))
            if not item["mixed_context"][key]:
                raise AssertionError("mixed_context_required")
        relations = {name: "" for name in mapping.values()}
        if case.startswith("direct_"):
            relations[ufw] = "Requires=" + (indexer if case == "direct_indexer" else guard)
        elif case in {"transitive", "mixed"}:
            relations[bridge] = "Requires=" + guard
            if case == "transitive":
                relations[ufw] = "Requires=" + bridge
            else:
                relations[bridge] += "\nPropagatesStopTo=" + ufw
        elif case == "activation":
            relations[guard] = "Wants=" + ufw
        elif case.startswith("conflict_"):
            source = guard if case == "conflict_guard" else indexer
            relations[source] = "Wants=" + bridge
            if case == "conflict_guard":
                relations[ufw] = "Conflicts=" + bridge  # bridge's actual inverse must be captured
            elif case == "conflict_stop":
                relations[bridge] = "Conflicts=" + guard
                relations[ufw] = "PartOf=" + guard
            else:
                relations[bridge] = "Conflicts=" + ufw
        else:
            relations[guard] = "Before=" + ufw
        paths = {}
        for name in relations:
            role = name.removeprefix("aegis-native-" + fixture.token + "-").removesuffix(".service")
            fixture.test.assertEqual(fixture.unit(role, base.format(relations="")), name)
            paths[name] = fixture.units[-1][1]
        fixture.systemctl("daemon-reload")
        if case == "mixed":
            item["mixed_context"] = {}
            fixture.systemctl("start", bridge)  # empty authored relations; retain the same unit across both probes
            record_bridge_active("bridge_active_baseline")
        actual = h.LinuxHost()
        baseline = MappedDependencyHost(actual, mapping)
        uh.UfwHostReader(baseline).dependency_facts()  # same complete mapper must admit the safe control
        baseline_proof = {"identity_mapping": baseline.mapping.queries,
                          "raw_facts_sha256": tx.digest(baseline.raw), "admitted": True}
        item["baseline"] = baseline_proof
        if case.startswith("conflict_"):
            # Establish the exact safe active UFW + inactive relay state first.
            fixture.systemctl("start", ufw, source, *([guard] if case == "conflict_stop" else []))
        for name, relation in relations.items():
            replace_fixture_file(Path("/run/systemd/system"), paths[name], base.format(relations=relation).encode(), 0o644)
        fixture.systemctl("daemon-reload")
        if case == "mixed":
            record_bridge_active("bridge_active_hostile")
        raw = {name: actual.dependency_properties(name) for name in mapping.values()}
        item["facts"] = {name: {key: sorted(value.split()) for key, value in facts.items()} for name, facts in raw.items()}
        hostile = MappedDependencyHost(actual, mapping)
        try:
            if case == "mixed":
                item["mixed_context"].update(
                    bridge_requires_guard=guard in raw[bridge]["Requires"].split(),
                    bridge_propagates_stop_to_wrapper=ufw in raw[bridge]["PropagatesStopTo"].split(),
                    guard_required_by_bridge=bridge in raw[guard]["RequiredBy"].split(),
                    wrapper_stop_propagated_from_bridge=bridge in raw[ufw]["StopPropagatedFrom"].split())
                if not all(item["mixed_context"].values()):
                    raise AssertionError("mixed_context_required")
            with fixture.test.assertRaisesRegex(SetupError, "ufw_unsupported"):
                uh.UfwHostReader(hostile).dependency_facts()
            item["refused"] = True
        finally:
            item.update(identity_mapping=hostile.mapping.queries, raw_facts_sha256=tx.digest(hostile.raw))
        propagated = case not in {"activation", "ordering", "mixed"}
        lifecycle = {}
        if case.startswith("conflict_"):
            def state(unit):
                return fixture.systemctl("show", unit, "--property=ActiveState", "--value").stdout.strip()
            fixture.test.assertEqual(state(source), b"active")
            fixture.test.assertEqual(state(ufw), b"active")
            fixture.test.assertEqual(state(bridge), b"inactive")
            fixture.systemctl("restart", source)
            wait_conflict_states(fixture, bridge, ufw)
            lifecycle = dict(source_active_before=True, wrapper_active_before=True, relay_inactive_before=True,
                             relay_active_after=True, wrapper_inactive_after=True)
        elif case == "mixed":
            observe_mixed_runtime(fixture, mapping, item)
        elif propagated:
            # One transaction establishes actual running units before stopping the source.
            fixture.systemctl("start", *mapping.values())
            fixture.test.assertEqual(fixture.systemctl("is-active", ufw).stdout.strip(), b"active")
            source = indexer if case == "direct_indexer" else guard
            fixture.systemctl("stop", source)
            wait_propagated_state(fixture, ufw)
            # Restart propagation gets separate evidence with both units active.
            fixture.systemctl("start", *mapping.values())
            before_raw = fixture.systemctl("show", ufw, "--property=ActiveEnterTimestampMonotonic", "--value", timeout=1).stdout.strip()
            if not re.fullmatch(rb"[0-9]{1,20}", before_raw) or not 0 < int(before_raw) < 2**64:
                raise AssertionError("propagation_observation_invalid")
            before = int(before_raw)
            fixture.systemctl("restart", source)
            wait_propagated_state(fixture, ufw, after=before)
        item["propagation_verified"] = propagated
        if lifecycle:
            item["lifecycle"] = lifecycle
        fixture.systemctl("stop", *mapping.values())
        # Remove hostile edges before the next safe control, retaining owned units for teardown.
        for path in paths.values():
            replace_fixture_file(Path("/run/systemd/system"), path, base.format(relations="").encode(), 0o644)
        fixture.systemctl("daemon-reload")
    return observations



def probe_mount_table():
    with open("/proc/self/mountinfo", "rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise AssertionError("probe_mount_observation_required")
    return raw


def probe_mount_facts(raw, path):
    """Bounded local inspection; never return mount names or the host inventory."""
    try:
        if not raw or len(raw) > 1024 * 1024 or len(raw.splitlines()) > 8192:
            raise ValueError
        matches, private = [], True
        for line in raw.decode("utf-8", "strict").splitlines():
            left, right = line.split(" - ", 1)
            fields = left.split()
            if len(fields) < 6 or len(right.split()) < 3:
                raise ValueError
            mountpoint = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
            if not mountpoint.startswith("/"):
                raise ValueError
            private = private and not any(v.startswith(("shared:", "master:", "propagate_from:")) for v in fields[6:])
            if path == mountpoint or path.startswith(mountpoint.rstrip("/") + "/"):
                matches.append((len(mountpoint), mountpoint == path, "nodev" in fields[5].split(",")))
        if not matches:
            raise ValueError
        _, mounted, nodev = max(matches)
        return {"nodev": nodev, "mounted": mounted, "private": private}
    except (ValueError, UnicodeError):
        raise AssertionError("probe_mount_observation_required") from None


def probe_null_metadata(info, *, device):
    rdev = [os.major(info.st_rdev), os.minor(info.st_rdev)]
    if (info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or
            (device and (not stat.S_ISCHR(info.st_mode) or rdev != [1, 3])) or
            (not device and (not stat.S_ISREG(info.st_mode) or info.st_size != 0 or
                             stat.S_IMODE(info.st_mode) != 0o600))):
        raise AssertionError("probe_null_untrusted")
    return {"type": "char" if device else "regular", "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid, "gid": info.st_gid, "rdev": rdev}


def probe_null_open(path, diagnostics, stage):
    diagnostics["stage"] = stage + "_open"
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            probe_null_metadata(os.fstat(fd), device=True)
            if os.read(fd, 1) != b"":
                raise AssertionError("probe_null_eof_required")
        finally:
            os.close(fd)
    except OSError as exc:
        diagnostics["open_errno"][stage] = exc.errno
        raise
    diagnostics["open_errno"][stage] = 0


def bind_probe_null(root, fixture_root, parent_pid, parent_namespace, diagnostics):
    """Bind only the real null device, only in a fork child's private mount ns."""
    diagnostics.update(stage="resource_validation", euid=os.geteuid(),
                       nodev={key: "unavailable" for key in ("source", "target_before", "target_bound")},
                       open_errno={key: "unavailable" for key in ("source", "bound", "chroot")})
    if os.getpid() == parent_pid or os.geteuid() != 0 or root != fixture_root / "probe-root":
        raise AssertionError("probe_child_owned_root_required")
    target = (root / "dev/null").as_posix()
    # Hold and recheck every root-owned, no-follow ancestor. The placeholder is
    # owned fixture storage; no parent mount or host device is ever replaced.
    with uh.root_parent("/dev/null"), uh.root_parent(target):
        source = os.stat("/dev/null", follow_symlinks=False)
        diagnostics["source"] = probe_null_metadata(source, device=True)
        diagnostics["target_before"] = probe_null_metadata(os.stat(target, follow_symlinks=False), device=False)
        raw = probe_mount_table()
        diagnostics["nodev"]["source"] = probe_mount_facts(raw, "/dev/null")["nodev"]
        diagnostics["nodev"]["target_before"] = probe_mount_facts(raw, target)["nodev"]
        probe_null_open("/dev/null", diagnostics, "source")
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        diagnostics["stage"] = "unshare"
        if libc.unshare(0x20000) != 0:  # CLONE_NEWNS
            raise OSError(ctypes.get_errno(), "probe_unshare_failed")
        distinct = os.stat("/proc/self/ns/mnt").st_ino != parent_namespace
        diagnostics["child_mount_namespace_distinct"] = distinct
        if not distinct:
            raise AssertionError("probe_private_namespace_required")
        diagnostics["stage"] = "private"
        if libc.mount(None, b"/", None, 0x4000 | 0x40000, None) != 0:  # MS_REC | MS_PRIVATE
            raise OSError(ctypes.get_errno(), "probe_private_mount_failed")
        private = probe_mount_facts(probe_mount_table(), target)["private"]
        diagnostics["recursive_private"] = private
        if not private:
            raise AssertionError("probe_private_namespace_required")
        diagnostics["stage"] = "bind"
        if libc.mount(b"/dev/null", target.encode("utf-8"), None, 0x1000, None) != 0:  # MS_BIND
            raise OSError(ctypes.get_errno(), "probe_bind_failed")
        bound = probe_mount_facts(probe_mount_table(), target)
        diagnostics["nodev"]["target_bound"] = bound["nodev"]
        if not bound["mounted"] or not bound["private"] or bound["nodev"]:
            raise AssertionError("probe_bound_device_mount_required")
        diagnostics["target_bound"] = probe_null_metadata(os.stat(target, follow_symlinks=False), device=True)
        if uh._identity(os.stat("/dev/null", follow_symlinks=False)) != uh._identity(source):
            raise AssertionError("probe_null_source_changed")
        probe_null_open(target, diagnostics, "bound")


def native_nft_read(test, fixture, root, *, refusal=False):
    """Real production nft reader in an owned netns and fork-only child root.

    The fixture supplies only nft and its shared libraries. There is no UFW CLI,
    compatibility binary, vendor config, interpreter executable or live bus here.
    """
    parent_pid = os.getpid()
    parent_namespace = os.stat("/proc/self/ns/mnt").st_ino
    target = (root / "dev/null").as_posix()
    with uh.root_parent(target):
        target_before = os.stat(target, follow_symlinks=False)
        probe_null_metadata(target_before, device=False)
    parent_mounts = probe_mount_table()
    test.assertFalse(probe_mount_facts(parent_mounts, target)["mounted"])
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        resources = {"stage": "network_namespace"}
        try:
            os.setsid()
            namespace = os.open("/run/netns/" + fixture.server, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.setns(namespace, 0)
            finally:
                os.close(namespace)
            assert os.geteuid() == 0 and os.stat("/proc/self/ns/net").st_ino == fixture.inode
            bind_probe_null(root, fixture.root, parent_pid, parent_namespace, resources)
            resources["stage"] = "chroot"
            os.chroot(root)
            os.chdir("/")
            probe_null_open("/dev/null", resources, "chroot")
            resources["stage"] = "nft_read"
            with child_assertions(test):
                host = h.LinuxHost()
                baseline = host.firewall()
                frozen = tx.digest(baseline)
                entries = sorted(path.name for path in Path("/run").iterdir())
                lock = Path("/run/ufw.lock")
                test.assertFalse(lock.exists())
                def observe():
                    actual = host.firewall()
                    test.assertEqual(actual, baseline)
                    if refusal:
                        with test.assertRaisesRegex(SetupError, "ufw_unsupported"):
                            uh.validate_nft_observation(actual)
                    else:
                        uh.validate_nft_observation(actual)
                    test.assertEqual(host.firewall(), baseline)
                observe()
                test.assertFalse(lock.exists())
                test.assertEqual(sorted(path.name for path in Path("/run").iterdir()), entries)
                private_file(lock, b"synthetic-ufw-lock-sentinel\n")
                def sentinel():
                    body = lock.read_bytes()
                    info = lock.stat()
                    return (body, *(getattr(info, "st_" + key) for key in
                                   ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")))
                before = sentinel()
                observe()
                test.assertEqual(sentinel(), before)
                test.assertEqual(sorted(path.name for path in Path("/run").iterdir()), [*entries, "ufw.lock"])
                lock.unlink()
                test.assertEqual(sorted(path.name for path in Path("/run").iterdir()), entries)
                after = tx.digest(host.firewall())
                test.assertEqual(frozen, after)
                resources["stage"] = "complete"
                result = dict(document=baseline, before_sha256=frozen, after_sha256=after,
                              refused=refusal, absent_lock_preserved=True, present_lock_preserved=True,
                              resources=resources)
                payload = tx.encoded(result)
                test.assertLessEqual(len(payload), 4096)
                os.write(writer, payload)
                os._exit(0)
        except BaseException as exc:
            # Closed diagnostics only: no paths, command text or exception message.
            failure = dict(resources=resources, error_type="os_error" if isinstance(exc, OSError) else "assertion_or_contract",
                           error_errno=exc.errno if isinstance(exc, OSError) else None)
            os.write(writer, tx.encoded(failure)[:4096])
            os._exit(1)
    os.close(writer)
    try:
        ready, _, _ = select.select([reader], [], [], 55)
        if not ready:
            os.killpg(pid, signal.SIGKILL)
        payload = os.read(reader, 4096) if ready else b""
        _, status = os.waitpid(pid, 0)
        result = json.loads(payload) if payload else {"resources": {"stage": "timeout"}}
        resources = result["resources"]
        resources["parent_namespace_unchanged"] = os.stat("/proc/self/ns/mnt").st_ino == parent_namespace
        with uh.root_parent(target):
            resources["parent_target_unchanged"] = uh._identity(os.stat(target, follow_symlinks=False)) == uh._identity(target_before)
        after_mounts = probe_mount_table()
        resources["parent_mounts_unchanged"] = parent_mounts == after_mounts
        resources["child_bind_released"] = not probe_mount_facts(after_mounts, target)["mounted"] and resources["parent_target_unchanged"]
        if status != 0:
            OBSERVATIONS.setdefault(test.id(), {})["probe_resource_failure"] = result
        test.assertTrue(ready, "native nft reader child timed out")
        test.assertTrue(all(resources[key] is True for key in ("parent_namespace_unchanged", "parent_target_unchanged", "parent_mounts_unchanged", "child_bind_released")))
        test.assertEqual(status, 0, tx.encoded(result).decode("ascii"))
        return result
    finally:
        os.close(reader)


def synthetic_guard_driver(fixture, root, mapping):
    """Return a real guard CLI with an expressly synthetic admission reader.

    All file reads, private record IO, firewall IO and guard decisions are real.
    Package database, stock-unit fields, backend identities and dependency
    fingerprint are model inputs. Native observations are tested independently.
    """
    source = fixture.root / "ufw-source"
    source.mkdir(mode=0o755)
    for name in h.KIT_FILES:
        private_file(source / name, (KIT / name).read_bytes(), 0o644)
    for directory in source.rglob("*"):
        if directory.is_dir():
            os.chmod(directory, 0o755)
    manifest = dict(schema_version=1, source_commit=os.environ["AEGIS_NATIVE_SOURCE_COMMIT"], native_proof=None,
                    files={name: h.sha((source / name).read_bytes()) for name in h.KIT_FILES})
    private_file(source / h.MANIFEST, tx.encoded(manifest))
    policy = fixture.root / "policy"
    policy.mkdir(mode=0o700)
    profile = policy / "profile.json"
    record = policy / "ufw-compat.json"
    private_file(profile, tx.encoded(fixture.profile.as_dict()))
    driver = f'''import os,sys
from pathlib import Path
sys.path.insert(0, {str(KIT.parents[1])!r})
sys.path.insert(0, {str(source)!r})
from https_setup import host, ufw, ufw_host
from deploy.wazuh.tests.test_ufw import FakeReader, loaders
host.INSTALL_ROOT=Path({str(source)!r})
host.PROFILE={str(profile)!r}
host.RECORD_PATH=ufw_host.RECORD_PATH={str(record)!r}
assert os.geteuid()==0 and os.stat('/proc/self/ns/net').st_ino=={fixture.inode}
class FixtureCommands(host.Commands):
    def _execute(self, executable, args, *, data=None, argv0=None):
        if os.geteuid() != 0 or os.stat("/proc/self/ns/net").st_ino != {fixture.inode}:
            raise AssertionError("fixture_namespace_required")
        return super()._execute(executable, args, data=data, argv0=argv0)
RealHost=host.LinuxHost
class SyntheticReader(FakeReader):
    def __init__(self, owner):
        super().__init__(ufw)
        self.actual=ufw_host.UfwHostReader(RealHost())
    def root_file(self, path, limit):
        if path==ufw_host.RECORD_PATH:
            return self.actual.root_file(path,limit)
        read=self.actual.root_file(str(Path({str(root)!r}) / path.lstrip('/')),limit)
        return ufw.RootFile(path,read.body,read.info)
    def validate_library_alias(self, wrapper):
        assert os.readlink({str(root / 'lib')!r})=='usr/lib'
    def dependency_facts(self):
        return {{name:{{key:[] for key in ufw_host.DEPENDENCIES}} for name in ('ufw.service',ufw_host.INDEXER)}}
class FixtureHost(RealHost):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.commands = FixtureCommands(self.fs)
    def ufw_reader(self): return SyntheticReader(self)
    def firewall_loaders(self): return loaders()
host.LinuxHost=FixtureHost
from https_setup.cli import main
if sys.argv[1]=='prepare-record':
    instance=FixtureHost(bundle=host.INSTALL_ROOT)
    p=host.load_profile(instance.fs.read(host.PROFILE,private=True))
    instance.install_firewall_compatibility(p,instance.admit_firewall_loaders())
    raise SystemExit(0)
raise SystemExit(main())
'''
    path = source / "fixture-driver.py"
    private_file(path, driver.encode(), 0o644)
    fixture.net(fixture.server, "/usr/bin/python3", "-I", "-B", path, "prepare-record")
    return path, profile, record


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

            # Fixed read-only compatibility artifact in this child's chroot;
            # no host /usr tree or installed service identity is touched.
            jar = Path("/usr/share/wazuh-indexer/lib/opensearch-2.19.4.jar")
            for directory in (Path("/usr"), Path("/usr/share"), jar.parent.parent, jar.parent):
                directory.mkdir(mode=0o755)
                os.chmod(directory, 0o755)
            for directory in (jar.parent.parent, jar.parent):
                os.chown(directory, 65534, 65534)
                os.chmod(directory, 0o750)
            private_file(jar, b"synthetic JAR bytes", 0o640, 65534)
            os.chown(jar, 65534, 65534)
            before = {path: h.identity(path.stat()) for path in (Path("/"), *reversed(jar.parents[:-1]), jar)}
            self.assertEqual(fs.read_indexer_jar(65534, 65534), b"synthetic JAR bytes")
            self.assertEqual({path: h.identity(path.stat()) for path in before}, before)
            with self.assertRaises(SetupError):
                fs.read(jar, owners={0, 65534})

            for path in (jar.parent.parent, jar.parent, jar):
                os.chown(path, 0, 0)
            self.assertEqual(fs.read_indexer_jar(65534, 65534), b"synthetic JAR bytes")
            for path in (jar.parent.parent, jar.parent, jar):
                os.chown(path, 65534, 65534)

            for path in (Path("/usr"), Path("/usr/share"), jar.parent.parent, jar.parent, jar):
                original = path.stat()
                for owner, group in ((65533, original.st_gid), (original.st_uid, 65533)):
                    # Upper ancestors require root ownership; group identities
                    # are constrained only at the fixed vendor-data boundary.
                    if path in (Path("/usr"), Path("/usr/share")) and owner == 0:
                        continue
                    os.chown(path, owner, group)
                    with self.assertRaises(SetupError):
                        fs.read_indexer_jar(65534, 65534)
                    os.chown(path, original.st_uid, original.st_gid)
                for bit in (0o020, 0o002):
                    os.chmod(path, stat.S_IMODE(original.st_mode) | bit)
                    with self.assertRaises(SetupError):
                        fs.read_indexer_jar(65534, 65534)
                    os.chmod(path, stat.S_IMODE(original.st_mode))

            saved = jar.with_name("saved.jar")
            jar.rename(saved)
            jar.symlink_to(saved.name)
            with self.assertRaises((SetupError, OSError)):
                fs.read_indexer_jar(65534, 65534)
            jar.unlink()
            saved.rename(jar)
            os.link(jar, saved)
            with self.assertRaises(SetupError):
                fs.read_indexer_jar(65534, 65534)
            saved.unlink()
            jar.rename(saved)
            os.mkfifo(jar, 0o640)
            os.chown(jar, 65534, 65534)
            with self.assertRaises(SetupError):
                fs.read_indexer_jar(65534, 65534)
            jar.unlink()
            saved.rename(jar)
            jar.parent.rename(jar.parent.with_name("held-lib"))
            jar.parent.symlink_to("held-lib", target_is_directory=True)
            with self.assertRaises((SetupError, OSError)):
                fs.read_indexer_jar(65534, 65534)
            jar.parent.unlink()
            jar.parent.with_name("held-lib").rename(jar.parent)

            original_read = os.read
            for replacement in ("file", "directory"):
                changed = False
                def racing_read(fd, size):
                    nonlocal changed
                    body = original_read(fd, size)
                    if not changed:
                        changed = True
                        if replacement == "file":
                            private_file(saved, b"replacement JAR", 0o640, 65534)
                            os.chown(saved, 65534, 65534)
                            os.replace(saved, jar)
                        else:
                            jar.parent.rename(jar.parent.with_name("held-lib"))
                            jar.parent.mkdir(mode=0o750)
                            os.chown(jar.parent, 65534, 65534)
                    return body
                os.read = racing_read
                try:
                    with self.assertRaisesRegex(SetupError, "state_changed"):
                        fs.read_indexer_jar(65534, 65534)
                finally:
                    os.read = original_read
                self.assertTrue(changed)
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
            text = firewall_create_text(fixture.profile)
            fixture.nft("--check", "--file", "-", data=text.encode())
            # A failing suffix must not commit even the successful create prefix.
            invalid = text + f"add rule inet {TABLE} missing_chain counter\n"
            self.assertNotEqual(fixture.nft("--file", "-", data=invalid.encode(), check=False).returncode, 0)
            self.assertNotEqual(fixture.nft("list", "table", "inet", TABLE, check=False).returncode, 0)
            # Match production's one exclusive batch, then exact verification.
            fixture.nft("--file", "-", data=text.encode())
            fixture.verify_table()
            before = fixture.table()
            self.assertNotEqual(fixture.nft("--file", "-", data=text.encode(), check=False).returncode, 0)
            self.assertEqual(fixture.table(), before)  # includes every handle
            self.assertTrue(fixture.reachable(fixture.allowed))
            self.assertFalse(fixture.reachable(fixture.denied))
            fixture.nft("delete", "table", "inet", TABLE)
            fixture.wait_reachable(fixture.denied)

    def test_systemd_every_start_guard(self):
        with network_fixture(self) as fixture:
            # Real service properties/DBus; no vendor service or nft mutation.
            property_service = '''[Service]
Type=oneshot
RemainAfterExit=yes
User=nobody
Group=nogroup
TimeoutStartSec=15
TimeoutStopSec=5
ExecStart=/usr/bin/true
'''
            empty_name = fixture.unit("empty-prestart", property_service)
            nonempty_name = fixture.unit("nonempty-prestart", property_service + "ExecStartPre=/usr/bin/true\n"
                                         "RestrictAddressFamilies=AF_UNIX\nSystemCallFilter=~getppid\n")
            fixture.systemctl("daemon-reload")
            fixture.systemctl("start", empty_name)
            fixture.systemctl("start", nonempty_name)
            self.assertEqual(h.LinuxHost().properties(empty_name, ("ExecStartPre", "LoadState"))["ExecStartPre"], "")
            filters = ("RestrictAddressFamilies", "SystemCallFilter")
            unrestricted = {}
            for unit in (empty_name, nonempty_name):
                # Separate actual display, typed bus and production-reader queries.
                raw = command("systemctl", "show", unit, "--no-pager", "--property=" + ",".join(filters)).stdout
                display = dict(line.split("=", 1) for line in raw.decode("ascii").splitlines())
                self.assertEqual(set(display), set(filters))
                canonical = h.LinuxHost().properties(unit, filters)
                # Owned fixture names contain only letters/digits/hyphens/dot.
                path = "/org/freedesktop/systemd1/unit/" + unit.replace("-", "_2d").replace(".", "_2e")
                for key in filters:
                    typed = command("busctl", "--system", "get-property", "org.freedesktop.systemd1",
                                    path, "org.freedesktop.systemd1.Service", key).stdout
                    if unit == empty_name:
                        self.assertIn(display[key], ("", "~"))
                        self.assertIn(typed, (b"(bas) false 0", b"(bas) false 0\n"))
                        self.assertEqual(canonical[key], "")
                        unrestricted[key] = {"display": display[key],
                                             "dbus": typed.decode("ascii").removesuffix("\n"),
                                             "canonical": canonical[key]}
                    else:
                        expected = {"RestrictAddressFamilies": ("AF_UNIX", b'(bas) true 1 "AF_UNIX"'),
                                    "SystemCallFilter": ("~getppid", b'(bas) false 1 "getppid"')}
                        self.assertEqual(display[key], expected[key][0])
                        self.assertIn(typed, (expected[key][1], expected[key][1] + b"\n"))
                        self.assertEqual(canonical[key], display[key])
                        self.assertNotEqual(canonical[key], "")
            OBSERVATIONS.setdefault(self.id(), {})["unrestricted_filters"] = unrestricted
            owned_property_units = {empty_name, nonempty_name}
            class OmittedPropertyCommands(h.Commands):
                bus_reads = 0
                def run(adapter, name, *args, **kwargs):
                    # Only reproduce the systemctl serialization omission. The
                    # independent busctl query and response are actual/unmodified.
                    output, errors = super().run(name, *args, **kwargs)
                    if name == "systemctl" and len(args) >= 2 and args[0] == "show" and args[1] in owned_property_units:
                        output = b"\n".join(line for line in output.splitlines() if not line.startswith(b"ExecStartPre=")) + b"\n"
                    if name == "busctl":
                        adapter.bus_reads += 1
                    return output, errors
            fs = h.SecureFS()
            commands = OmittedPropertyCommands(fs)
            reader = h.LinuxHost(fs=fs, commands=commands)
            self.assertEqual(reader.properties(empty_name, ("ExecStartPre", "LoadState")), {"ExecStartPre": "", "LoadState": "loaded"})
            with self.assertRaisesRegex(SetupError, "host_unsupported"):
                reader.properties(nonempty_name, ("ExecStartPre", "LoadState"))
            self.assertEqual(commands.bus_reads, 2)
            OBSERVATIONS.setdefault(self.id(), {}).update(empty_execstartpre_dbus_confirmed=True,
                                                         nonempty_execstartpre_dbus_refused=True)
            # Reachability proof precedes guard, with exactly the listener used by systemd.
            fixture.start_listener()
            fixture.processes[0].terminate()
            fixture.processes[0].wait(timeout=5)
            fixture.processes.clear()
            loader_mapping = inactive_loader_inventory(fixture)
            OBSERVATIONS.setdefault(self.id(), {}).update(
                loader_query_mapping=loader_mapping,
                loader_facts={role: h.LinuxHost().properties(unit, uh.LOADER_KEYS) for role, unit in loader_mapping.items()},
                loader_scope="owned_namespace_inventory_not_host_eligibility",
                strict_path_exception_not_used=True)
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
            # Declared paths and owned loader query identities relocate. CLI/manifest checks,
            # Guard/verifier remain unchanged; FixtureCommands fences each real execution.
            driver = f'''import os, sys
from pathlib import Path
sys.path.insert(0, {str(source)!r})
from https_setup import host, ufw_host
loader_mapping = {loader_mapping!r}
class FixtureCommands(host.Commands):
    def _execute(self, executable, args, *, data=None, argv0=None):
        if os.geteuid() != 0 or os.stat("/proc/self/ns/net").st_ino != {fixture.inode}:
            raise AssertionError("fixture_namespace_required")
        return super()._execute(executable, args, data=data, argv0=argv0)
class FixtureHost(host.LinuxHost):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.commands = FixtureCommands(self.fs)
    def firewall_loaders(self):
        return {{role: self.properties(unit, host.LOADER_KEYS) for role, unit in loader_mapping.items()}}
    def ufw_reader(self):
        raise AssertionError("strict fixture must never use UFW exception")
host.LinuxHost = FixtureHost
from https_setup.cli import main
host.RECORD_PATH = ufw_host.RECORD_PATH = {str(fixture.root / 'absent-policy' / 'ufw-compat.json')!r}
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
            guard = guard_unit().replace("wazuh-indexer.service", indexer_name).replace("ufw.service", loader_mapping["ufw.service"])
            guard = guard.replace(h.ENTRYPOINT, entry).replace(h.PROFILE, str(profile_path))
            guard = guard.replace("[Service]\n", f"[Service]\nTimeoutStartSec=15\nTimeoutStopSec=5\nNetworkNamespacePath=/run/netns/{fixture.server}\nExecStartPre={assert_command} ensure-assert\n")
            self.assertEqual(fixture.unit("guard", guard), guard_name)
            dropin = indexer_dropin().replace("aegis-wazuh-http-guard.service", guard_name).replace("ufw.service", loader_mapping["ufw.service"])
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
            fixture.nft("--file", "-", data=firewall_create_text(fixture.profile).encode())
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
    def test_ufw_disabled_wrapper_preserved(self):
        """Exact packaged vendor behavior, with honest separate admission scopes."""
        spec = importlib.util.spec_from_file_location("native_gate_schema", KIT / "Run-SelfTests.py")
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        real_before = real_ufw_baseline()
        with network_fixture(self) as fixture:
            observation = OBSERVATIONS.setdefault(self.id(), {})
            checks, operations, nft_observations = {}, {}, {}
            observation.update(checks=checks, operations=operations, nft_observations=nft_observations)
            root = vendor_tree(fixture)
            vendor_before = vendor_digest(root)
            # Separate child root: nft tool closure cannot become vendor executables.
            probe_root = fixture.root / "probe-root"
            probe_root.mkdir(mode=0o755)
            copy_tool_closure(probe_root, ("/usr/sbin/nft",))
            (probe_root / "dev").mkdir()
            private_file(probe_root / "dev/null", b"")  # child-only real device bind target
            (probe_root / "run").mkdir()
            nft_observations["empty"] = native_nft_read(self, fixture, probe_root)
            foreign_name = "aegis_fixture_foreign"
            fixture.nft("--file", "-", data=(f"add table inet {foreign_name}\n"
                        f"add chain inet {foreign_name} input {{ type filter hook input priority 10; policy accept; }}\n"
                        f"add rule inet {foreign_name} input tcp dport 9200 counter\n").encode())
            def foreign_digest():
                document = json.loads(fixture.nft("--json", "list", "table", "inet", foreign_name).stdout)
                return tx.digest(h.stable_firewall(document))
            foreign_before = foreign_digest()
            nft_observations["foreign"] = native_nft_read(self, fixture, probe_root)
            for prefix in ("ufw-", "ufw6-"):
                fixture.nft("add", "chain", "inet", foreign_name, prefix + "partial")
                try:
                    nft_observations[prefix + "partial"] = native_nft_read(self, fixture, probe_root, refusal=True)
                finally:
                    fixture.nft("delete", "chain", "inet", foreign_name, prefix + "partial")
            checks.update(fresh_nft_observation_preserved=True, ufw_lock_absent_preserved=True,
                          ufw_lock_present_preserved=True, partial_ufw_chains_refused=True)
            fixture.start_listener()  # establishes both source routes with CA-verified TLS
            fixture.processes[0].terminate()
            fixture.processes[0].wait(timeout=5)
            fixture.processes.clear()
            wrapper = fixture.unit("wrapper", f'''[Unit]
Description=Owned exact disabled UFW wrapper fixture
DefaultDependencies=no
[Service]
Type=oneshot
RemainAfterExit=yes
RootDirectory={root}
WorkingDirectory=/
NetworkNamespacePath=/run/netns/{fixture.server}
ExecStart=/usr/lib/ufw/ufw-init start quiet
ExecStop=/usr/lib/ufw/ufw-init stop
TimeoutStartSec=15
TimeoutStopSec=5
[Install]
WantedBy=multi-user.target
''')
            mapping = {"ufw.service": wrapper, uh.GUARD: f"aegis-native-{fixture.token}-ufw-guard.service",
                       uh.INDEXER: f"aegis-native-{fixture.token}-ufw-indexer.service"}
            driver, profile, record = synthetic_guard_driver(fixture, root, mapping)
            checks["synthetic_positive_admission_verified"] = record.is_file()
            def render(body):
                for original, renamed in mapping.items():
                    body = body.replace(original, renamed)
                return body.replace(h.ENTRYPOINT, str(driver)).replace(h.PROFILE, str(profile))
            guard = render(guard_unit()).replace("[Service]\n", f"[Service]\nNetworkNamespacePath=/run/netns/{fixture.server}\nTimeoutStartSec=15\nTimeoutStopSec=5\n")
            self.assertEqual(fixture.unit("ufw-guard", guard), mapping[uh.GUARD])
            listener = f'''[Service]
Type=simple
User=nobody
Group=nogroup
NetworkNamespacePath=/run/netns/{fixture.server}
TimeoutStartSec=15
TimeoutStopSec=5
ExecStart=/usr/bin/python3 -I -B {fixture.root}/listener.py {fixture.credentials}/cert.pem {fixture.credentials}/key.pem {fixture.indexer}
'''
            self.assertEqual(fixture.unit("ufw-indexer", listener + "\n" + render(indexer_dropin())), mapping[uh.INDEXER])
            names = gate.transaction_names(mapping)
            controller = fixture.unit("transaction-controller", gate.transaction_body("controller",names).decode("ascii"))
            observer = make_stop_observer(fixture, mapping, controller)
            transaction = observation.setdefault("native_adapter", {})["transaction"] = dict(
                mechanism="owned_controller_wants_and_propagates_stop_to_v1",controller=controller,observer=observer,phases={})
            fixture.systemctl("daemon-reload")
            def props(unit, keys):
                return h.LinuxHost().properties(unit, keys)
            def packets(name):
                fixture.wait_reachable(fixture.allowed)
                self.assertFalse(fixture.reachable(fixture.denied))
                fixture.verify_table()
                self.assertEqual(foreign_digest(), foreign_before)
                operations[name] = dict(allowed=True, denied=True, table=True, foreign=True)
            def direct_guard(ensure=False):
                return fixture.net(fixture.server, "/usr/bin/python3", "-I", "-B", driver,
                                   "guard-ensure" if ensure else "guard-verify", "--profile", profile, check=False)
            def refused_guard(expected, ensure=False):
                result = direct_guard(ensure)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(json.loads(result.stdout), {"status": "error", "error": expected})
            # A cold kit start cannot activate UFW: only After, never activation edges.
            fixture.systemctl("start", mapping[uh.INDEXER])
            self.assertEqual(props(wrapper, ("ActiveState", "UnitFileState")), {"ActiveState": "inactive", "UnitFileState": "disabled"})
            checks["no_unintended_wrapper_start"] = True
            packets("cold_guard")
            checks["cold_guard_verified"] = True
            fixture.systemctl("stop", mapping[uh.INDEXER], mapping[uh.GUARD])
            fixture.verify_table()
            fixture.systemctl("start", observer)  # retention setup, outside all three measured phases
            measure_owned_transaction(fixture,mapping,transaction,"concurrent_start",gate)
            def timestamp(unit, key):
                value = int(fixture.systemctl("show", unit, "--property=" + key, "--value").stdout)
                self.assertGreater(value, 0)
                return value
            checks["concurrent_start_order_verified"] = True
            packets("concurrent_start")
            state_before = props(wrapper, ("ActiveState", "SubState", "UnitFileState"))
            self.assertEqual(state_before, {"ActiveState": "active", "SubState": "exited", "UnitFileState": "disabled"})
            # All native file reads use the production held no-follow reader.
            actual_reader = uh.UfwHostReader(h.LinuxHost())
            for path, expected in VENDOR.items():
                self.assertEqual(actual_reader.root_file(str(root / path.lstrip("/")), u.LIMIT).body, expected)
            checks["native_file_reads_verified"] = True
            label = "".join(c if c.isalpha() or i > 0 and c.isdigit() else "_%02x" % ord(c) for i, c in enumerate(wrapper))
            class OwnedUnitHost(h.LinuxHost):
                def properties(self, unit, keys):
                    return super().properties(wrapper if unit == "ufw.service" else unit, keys)
                def run(self, name, *args, **kwargs):
                    if name == "busctl":
                        args = tuple("/org/freedesktop/systemd1/unit/" + label if a == "/org/freedesktop/systemd1/unit/ufw_2eservice" else a for a in args)
                    return super().run(name, *args, **kwargs)
            unit_reader = uh.UfwHostReader(OwnedUnitHost())
            observed_props = unit_reader.properties("ufw.service", u.PROPERTIES)
            self.assertEqual(observed_props["RootDirectory"], str(root))
            self.assertEqual(observed_props["FragmentPath"], "/run/systemd/system/" + wrapper)
            with self.assertRaises(ValueError):
                u._unit(unit_reader)  # production classifier must refuse these real facts
            job = u._bus(unit_reader, "Job", "(uo)")
            self.assertEqual(job, [0, "/"])
            native_bus = {"Job": {"type": "(uo)", "data": job}}
            for key, signature in u.EMPTY_ARRAYS.items():
                data = u._bus(unit_reader, key, signature)
                self.assertEqual(data, [])
                native_bus[key] = {"type": signature, "data": data}
            for key, args in (("ExecStartEx", ["start", "quiet"]), ("ExecStopEx", ["stop"])):
                data = u._bus(unit_reader, key, "a(sasasttttuii)")
                self.assertEqual(data[0][:3], [u.INIT_PATH, [u.INIT_PATH, *args], []])
                native_bus[key] = {"type": "a(sasasttttuii)", "data": data}
            checks.update(native_typed_bus_verified=True, native_modified_unit_refused=True)
            # Only selected --version calls; no CLI or compatibility list probes.
            identities = [actual_reader.backend_identity(name) for name in ("iptables", "ip6tables")]
            self.assertEqual(identities[0]["file"].body, identities[1]["file"].body)
            self.assertTrue(all(b"(nf_tables)" in item["version"] for item in identities))
            checks["native_backends_verified"] = True
            fixture.systemctl("stop", wrapper)
            packets("normal_stop")
            fixture.systemctl("start", wrapper)
            fixture.systemctl("restart", wrapper)
            packets("normal_restart")
            self.assertNotEqual(fixture.systemctl("reload", wrapper, check=False).returncode, 0)
            packets("systemd_reload_refused")
            for operation, name in (("restart", "direct_restart"), ("force-reload", "direct_force_reload")):
                wrapper_direct(fixture, root, operation)
                packets(name)
            guard_started = timestamp(mapping[uh.GUARD], "ActiveEnterTimestampMonotonic")
            fixture.systemctl("restart", mapping[uh.INDEXER])
            self.assertEqual(timestamp(mapping[uh.GUARD], "ActiveEnterTimestampMonotonic"), guard_started)
            packets("active_guard_restart")
            checks["active_guard_verified"] = True
            measure_owned_transaction(fixture,mapping,transaction,"concurrent_stop",gate)
            fixture.verify_table()
            checks.update(concurrent_stop_order_verified=True, guard_stop_retained_table=True)
            measure_owned_transaction(fixture,mapping,transaction,"concurrent_stop_start",gate)
            fixture.systemctl("stop", observer)  # release only after all retained samples qualify
            packets("concurrent_stop_start")
            # Refusals alter fixture data only; do not execute enabled vendor branches.
            fixture.systemctl("stop", mapping[uh.INDEXER])
            conf = root / u.CONF_PATH.lstrip("/")
            disabled = conf.read_bytes()
            frozen_record = record.read_bytes()
            try:
                replace_fixture_file(fixture.root, conf, b"ENABLED=yes\nLOGLEVEL=low\n", 0o644)
                refused_guard("ufw_unsupported")
                self.assertNotEqual(fixture.systemctl("start", mapping[uh.INDEXER], check=False).returncode, 0)
                checks["enabled_policy_refused"] = True
            finally:
                replace_fixture_file(fixture.root, conf, disabled, 0o644)
            # Valid disabled config can still drift from the installed static record.
            replace_fixture_file(fixture.root, conf, b"ENABLED=no\nLOGLEVEL=medium\n", 0o644)
            try:
                refused_guard("ufw_drift", ensure=True)
                refused_guard("ufw_drift")
            finally:
                replace_fixture_file(fixture.root, conf, disabled, 0o644)
            # The installed guard must freshly see a partial chain despite earlier clean reads.
            fixture.nft("add", "chain", "inet", foreign_name, "ufw-partial")
            try:
                refused_guard("ufw_unsupported", ensure=True)
                refused_guard("ufw_unsupported")
            finally:
                fixture.nft("delete", "chain", "inet", foreign_name, "ufw-partial")
            changed = json.loads(frozen_record)
            changed["profile_sha256"] = "0" * 64
            replace_fixture_file(fixture.root, record, tx.encoded(changed))
            try:
                refused_guard("ufw_drift", ensure=True)
                refused_guard("ufw_drift")
                checks["static_record_drift_refused"] = True
            finally:
                replace_fixture_file(fixture.root, record, frozen_record)
            fixture.nft("delete", "table", "inet", TABLE)
            refused_guard("firewall_mismatch")
            checks["deleted_table_refused"] = True
            self.assertEqual(direct_guard(ensure=True).returncode, 0)
            fixture.nft("add", "rule", "inet", TABLE, "input", "counter", "accept")
            refused_guard("firewall_mismatch")
            refused_guard("firewall_mismatch", ensure=True)
            checks["modified_table_refused"] = True
            fixture.nft("delete", "table", "inet", TABLE)
            self.assertEqual(direct_guard(ensure=True).returncode, 0)
            self.assertEqual(record.read_bytes(), frozen_record)
            cases = dependency_observations(fixture)
            self.assertEqual(props(wrapper, ("ActiveState", "SubState", "UnitFileState")), state_before)
            vendor_after, foreign_after = vendor_digest(root), foreign_digest()
            self.assertEqual(vendor_before, vendor_after)
            self.assertEqual(foreign_before, foreign_after)
            checks.update(vendor_bytes_preserved=True, vendor_state_preserved=True, foreign_rules_preserved=True,
                          namespace_assertion_before_mutations=True)
            OBSERVATIONS[self.id()] = dict(
                vendor_deb_sha256="096eb403ecaf6740d160bb306970f025222ef71324319cc1cb78d06dfa462ef1",
                vendor_inputs={path: hashlib.sha256(body).hexdigest() for path, body in VENDOR.items()},
                relocations=gate.UFW_RELOCATIONS, checks=checks, operations=operations, unit_mapping=mapping,
                dependency_cases=cases,
                nft_observations=nft_observations,
                native_adapter={"transaction": transaction, "unit_properties": {**observed_props, "RootDirectory": "<owned_vendor_root>"},
                                "typed_bus": native_bus,
                                "backend_sha256": hashlib.sha256(identities[0]["file"].body).hexdigest()},
                preservation_hashes={"vendor": {"before": vendor_before, "after": vendor_after},
                                     "foreign": {"before": foreign_before, "after": foreign_after},
                                     "fresh_nft": {"before": tx.digest(nft_observations["foreign"]["document"]), "after": nft_observations["foreign"]["after_sha256"]}},
                scope={"native": "vendor_lifecycle_packets_order_and_adapter_refusal", "positive_admission": "synthetic_reader",
                       "probe": "nft-no-ufw-chains-v1", "owner_full_class_check": "pending", "vendor_lab_acceptance": False})
        real_after = real_ufw_baseline()
        self.assertEqual(real_before, real_after)
        OBSERVATIONS[self.id()]["preservation_hashes"]["real_ufw"] = {"before": real_before, "after": real_after}
        OBSERVATIONS[self.id()]["checks"]["real_ufw_baseline_preserved"] = True
