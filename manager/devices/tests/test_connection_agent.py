"""Real published CLI -> verified TLS -> production Django issuer and views.

The bounded HTTPS adapter models nginx's verified certificate forwarding from
the TLS socket; nginx's shipped configuration has its separate real proxy gate.
Only synthetic private material is created, outside release/source directories.
"""
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
from threading import Thread
import time
from unittest import skipUnless
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone

from accounts.models import AccountMutationLock
from control.models import Device
from devices.contracts import device_dto
from devices.issuer import initialize_issuer
from devices.models import PairingCode
from devices.services import create_pairing_code, revoke_device


class QuietTlsAdapter(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        if self.path not in ("/agent/v2/enroll", "/agent/v2/heartbeat"):
            self.send_error(404)
            return
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 16384:
            self.send_error(400)
            return
        certificate = self.connection.getpeercert(binary_form=True)
        headers = {"HTTP_X_FORWARDED_PROTO": "https"}
        if certificate:
            pem = ssl.DER_cert_to_PEM_cert(certificate)
            headers.update(HTTP_X_AEGIS_CLIENT_VERIFY="SUCCESS", HTTP_X_AEGIS_CLIENT_CERT=quote(pem, safe=""))
        # Caller-supplied identity headers are discarded. Only the TLS socket's
        # verified certificate enters the production request identity boundary.
        response = Client().post(self.path, data=self.rfile.read(size), content_type="application/json",
                                 REMOTE_ADDR="127.0.0.1", **headers)
        self.send_response(response.status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response.content)))
        self.end_headers()
        self.wfile.write(response.content)


def private_file(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def synthetic_tls(root):
    now = timezone.now()
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AEGIS synthetic TLS CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-server")])
    server = (x509.CertificateBuilder().subject_name(subject).issuer_name(name).public_key(key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
              .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
              .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(ca_key, hashes.SHA256()))
    for filename, data in (("server-ca.pem", ca.public_bytes(serialization.Encoding.PEM)),
                           ("server.pem", server.public_bytes(serialization.Encoding.PEM)),
                           ("server-key.pem", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))):
        private_file(root / filename, data)


def connection_test_owner():
    # TransactionTestCase flush removes migration data between test methods.
    AccountMutationLock.objects.get_or_create(pk=1)
    return get_user_model().objects.create_superuser("synthetic-tls-owner", password="synthetic-test-only")


NATIVE_DIAGNOSTIC_STAGES = frozenset(("preflight", "installer", "configuration", "status", "restart", "uninstall", "owner_conflict", "helper"))
# This reviewed static vocabulary is also read by the disposable native helpers;
# never learn labels from captured output or arbitrary exception messages.
NATIVE_DIAGNOSTIC_CODES = frozenset((Path(__file__).resolve().parents[3] /
    "scripts/tests/agent/native-diagnostic-codes.txt").read_text(encoding="ascii").splitlines())


def native_diagnostic(stderr):
    if len(stderr) > 512:
        return None

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result

    try:
        data = json.loads(stderr, object_pairs_hook=unique_object)
        if type(data) is not dict or set(data) != {"stage", "code"}:
            return None
        stage, code = data["stage"], data["code"]
        if type(stage) is not str or stage not in NATIVE_DIAGNOSTIC_STAGES or type(code) is not str:
            return None
        known = code in NATIVE_DIAGNOSTIC_CODES
        if not known:
            match = re.fullmatch(r"(win32|hresult)_(-?(?:0|[1-9][0-9]*))", code)
            if match:
                value = int(match[2])
                known = str(value) == match[2] and ((match[1] == "win32" and 0 <= value <= 65535)
                    or (match[1] == "hresult" and -(2 ** 31) <= value < 2 ** 31))
        return stage + ":" + code if known else None
    except (ValueError, TypeError, RecursionError):
        return None


def assert_native_result(action, result, *, code=None):
    # Do this Boolean check before any assertion or diagnostic classification so
    # nonzero exits cannot bypass the input leak guard or echo captured values.
    if code is not None and (code in result.stdout or code in result.stderr):
        raise AssertionError("Native helper exposed synthetic input; output withheld")
    if len(result.stdout) >= 4096:
        raise AssertionError("Native output exceeded public result cap")
    if result.returncode != 0:
        safe_action = action if action in ("Install", "Restart", "Reinstall", "Status", "Uninstall") else "unknown"
        diagnostic = native_diagnostic(result.stderr)
        suffix = " [" + diagnostic + "]" if diagnostic is not None else ""
        raise AssertionError("Native " + safe_action + " failed" + suffix + "; output withheld")


def native_process_environment(platform, environment):
    # pwsh only adjusts PSModulePath when it launches Windows PowerShell directly.
    # Python inherits Core's paths; let the Windows child rebuild its native paths.
    return {key: value for key, value in environment.items()
            if platform != "nt" or key.casefold() != "psmodulepath"}


class NativeProcessEnvironmentTests(SimpleTestCase):
    def test_windows_preserves_ci_guards_and_other_environment_case_insensitively(self):
        for name in ("PSModulePath", "PSMODULEPATH", "psmodulepath"):
            inherited = {name: "synthetic Core modules", "GITHUB_ACTIONS": "true",
                         "RUNNER_OS": "Windows", "PATH": "synthetic tools", "OTHER": "unchanged"}
            self.assertEqual(native_process_environment("nt", inherited),
                             {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows",
                              "PATH": "synthetic tools", "OTHER": "unchanged"})
            self.assertEqual(inherited[name], "synthetic Core modules")

    def test_linux_preserves_module_path_and_all_other_environment(self):
        inherited = {"PSMODULEPATH": "synthetic Core modules", "GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux"}
        self.assertEqual(native_process_environment("posix", inherited), inherited)

    @skipUnless(os.name == "nt", "Windows PowerShell module resolution requires Windows")
    def test_python_child_loads_windows_modules_despite_inherited_powershell_core_path(self):
        core = shutil.which("pwsh")
        self.assertIsNotNone(core, "PowerShell Core is required to reproduce the CI process boundary")
        discovery = subprocess.run([core, "-NoProfile", "-Command", "$PSHOME"],
                                   capture_output=True, text=True, timeout=15)
        self.assertEqual(discovery.returncode, 0, "PowerShell Core discovery failed; output withheld")
        core_modules = Path(discovery.stdout.strip()) / "Modules"
        self.assertTrue(core_modules.is_dir(), "PowerShell Core modules unavailable")
        inherited = dict(os.environ)
        inherited["PSMODULEPATH"] = str(core_modules) + os.pathsep + inherited.get("PSMODULEPATH", "")
        windows_shell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
        probe = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
foreach ($name in @('Get-FileHash', 'Get-Acl', 'Get-CimInstance')) {
    $command = Get-Command $name -ErrorAction Stop
    $moduleRoot = $command.Module.ModuleBase
    if ($moduleRoot -ine $PSHOME -and !$moduleRoot.StartsWith(($PSHOME + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'unexpected_module_origin'
    }
    [Console]::Out.WriteLine($name)
}
"""
        result = subprocess.run([windows_shell, "-NoProfile", "-Command", probe],
                                env=native_process_environment("nt", inherited),
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, "Windows child could not load its native modules; output withheld")
        self.assertEqual(result.stdout.splitlines(), ["Get-FileHash", "Get-Acl", "Get-CimInstance"])


class NativeDiagnosticsTests(SimpleTestCase):
    def result(self, stderr, stdout="", returncode=1):
        return subprocess.CompletedProcess(["synthetic-helper"], returncode, stdout, stderr)

    def test_recognized_closed_diagnostic_surfaces_only_fixed_stage_and_code(self):
        result = self.result('{"stage":"installer","code":"state_invalid"}\n',
                             stdout="synthetic private stdout /private/path")
        with self.assertRaises(AssertionError) as caught:
            assert_native_result("Install", result)
        self.assertEqual(str(caught.exception), "Native Install failed [installer:state_invalid]; output withheld")

    def test_untrusted_output_is_withheld_including_unknown_extra_and_duplicate_json(self):
        outputs = ["", "synthetic private key /private/path", "state_invalid",
            '{"stage":"installer","code":"unknown_private_value"}',
            '{"stage":"private_path","code":"state_invalid"}',
            '{"stage":"installer","code":"state_invalid","private":"synthetic secret"}',
            '{"stage":"installer","code":"state_invalid","code":"synthetic secret"}',
            '{"stage":"installer","code":"state_invalid"}\nsynthetic stack trace',
            '{"stage":"installer","code":1}', 'x' * 513,
            '{"stage":"installer","code":"win32_65536"}',
            '{"stage":"installer","code":"win32_-1"}',
            '{"stage":"installer","code":"hresult_2147483648"}',
            '{"stage":"installer","code":"hresult_-2147483649"}',
            '{"stage":"installer","code":"exception_synthetic_secret"}']
        for index, stderr in enumerate(outputs):
            with self.subTest(index=index), self.assertRaises(AssertionError) as caught:
                assert_native_result("Install", self.result(stderr, stdout="synthetic private stdout"))
            self.assertEqual(str(caught.exception), "Native Install failed; output withheld")

    def test_bounded_native_numbers_and_known_exception_type_are_safe_diagnostics(self):
        for code in ("win32_5", "hresult_-2147024891", "exception_unauthorizedaccess"):
            with self.subTest(code=code), self.assertRaises(AssertionError) as caught:
                assert_native_result("Install", self.result(json.dumps({"stage": "installer", "code": code})))
            self.assertEqual(str(caught.exception), "Native Install failed [installer:" + code + "]; output withheld")

    def test_pairing_leak_is_detected_before_exit_status_or_diagnostic_classification(self):
        code = "a" * 64
        for returncode in (0, 1):
            for stream in ("stdout", "stderr"):
                stdout, stderr = "", '{"stage":"installer","code":"state_invalid"}'
                if stream == "stdout":
                    stdout = code
                else:
                    stderr = code
                with self.subTest(exit=returncode, stream=stream), self.assertRaises(AssertionError) as caught:
                    assert_native_result("Install", self.result(stderr, stdout, returncode), code=code)
                self.assertEqual(str(caught.exception), "Native helper exposed synthetic input; output withheld")


class ConnectionFixtureTests(TransactionTestCase):
    def test_pairing_fixture_can_start_after_a_previous_transaction_test_flush(self):
        # TransactionTestCase flushes rows after each method; data migrations do
        # not rerun, so this must work independently of the initial seeded row.
        call_command("flush", interactive=False, verbosity=0)
        self.assertFalse(AccountMutationLock.objects.exists())
        owner = connection_test_owner()
        minted = create_pairing_code(actor=owner, environment_id="synthetic.after-flush")
        self.assertEqual(PairingCode.objects.get(pk=minted["id"]).issued_by_id, owner.pk)
        self.assertEqual(AccountMutationLock.objects.count(), 1)


@skipUnless(os.environ.get("AEGIS_CONNECTION_TEST_EXE"), "Published connection CLI required; native CI sets AEGIS_CONNECTION_TEST_EXE")
class PublishedConnectionTests(TransactionTestCase):
    def setUp(self):
        self.executable = Path(os.environ["AEGIS_CONNECTION_TEST_EXE"])
        self.assertTrue(self.executable.is_absolute() and self.executable.is_file(), "Published CLI is missing")
        self.temporary = tempfile.TemporaryDirectory(prefix="aegis-real-tls-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.setting = override_settings(PRIVATE_ROOT=self.root, ENROLLMENT_CA_KEY=str(self.root / "issuer-key.pem"),
            ENROLLMENT_CA_CERT=str(self.root / "issuer.pem"), ALLOWED_HOSTS=["testserver"])
        self.setting.enable()
        self.addCleanup(self.setting.disable)
        self.owner = connection_test_owner()
        initialize_issuer()
        synthetic_tls(self.root)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.root / "server.pem"), str(self.root / "server-key.pem"))
        context.load_verify_locations(cafile=str(self.root / "issuer.pem"))
        context.verify_mode = ssl.CERT_OPTIONAL
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietTlsAdapter)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.origin = "https://127.0.0.1:" + str(self.server.server_port)
        self.state = self.root / "endpoint"

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def cli(self, *arguments, code=None):
        # Never include code in argv/environment/file, and never show captured
        # unredacted child output if an assertion fails.
        result = subprocess.run([str(self.executable), *arguments], input=None if code is None else code + "\n",
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, "Published CLI failed; output withheld")
        if code is not None:
            self.assertTrue(code not in result.stdout + result.stderr, "Child exposed synthetic pairing input; output withheld")
        return result.stdout

    def wait_until(self, predicate, description):
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.1)
        self.fail(description)

    def start_loop(self):
        process = subprocess.Popen([str(self.executable), "run", "--state-dir", str(self.state)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: self.stop_loop(process))
        return process

    @staticmethod
    def stop_loop(process):
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=20)

    def test_cli_enrolls_over_ip_san_tls_reconnects_same_uuid_and_honors_revoke(self):
        code = create_pairing_code(actor=self.owner, environment_id="synthetic.tls")["code"]
        self.cli("connect", "--manager", self.origin, "--server-ca", str(self.root / "server-ca.pem"),
                 "--state-dir", str(self.state), code=code)
        status = json.loads(self.cli("status", "--state-dir", str(self.state)))
        identity = status["device_id"]
        device = Device.objects.get(pk=identity)
        self.assertEqual(device_dto(device)["status"], "offline")
        self.assertEqual(device.connection_kind, "paired_presence")
        self.assertIsNone(device.wazuh_agent_id)
        first = self.start_loop()
        self.wait_until(lambda: Device.objects.get(pk=identity).last_heartbeat_at is not None, "Real TLS heartbeat not received")
        device.refresh_from_db()
        self.assertEqual(device_dto(device)["status"], "online")
        previous = device.last_heartbeat_at
        self.stop_loop(first)
        second = self.start_loop()
        self.wait_until(lambda: Device.objects.get(pk=identity).last_heartbeat_at > previous, "Reconnect did not reuse identity")
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(json.loads(self.cli("status", "--state-dir", str(self.state)))["device_id"], identity)
        revoke_device(actor=self.owner, device_id=identity)
        self.wait_until(lambda: second.poll() is not None, "Client ignored Manager identity revocation")
        self.assertEqual(second.returncode, 3)
        self.assertEqual(json.loads(self.cli("status", "--state-dir", str(self.state)))["state"], "identity_denied")
        self.assertEqual(device_dto(Device.objects.get(pk=identity))["status"], "revoked")

    def native_phase(self, action, *, identity=None, code=None):
        repository = Path(__file__).resolve().parents[3]
        package = Path(os.environ["AEGIS_CONNECTION_SERVICE_PACKAGE"])
        self.assertTrue(package.is_absolute() and package.is_dir(), "Native release package missing")
        if os.name == "nt":
            command = [str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"),
                "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                str(repository / "scripts/tests/agent/Test-WindowsService.ps1"),
                "-Action", action, "-PackageRoot", str(package), "-ManagerOrigin", self.origin,
                "-ServerCa", str(self.root / "server-ca.pem")]
            if identity:
                command += ["-ExpectedDeviceId", identity]
        else:
            command = ["sudo", "--preserve-env=GITHUB_ACTIONS,RUNNER_OS", "bash",
                str(repository / "scripts/tests/agent/test-systemd-service.sh"),
                "--action", action, "--package-root", str(package), "--manager-origin", self.origin,
                "--server-ca", str(self.root / "server-ca.pem")]
            if identity:
                command += ["--expected-device-id", identity]
        result = subprocess.run(command, input="" if code is None else code + "\n",
                                env=native_process_environment(os.name, os.environ),
                                capture_output=True, text=True, timeout=120)
        assert_native_result(action, result, code=code)
        data = json.loads(result.stdout)
        self.assertEqual(set(data), {"action", "device_id", "state", "service_status", "identity_preserved"})
        self.assertEqual(data["action"], action)
        self.assertTrue(data["identity_preserved"])
        if identity:
            self.assertEqual(data["device_id"], identity)
        return data

    @skipUnless(os.environ.get("AEGIS_CONNECTION_SERVICE_PACKAGE"), "Disposable native service CI package required")
    def test_native_installer_service_account_reconnect_reinstall_revoke_and_preserving_uninstall(self):
        code = create_pairing_code(actor=self.owner, environment_id="synthetic.service")["code"]
        installed = self.native_phase("Install", code=code)
        identity = installed["device_id"]
        self.assertEqual(installed["service_status"], "Running" if os.name == "nt" else "active")
        try:
            self.wait_until(lambda: Device.objects.get(pk=identity).last_heartbeat_at is not None,
                            "Native service account did not complete actual TLS heartbeat")
            for action in ("Restart", "Reinstall"):
                previous = Device.objects.get(pk=identity).last_heartbeat_at
                self.native_phase(action, identity=identity)
                self.wait_until(lambda: Device.objects.get(pk=identity).last_heartbeat_at > previous,
                                "Native " + action + " failed to reconnect with same identity")
                self.assertEqual(Device.objects.count(), 1)
            revoke_device(actor=self.owner, device_id=identity)
            self.wait_until(lambda: self.native_phase("Status", identity=identity)["state"] == "identity_denied",
                            "Native service did not observe Manager revocation")
            self.assertEqual(device_dto(Device.objects.get(pk=identity))["status"], "revoked")
        finally:
            removed = self.native_phase("Uninstall", identity=identity)
            self.assertEqual(removed["service_status"], "absent")
