"""Disposable systemd proof; ordinary test runs visibly skip the native gate."""
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone as utc
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone

from aegis_verify.connectors.wazuh.live import Config, probe
from accounts.models import AccountMutationLock
from control import execution_services as services
from control.execution_connections import register_execution_connection
from control.execution_contracts import BindingInput, PollRequest, PROTOCOL, PROVIDER_ID, canonical_bytes
from control.execution_models import CollectionWorkerLease, DeviceExecutionBinding
from control.execution_ownership import transfer_execution_ownership
from control.models import AuditEntry, Device, DispatchLock, Job, RunnerRelease
from control.tests.test_execution_collection import ExecutionCollectionFixture
from control.worker_health import current_scope_sha256


REPO = Path(__file__).resolve().parents[3]
WRAPPER = REPO / 'scripts/tests/manager/test-registered-worker-systemd.sh'


def native_prerequisite_errors(environ, *, platform, vendor, database, executable, init):
    """No OS mutation is reachable before the disposable/test-database fence."""
    errors = []
    required = {'CI': 'true', 'GITHUB_ACTIONS': 'true', 'AEGIS_MANAGER_CI': '1',
                'AEGIS_MANAGER_REQUIRE_WORKER_SYSTEMD': '1',
                'AEGIS_MANAGER_DISPOSABLE_SYSTEMD_CI': '1'}
    if any(environ.get(key) != value for key, value in required.items()):
        errors.append('disposable_systemd_ci_required')
    if platform != 'linux' or init != 'systemd': errors.append('systemd_required')
    if (vendor != 'postgresql' or not re.fullmatch(r'test_aegis_ci[a-z0-9_]*', database)
            or not re.fullmatch(r'aegis_ci[a-z0-9_]*', environ.get('AEGIS_MANAGER_DB_NAME', ''))):
        errors.append('isolated_postgresql_test_database_required')
    if not executable.startswith(('/opt/', '/usr/')):
        errors.append('systemd_accessible_python_required')
    return errors


def fixture_unit(template, root, executable, uid, gid):
    """Change deployment locations/identity only; keep every hardening directive."""
    root = Path(root)
    if root.parent != Path('/var/lib') or not re.fullmatch(r'aegis-worker-ci-[0-9a-f]{32}', root.name):
        raise ValueError('invalid_fixture_root')
    if not re.fullmatch(r'/(?:opt|usr)/[A-Za-z0-9_./-]+', executable):
        raise ValueError('invalid_fixture_python')
    if type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0:
        raise ValueError('unprivileged_fixture_identity_required')
    replacements = {
        'User=aegis-manager': f'User={uid}',
        'Group=aegis-manager': f'Group={gid}',
        'WorkingDirectory=/opt/aegis/current/manager': f'WorkingDirectory={root}/source/manager',
        'EnvironmentFile=/etc/aegis-manager/manager.env': f'EnvironmentFile={root}/private/worker.env',
        'ExecStart=/opt/aegis/venv/bin/python manage.py manager_worker $AEGIS_MANAGER_WORKER_ARGS':
            f'ExecStart={executable} manage.py manager_worker $AEGIS_MANAGER_WORKER_ARGS',
        'ReadWritePaths=/var/lib/aegis-manager': f'ReadWritePaths={root}/private',
    }
    lines = template.splitlines()
    for old, new in replacements.items():
        if lines.count(old) != 1: raise ValueError('worker_unit_contract_changed')
        lines[lines.index(old)] = new
    return '\n'.join(lines) + '\n'


def environment_file(values):
    """Systemd EnvironmentFile quoting, without shell evaluation or interpolation."""
    lines = []
    for name, value in sorted(values.items()):
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*', name) or any(c in value for c in '\r\n\x00'):
            raise ValueError('invalid_fixture_environment')
        escaped = value.replace('\\', '\\\\').replace('"', '\\"').replace('`', '\\`').replace('$', '\\$')
        lines.append(f'{name}="{escaped}"')
    return '\n'.join(lines) + '\n'


class TestIndexer:
    """Local TEST HTTPS source: authenticated, verified TLS, zero fabricated events."""
    def __init__(self, root):
        self.username, self.password = 'fixture-reader', secrets.token_urlsafe(32)
        self.authorization = 'Basic ' + base64.b64encode(f'{self.username}:{self.password}'.encode()).decode()
        self.health_block = threading.Event()
        self.health_entered = threading.Event()
        self.health_release = threading.Event()
        self.collection_entered = threading.Event()
        self.collection_release = threading.Event()
        self.probes = self.collections = self.invalid = 0
        self.mutex = threading.Lock()
        self.ca = Path(root) / 'test-ca.pem'
        key_path, cert_path = Path(root) / 'test-server-key.pem', Path(root) / 'test-server.pem'
        now = datetime.now(utc.utc)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'AEGIS disposable TEST CA')])
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
              .not_valid_after(now+timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
              .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                  key_encipherment=False, data_encipherment=False, key_agreement=False,
                  key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), True)
              .sign(ca_key, hashes.SHA256()))
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        cert = (x509.CertificateBuilder().subject_name(server_name).issuer_name(name).public_key(server_key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
                .not_valid_after(now+timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True).sign(ca_key, hashes.SHA256()))
        self.ca.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_path.chmod(0o600)
        source = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass

            def do_POST(self):
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 65536: raise ValueError
                    body = json.loads(self.rfile.read(length))
                    if self.headers.get('Authorization') != source.authorization:
                        self.send_error(401); return
                    health = self.path == '/wazuh-alerts-test/_search' and body.get('size') == 0
                    collection = self.path == '/wazuh-alerts-test/_search?scroll=1m' and body.get('size', 0) > 0
                    filters = body['query']['bool']['filter']
                    if not (health or collection) or filters[0] != {'term': {'agent.id': '901'}}: raise ValueError
                    if set(filters[1]['range']['timestamp']) != {'gte', 'lt'}: raise ValueError
                    with source.mutex:
                        if health: source.probes += 1
                        else: source.collections += 1
                    if health and source.health_block.is_set():
                        source.health_entered.set(); source.health_release.wait(30)
                    if collection:
                        source.collection_entered.set(); source.collection_release.wait(60)
                    raw = canonical_bytes(dict(timed_out=False, _shards=dict(failed=0, successful=1, total=1),
                                               hits=dict(total=dict(value=0, relation='eq'), hits=[])))
                    self.send_response(200); self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
                except (ValueError, KeyError, TypeError):
                    with source.mutex: source.invalid += 1
                    self.send_error(400)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass  # Expected when the deliberately interrupted worker loses its socket.

        self.server = ThreadingHTTPServer(('localhost', 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.endpoint = f'https://localhost:{self.server.server_port}'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.health_release.set(); self.collection_release.set()
        self.server.shutdown(); self.server.server_close(); self.thread.join(5)

    def config(self):
        return Config(endpoint=self.endpoint, username=self.username, password=self.password,
                      ca_file=str(self.ca), index='wazuh-alerts-test', agent_id='901', environment_id='synthetic-env',
                      start='2026-01-01T00:00:00Z', end='2026-01-01T00:00:01Z')


class WorkerServiceHarnessTests(SimpleTestCase):
    def bash(self, *args):
        executable = shutil.which('bash')
        if __import__('os').name == 'nt':
            executable = 'C:/Program Files/Git/bin/bash.exe'
        if not executable or not Path(executable).is_file():
            self.skipTest('Bash is required for wrapper interface tests')
        return subprocess.run([executable, WRAPPER.as_posix(), *args], capture_output=True,
                              text=True, timeout=15)

    def test_wrapper_help_is_available_without_native_prerequisites(self):
        result = self.bash('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--require-native', result.stdout)

    def test_wrapper_rejects_unknown_arguments_without_running_tests(self):
        result = self.bash('--unknown')
        self.assertEqual(result.returncode, 2)
        self.assertIn('invalid_worker_gate_arguments', result.stderr)

    def test_native_fence_rejects_workstation_and_non_test_database_before_mutation(self):
        arguments = dict(platform='linux', vendor='postgresql', database='test_aegis_ci',
                         executable='/opt/python/bin/python', init='systemd')
        environ = dict(CI='true', GITHUB_ACTIONS='true', AEGIS_MANAGER_CI='1',
            AEGIS_MANAGER_REQUIRE_WORKER_SYSTEMD='1', AEGIS_MANAGER_DISPOSABLE_SYSTEMD_CI='1',
            AEGIS_MANAGER_DB_NAME='aegis_ci')
        self.assertEqual(native_prerequisite_errors(environ, **arguments), [])
        for variable in environ:
            changed = {k: v for k, v in environ.items() if k != variable}
            self.assertTrue(native_prerequisite_errors(changed, **arguments), variable)
        for changed in (dict(platform='win32'), dict(init='other'), dict(vendor='sqlite'),
                        dict(database='aegis_ci'), dict(database='test_real_lab'),
                        dict(executable='/home/runner/venv/bin/python')):
            self.assertTrue(native_prerequisite_errors(environ, **(arguments | changed)))

    def test_fixture_transformation_preserves_hardening_and_rejects_unknown_layout(self):
        template = (REPO / 'deploy/manager/aegis-manager-worker.service').read_text()
        root = Path('/var/lib/aegis-worker-ci-' + 'a'*32)
        rendered = fixture_unit(template, root, '/opt/python/bin/python', 1001, 1001)
        # Independently compare all deployment security settings; no override is appended.
        for prefix in ('PrivateTmp=', 'ProtectHome=', 'ProtectSystem=', 'NoNewPrivileges=', 'UMask=', 'Restart='):
            original = [line for line in template.splitlines() if line.startswith(prefix)]
            self.assertEqual([line for line in rendered.splitlines() if line.startswith(prefix)], original)
        self.assertIn(f'WorkingDirectory={root}/source/manager', rendered)
        self.assertIn(f'ReadWritePaths={root}/private', rendered)
        for invalid_root in (Path('/tmp/aegis-worker-ci-'+'a'*32), Path('/var/lib/aegis-manager')):
            with self.assertRaises(ValueError): fixture_unit(template, invalid_root, '/opt/python/bin/python', 1001, 1001)
        with self.assertRaises(ValueError):
            fixture_unit(template + '\nUser=aegis-manager\n',
                         root, '/opt/python/bin/python', 1001, 1001)

    def test_private_env_rejects_line_injection(self):
        self.assertEqual(environment_file({'VALUE': 'test "quoted" \\ value'}),
                         'VALUE="test \\"quoted\\" \\\\ value"\n')
        for values in ({'VALUE': 'x\nOTHER=y'}, {'VALUE': 'x\r'}, {'bad-name': 'x'}, {'VALUE': 'x\x00'}):
            with self.assertRaises(ValueError): environment_file(values)

    def test_local_test_source_requires_authentication_and_verified_tls_for_zero_hit_health(self):
        with tempfile.TemporaryDirectory(prefix='aegis-test-https-') as directory:
            source = TestIndexer(directory)
            try:
                self.assertTrue(probe(source.config()).healthy)
                self.assertFalse(probe(replace(source.config(), ca_file=None)).healthy)
                self.assertFalse(probe(replace(source.config(), password=secrets.token_urlsafe(24))).healthy)
                self.assertEqual((source.probes, source.collections, source.invalid), (1, 0, 0))
            finally: source.close()

    def test_staged_worker_imports_use_staged_source_instead_of_editable_checkout(self):
        with tempfile.TemporaryDirectory(prefix='aegis-worker-source-only-') as directory:
            root = Path(directory)
            RegisteredWorkerSystemdTests.stage_source(SimpleNamespace(root=root))
            script = '''
import os
from pathlib import Path
import django
django.setup()
import control.worker_health
import control.management.commands.manager_worker
import aegis_verify.connectors.wazuh.live
root = Path(os.environ['AEGIS_TEST_STAGE_ROOT']).resolve()
for module in (control.worker_health, control.management.commands.manager_worker, aegis_verify.connectors.wazuh.live):
    assert Path(module.__file__).resolve().is_relative_to(root), 'worker_import_escaped_stage'
'''
            environ = os.environ | dict(PYTHONPATH=os.pathsep.join((str(root/'python'), str(root/'source/manager'))),
                AEGIS_TEST_STAGE_ROOT=str(root), DJANGO_SETTINGS_MODULE='aegis_manager.test_settings',
                PYTHONDONTWRITEBYTECODE='1')
            result = subprocess.run([sys.executable, '-c', script], env=environ,
                cwd=root/'source/manager', capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)


class RegisteredWorkerSystemdTests(ExecutionCollectionFixture, TransactionTestCase):
    """Actual unit/service/PG checks, never substituted by local or static tests."""
    @classmethod
    def setUpClass(cls):
        if os.environ.get('AEGIS_MANAGER_REQUIRE_WORKER_SYSTEMD') != '1':
            raise unittest.SkipTest('Native worker gate requires opted-in disposable systemd CI; no native proof executed')
        super().setUpClass()
        init = Path('/proc/1/comm').read_text().strip() if sys.platform == 'linux' else ''
        errors = native_prerequisite_errors(os.environ, platform=sys.platform, vendor=connection.vendor,
            database=connection.settings_dict['NAME'], executable=str(Path(sys.executable).resolve()), init=init)
        if errors: raise AssertionError(','.join(errors))
        if not shutil.which('systemctl') or not shutil.which('sudo'):
            raise AssertionError('systemctl_and_sudo_required')
        # CI authentication and actual systemd availability must work before mkdir/enable.
        result = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=10)
        if result.returncode: raise AssertionError('noninteractive_sudo_required')
        result = subprocess.run(['systemctl', 'show', '--property=Version', '--value'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode or not result.stdout.strip(): raise AssertionError('active_systemd_required')

    def setUp(self):
        # Deliberately do not call ExecutionCollectionFixture.setUp: its placeholder
        # CA/config and external ACL mocks are unsuitable for a native service gate.
        self.root = Path('/var/lib') / ('aegis-worker-ci-' + uuid.uuid4().hex)
        self.unit_name = self.root.name + '.service'
        self.root_created = False
        self.unit_enabled = False
        self.addCleanup(self.cleanup_native)
        self.command(['sudo', '-n', 'mkdir', '-m', '0700', '--', str(self.root)])
        self.root_created = True
        self.command(['sudo', '-n', 'chown', f'{os.getuid()}:{os.getgid()}', '--', str(self.root)])
        self.private = self.root / 'private'; self.private.mkdir(mode=0o700)
        self.output = self.private / 'evidence'; self.output.mkdir(mode=0o700)
        self.stage_source()
        self.source = TestIndexer(self.private)
        self.addCleanup(self.source.close)
        self.now = timezone.now().replace(microsecond=0) - timedelta(minutes=10)
        self.owner = get_user_model().objects.create_superuser('native-worker-owner', password=secrets.token_urlsafe(32))
        AccountMutationLock.objects.get_or_create(pk=1); DispatchLock.objects.get_or_create(pk=1)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.key_path = self.private / 'execution.pem'
        self.key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.key_path.chmod(0o600)
        self.settings = override_settings(MANAGER_EXECUTION_SIGNING_KEY=str(self.key_path))
        self.settings.enable(); self.addCleanup(self.settings.disable)
        self.config_path = self.private / 'reader.json'
        self.config_path.write_bytes(canonical_bytes(dict(endpoint=self.source.endpoint,
            username=self.source.username, password=self.source.password, ca_file=str(self.source.ca),
            index='wazuh-alerts-test', collection_mode='unknown')))
        self.config_path.chmod(0o600)
        self.registered = register_execution_connection(self.owner, expected_revision=None,
            config_path=self.config_path, output_root=self.output)
        self.scenario_path, self.profile_path = self.private / 'scenario.yaml', self.private / 'profile.json'
        self.scenario_path.write_bytes((REPO / 'scenarios/SCN-001-powershell-execution.yaml').read_bytes())
        self.profile_path.write_bytes((REPO / 'tests/fixtures/wazuh/windows-telemetry/profile.json').read_bytes())
        self.release = RunnerRelease.objects.create(scenario_path=str(self.scenario_path), profile_path=str(self.profile_path),
            scenario_sha256=sha256(self.scenario_path.read_bytes()).hexdigest(),
            profile_sha256=sha256(self.profile_path.read_bytes()).hexdigest(), runner_sha256='b'*64,
            kit_sha256='c'*64, payload_sha256='d'*64, rule_hashes={'baseline':'e'*64, 'behavioral':'f'*64},
            timeout_seconds=180, evaluation_bindings=[{'name':'target', 'value':'synthetic-endpoint'}])
        self.device = Device.objects.create(connection_kind='paired_presence', environment_id='synthetic-env',
            certificate_sha256='a'*64, certificate_not_before=self.now-timedelta(days=1),
            certificate_expires_at=self.now+timedelta(days=1), os='windows', architecture='x64')
        transfer_execution_ownership(self.owner, dict(connection_id=str(self.registered.connection_id),
            environment_id='synthetic-env', wazuh_agent_id='901'), None, str(self.device.pk),
            dict(paired_device_id=str(self.device.pk), legacy_device_id=None), 'Reviewed disposable TEST fixture',
            evidence_refs=['fixture:worker-ci-review'])
        services.set_execution_binding(self.owner, str(self.device.pk), BindingInput(None, True, PROVIDER_ID,
            self.release.pk, 'b'*64, str(self.registered.connection_id), 1, '901'))
        self.binding = DeviceExecutionBinding.objects.get(device=self.device, is_current=True)
        self.identity = services.ExecutionIdentity(str(self.device.pk), 1, self.device.certificate_sha256)
        self.poll = PollRequest(protocol=PROTOCOL, device_id=str(self.device.pk), generation=1,
            binding_id=str(self.binding.binding_id), binding_revision=1)
        self.service_environment = {key: str(connection.settings_dict[field]) for key, field in (
            ('AEGIS_MANAGER_DB_NAME','NAME'), ('AEGIS_MANAGER_DB_USER','USER'), ('AEGIS_MANAGER_DB_PASSWORD','PASSWORD'),
            ('AEGIS_MANAGER_DB_HOST','HOST'), ('AEGIS_MANAGER_DB_PORT','PORT'))}
        self.service_environment.update(AEGIS_MANAGER_CI='1', DJANGO_SETTINGS_MODULE='aegis_manager.ci_settings',
            AEGIS_MANAGER_EXECUTION_SIGNING_KEY=str(self.key_path), PYTHONPATH=str(self.root / 'python'),
            PYTHONDONTWRITEBYTECODE='1', AEGIS_MANAGER_WORKER_ARGS=' '.join(self.worker_arguments()))
        env_path = self.private / 'worker.env'
        env_path.write_text(environment_file(self.service_environment), encoding='utf-8'); env_path.chmod(0o600)
        unit_path = self.root / self.unit_name
        unit_path.write_text(fixture_unit((REPO / 'deploy/manager/aegis-manager-worker.service').read_text(),
            self.root, str(Path(sys.executable).resolve()), os.getuid(), os.getgid()), encoding='utf-8')
        self.unit_enabled = True
        self.command(['sudo', '-n', 'systemctl', 'enable', str(unit_path)])
        self.assertEqual(self.systemctl('is-enabled').stdout.strip(), 'enabled')

    def stage_source(self):
        # A source-only copy prevents ProtectHome/PrivateTmp bypasses through an
        # editable install rooted in the checkout or the runner's home directory.
        def source_only(directory, names):
            return [name for name in names if name == '__pycache__'
                    or not (Path(directory)/name).is_dir() and not name.endswith('.py')]
        shutil.copytree(REPO/'manager', self.root/'source/manager', ignore=source_only)
        shutil.copytree(REPO/'backend/app', self.root/'python/aegis_verify', ignore=source_only)
        shutil.copytree(REPO/'connectors', self.root/'python/aegis_verify/connectors', ignore=source_only)

    def command(self, args, *, check=True, env=None, cwd=None):
        result = subprocess.run(args, capture_output=True, text=True, timeout=45, env=env, cwd=cwd)
        if check and result.returncode: self.fail('native_fixture_command_failed')
        return result

    def systemctl(self, action, *args, check=True):
        return self.command(['sudo', '-n', 'systemctl', action, *args, self.unit_name], check=check)

    def worker_arguments(self):
        return ['--execution-connection', str(self.registered.connection_id), '--execution-revision',
                str(self.registered.revision), '--output-root', str(self.output)]

    def run_worker(self, *extra):
        return self.command([str(Path(sys.executable).resolve()), 'manage.py', 'manager_worker',
            *self.worker_arguments(), *extra], check=False, env=self.service_environment,
            cwd=self.root/'source/manager')

    def wait_for(self, condition, *, timeout=40):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            value = condition()
            if value: return value
            time.sleep(.1)
        self.fail('native_worker_condition_timed_out')

    def fresh_health(self, *, after=None, excluding=()):
        def read():
            rows = CollectionWorkerLease.objects.filter(connection_id=self.registered.connection_id,
                connection_revision=1, config_sha256=self.registered.config_sha256,
                output_root_fingerprint=self.registered.output_root_fingerprint,
                health_code='healthy', source_probe_status='healthy',
                last_seen_at__gte=timezone.now()-timedelta(seconds=30),
                source_probe_succeeded_at__gte=after or timezone.now()-timedelta(seconds=30)).exclude(instance_id__in=excluding)
            row = rows.order_by('-started_at').first()
            if row and row.source_probe_scope_sha256 == current_scope_sha256(self.registered): return row
        return self.wait_for(read)

    def cleanup_native(self):
        # Every deletion and service action is constrained to this generated root.
        if (self.root.parent != Path('/var/lib') or self.root.is_symlink() or self.root.resolve() != self.root
                or not re.fullmatch(r'aegis-worker-ci-[0-9a-f]{32}', self.root.name)
                or self.unit_name != self.root.name+'.service'):
            raise AssertionError('unsafe_native_fixture_cleanup')
        if self.unit_enabled:
            self.systemctl('disable', '--now')
            self.command(['sudo', '-n', 'systemctl', 'daemon-reload'])
        if self.root_created and self.root.exists():
            if self.root.stat().st_uid != os.getuid(): raise AssertionError('fixture_root_owner_changed')
            shutil.rmtree(self.root)

    def test_actual_enabled_unit_lifecycle_fresh_health_independent_loop_and_os_lock(self):
        started = timezone.now()
        self.systemctl('start')
        first = self.fresh_health(after=started)
        self.assertEqual(self.systemctl('is-active').stdout.strip(), 'active')
        for property_name, value in (('PrivateTmp','yes'), ('ProtectHome','yes'),
                                     ('ProtectSystem','strict'), ('NoNewPrivileges','yes')):
            self.assertEqual(self.systemctl('show', '--property='+property_name, '--value').stdout.strip(), value)
        contender = self.run_worker('--once')
        self.assertNotEqual(contender.returncode, 0)
        self.assertIn('worker_already_running', contender.stderr)
        self.assertEqual(CollectionWorkerLease.objects.count(), 1)
        denied_recovery = self.run_worker('--recover-interrupted')
        self.assertNotEqual(denied_recovery.returncode, 0)
        self.assertIn('worker_already_running', denied_recovery.stderr)
        self.source.health_block.set()
        self.assertTrue(self.source.health_entered.wait(25), 'actual_health_source_request_required')
        first.refresh_from_db(); before_seen, before_probe = first.last_seen_at, first.source_probe_succeeded_at
        self.wait_for(lambda: CollectionWorkerLease.objects.filter(pk=first.pk, last_seen_at__gt=before_seen).exists(), timeout=7)
        first.refresh_from_db(); self.assertEqual(first.source_probe_succeeded_at, before_probe)
        self.source.health_release.set()
        self.fresh_health(after=before_probe+timedelta(microseconds=1))
        self.systemctl('stop'); first.refresh_from_db(); self.assertEqual(first.health_code, 'stopped')
        self.assertNotEqual(self.systemctl('is-active', check=False).returncode, 0)
        stopped = timezone.now(); self.systemctl('start')
        second = self.fresh_health(after=stopped, excluding=(first.pk,))
        restarted = timezone.now(); self.systemctl('restart')
        third = self.fresh_health(after=restarted, excluding=(first.pk, second.pk))
        second.refresh_from_db(); self.assertEqual(second.health_code, 'stopped')
        self.assertNotEqual(third.pk, second.pk)
        self.assertEqual((self.source.collections, self.source.invalid), (0, 0))
        self.assertGreaterEqual(self.source.probes, 3)
        self.assertEqual([path.name for path in self.output.iterdir()], ['.worker.lock'])

    def test_killed_real_collection_is_not_reclaimed_and_requires_explicit_failure_and_owner_review(self):
        self.systemctl('start'); first = self.fresh_health()
        # Only the fixture Windows readiness input is injected by the existing
        # factory. Signed approval/start/receipt/pins and actual worker health run.
        job = self.succeeded()
        self.assertTrue(self.source.collection_entered.wait(20), 'actual_collection_source_request_required')
        self.wait_for(lambda: Job.objects.filter(pk=job.pk, collection_state='collecting').exists())
        job.refresh_from_db(); original_envelope, original_receipt = bytes(job.envelope_bytes), bytes(job.terminal_receipt_bytes)
        self.assertEqual(AuditEntry.objects.filter(job=job, action='collection_started').count(), 1)
        self.assertIsNone(job.report)
        with self.assertRaises(ValueError):
            services.reconcile_execution(self.owner, str(job.pk), reason='TEST interrupted claim', evidence_refs=['fixture:claim'])
        killed = timezone.now(); self.systemctl('kill', '--signal=SIGKILL', '--kill-whom=all')
        second = self.fresh_health(after=killed, excluding=(first.pk,))
        # Observe at least one further worker loop and independent health refresh.
        self.wait_for(lambda: CollectionWorkerLease.objects.filter(pk=second.pk,
            last_seen_at__gt=second.last_seen_at+timedelta(seconds=5)).exists(), timeout=15)
        job.refresh_from_db()
        self.assertEqual((job.collection_state, job.error_code, job.report), ('collecting', '', None))
        self.assertEqual(self.source.collections, 1)
        self.assertEqual(AuditEntry.objects.filter(job=job, action='collection_started').count(), 1)
        self.systemctl('stop')
        recovery = self.run_worker('--recover-interrupted')
        self.assertEqual(recovery.returncode, 0)
        self.assertIn('interrupted_collections_marked_failed=1', recovery.stdout)
        job.refresh_from_db()
        self.assertEqual((job.collection_state, job.error_code, job.report), ('failed', 'worker_interrupted', None))
        self.assertEqual((bytes(job.envelope_bytes), bytes(job.terminal_receipt_bytes)), (original_envelope, original_receipt))
        self.assertEqual(AuditEntry.objects.filter(job=job, action='collection_interrupted').count(), 1)
        recovery_retry = self.run_worker('--recover-interrupted')
        self.assertEqual(recovery_retry.returncode, 0)
        self.assertIn('interrupted_collections_marked_failed=0', recovery_retry.stdout)
        self.systemctl('start'); third = self.fresh_health(excluding=(first.pk, second.pk))
        self.wait_for(lambda: CollectionWorkerLease.objects.filter(pk=third.pk,
            last_seen_at__gt=third.last_seen_at+timedelta(seconds=5)).exists(), timeout=15)
        self.assertEqual(self.source.collections, 1)
        self.systemctl('stop')
        services.reconcile_execution(self.owner, str(job.pk), reason='Reviewed disposable TEST interruption',
            evidence_refs=['fixture:worker-ci-interrupted-claim'])
        job.refresh_from_db(); self.assertEqual(job.collection_state, 'reconciled')
        self.assertEqual(AuditEntry.objects.filter(job=job, action='owner_reconciled').count(), 1)
        self.assertIsNone(job.report)
        self.assertEqual((self.source.collections, self.source.invalid), (1, 0))
