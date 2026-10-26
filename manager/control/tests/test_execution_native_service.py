"""Required disposable service gate; generated fixtures are not lab evidence."""
import json
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from django.test import SimpleTestCase, TransactionTestCase
from devices.tests import test_connection_agent as presence

ROOT = Path(__file__).resolve().parents[3]
CATEGORIES = (
    'containment', 'service_identity_acl', 'service_channel_grants',
    'immutable_default_ancestors', 'upgrade_rollback_journal', 'policy_denial',
    'published_presence_mtls_missing_vendor',
)


class NativeGateRefusalTests(SimpleTestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows script contract')
    def test_required_gate_fails_without_disposable_prerequisites_and_writes_zero_counts(self):
        """No host mutation: remove CI authorization before invoking the wrapper."""
        with tempfile.TemporaryDirectory(prefix='aegis-native-refusal-') as temporary:
            output = Path(temporary).resolve() / 'result'
            environment = {key: value for key, value in os.environ.items()
                           if key.upper() not in {'GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT'}}
            result = subprocess.run([
                'powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                str(ROOT / 'scripts/tests/agent/Test-WindowsExecution.ps1'),
                '-PackageRoot', str(ROOT), '-OutputRoot', str(output), '-RequireNative'],
                env=environment, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            report = output / 'execution-native-results.json'
            self.assertTrue(report.is_file(), 'Required gate omitted its failure artifact')
            data = json.loads(report.read_text(encoding='utf-8-sig'))
            self.assertEqual(data['result'], 'failed')
            self.assertEqual({row['name'] for row in data['categories']}, set(CATEGORIES))
            self.assertTrue(all(row['executed'] == row['passed'] == 0 for row in data['categories']))
            self.assertTrue(all(value == 'not_executed' for value in data['lab_gates'].values()))
            self.assertEqual(data['diagnostics']['stage'], 'prerequisites')
            self.assertEqual(data['diagnostics']['code'], 'required_native_prerequisites_missing')
            self.assertIsNone(data['diagnostics']['child_exit_code'])
            self.assertNotIn(str(output), json.dumps(data['diagnostics']))


class ExecutionPublishedNativeTests(TransactionTestCase):
    """Actual published CLI + generated Django issuer on a clean disposable host."""
    stop_server = presence.PublishedConnectionTests.stop_server
    cli = presence.PublishedConnectionTests.cli
    wait_until = presence.PublishedConnectionTests.wait_until
    native_phase = presence.PublishedConnectionTests.native_phase
    assert_network_snapshot = presence.PublishedConnectionTests.assert_network_snapshot

    def setUp(self):
        presence.PublishedConnectionTests.setUp(self)
        self.server.execution_reports = []

        class ObservingTlsAdapter(presence.QuietTlsAdapter):
            def do_POST(handler):
                if handler.path == '/agent/v2/execution/readiness':
                    length = int(handler.headers.get('Content-Length', '0'))
                    if not 0 < length <= 65536:
                        handler.send_error(400)
                        return
                    body = handler.rfile.read(length)
                    handler.rfile = io.BytesIO(body)
                    handler.server.execution_reports.append(json.loads(body))
                super().do_POST()

        self.server.RequestHandlerClass = ObservingTlsAdapter

    @classmethod
    def setUpClass(cls):
        if os.environ.get('AEGIS_EXECUTION_REQUIRE_NATIVE') != '1':
            raise unittest.SkipTest('Disposable execution service gate not requested')
        if (os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true'
                or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
                or not all(os.environ.get(name) for name in (
                    'AEGIS_CONNECTION_TEST_EXE', 'AEGIS_CONNECTION_SERVICE_PACKAGE',
                    'AEGIS_EXECUTION_NATIVE_TEST_EXE', 'AEGIS_EXECUTION_NATIVE_OUTPUT_ROOT'))):
            raise AssertionError('Required disposable native prerequisites missing')
        super().setUpClass()

    def test_real_published_service_mtls_upgrade_unknown_journal_and_no_execution_default(self):
        rows = {name: dict(executed=0, passed=0, failed=0, skipped=0)
                for name in ('published_presence_mtls_missing_vendor', 'upgrade_rollback_journal')}
        path = Path(os.environ['AEGIS_EXECUTION_NATIVE_OUTPUT_ROOT']) / 'published-results.json'

        def check(name, action):
            row = rows[name]
            row['executed'] += 1
            try:
                result = action()
            except BaseException:
                row['failed'] += 1
                raise
            row['passed'] += 1
            return result

        identity = None
        try:
            code = presence.create_pairing_code(actor=self.owner, environment_id='synthetic.execution.service')['code']

            def install():
                installed = self.native_phase('Install', code=code)
                self.assertEqual(installed['service_status'], 'Running')
                self.wait_until(lambda: presence.Device.objects.get(pk=installed['device_id']).last_heartbeat_at is not None,
                                'Published service did not reach real mTLS endpoint')
                self.assert_network_snapshot(presence.Device.objects.get(pk=installed['device_id']))
                self.assertFalse(any('/execution/' in route for route in self.server.routes))
                return installed['device_id']

            identity = check('published_presence_mtls_missing_vendor', install)

            def missing_vendor():
                self.native_phase('MissingVendor', identity=identity)
                self.assertTrue(self.server.execution_reports, 'Configured published service emitted no readiness exchange')
                self.assertTrue(all(row['ready'] is False for row in self.server.execution_reports))
                self.assertFalse(any(route.endswith('/poll') or route.endswith('/start') for route in self.server.routes))

            check('published_presence_mtls_missing_vendor', missing_vendor)
            check('upgrade_rollback_journal', lambda: self.native_phase('ExecutionUpgrade', identity=identity))
            self.assertEqual(presence.Device.objects.count(), 1)
            self.assertFalse(any(route.endswith('/poll') or route.endswith('/start') for route in self.server.routes))
            check('upgrade_rollback_journal', lambda: self.native_phase('Uninstall', identity=identity))
            # Cleanup is test-only and requires exact paired UUID plus absence of
            # service/binaries; production uninstall deliberately preserves these.
            self.native_phase('Cleanup', identity=identity)
            identity = None
        finally:
            if identity:
                try:
                    self.native_phase('Uninstall', identity=identity)
                    self.native_phase('Cleanup', identity=identity)
                except Exception:
                    rows['upgrade_rollback_journal']['executed'] += 1
                    rows['upgrade_rollback_journal']['failed'] += 1
            path.write_text(json.dumps(dict(schema_version=1, kind='execution_published_gate', categories=rows)), encoding='utf-8')
