"""Required disposable service gate; generated fixtures are not lab evidence."""
import json
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid
import xml.etree.ElementTree as ET
from django.test import SimpleTestCase, TransactionTestCase
from devices.tests import test_connection_agent as presence

ROOT = Path(__file__).resolve().parents[3]
CATEGORIES = (
    'containment', 'service_identity_acl', 'service_channel_grants',
    'immutable_default_ancestors', 'upgrade_rollback_journal', 'policy_denial',
    'published_presence_mtls_missing_vendor',
)


class NativeGateRefusalTests(SimpleTestCase):
    def fixture_helpers(self, command, *, environment=None, helpers=()):
        """Load selected inert helpers, never the disposable fixture entry."""
        environment = os.environ | (environment or {}) | {
            'AEGIS_TEST_FIXTURE_SCRIPT': str(ROOT / 'scripts/tests/agent/Test-ExecutionProvisioning.ps1'),
            'AEGIS_TEST_INSTALLER_SCRIPT': str(ROOT / 'deploy/agent/windows/Install-Agent.ps1'),
            'AEGIS_TEST_WRAPPER_SCRIPT': str(ROOT / 'scripts/tests/agent/Test-WindowsExecution.ps1'),
            'AEGIS_TEST_FIXTURE_HELPERS': ','.join(helpers),
        }
        loader = r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
foreach($source in @($env:AEGIS_TEST_INSTALLER_SCRIPT,$env:AEGIS_TEST_FIXTURE_SCRIPT,$env:AEGIS_TEST_WRAPPER_SCRIPT)){
    $ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'fixture_parse_failed'}
    foreach($name in @('ConvertTo-AgentNativeArgument')+$env:AEGIS_TEST_FIXTURE_HELPERS.Split(',')){
        $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false)
        if($definition){. ([scriptblock]::Create($definition.Extent.Text))}
    }
}
'''
        return subprocess.run([
            str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'),
            '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', loader + command,
        ], env=environment, capture_output=True, text=True, timeout=60)

    @unittest.skipUnless(os.name == 'nt', 'Windows manifest resource contract')
    def test_manifest_references_compiled_resources_for_its_own_provider_and_channel(self):
        """An apphost path without this manifest's WEVT_TEMPLATE cannot substitute."""
        import ctypes
        provider = uuid.uuid4()
        name = f'AEGIS-Test-{uuid.uuid4().hex}-Read'
        with tempfile.TemporaryDirectory(prefix='aegis-event-metadata-') as temporary:
            directory = Path(temporary).resolve() / 'metadata & resources'
            result = self.fixture_helpers(r'''
New-FixtureEventManifest $env:AEGIS_TEST_METADATA_ROOT $env:AEGIS_TEST_PROVIDER_NAME ([guid]$env:AEGIS_TEST_PROVIDER) | ConvertTo-Json -Compress
''', environment={
                'AEGIS_TEST_METADATA_ROOT': str(directory),
                'AEGIS_TEST_PROVIDER_NAME': name,
                'AEGIS_TEST_PROVIDER': str(provider),
            }, helpers=('Get-FixtureManifestTools', 'Invoke-FixtureCompiler', 'New-FixtureEventManifest'))
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout)
            manifest = Path(output['manifest'])
            resource_file = Path(output['resource'])
            self.assertEqual(manifest.parent, directory)
            self.assertEqual(resource_file.parent, directory)
            provider_xml = ET.parse(manifest).find('.//{*}provider')
            self.assertEqual(provider_xml.attrib['guid'], '{' + str(provider) + '}')
            self.assertEqual(provider_xml.attrib['resourceFileName'], str(resource_file))
            self.assertEqual(provider_xml.attrib['messageFileName'], str(resource_file))
            # LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE: no code runs.
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.LoadLibraryExW.argtypes = (ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32)
            kernel.LoadLibraryExW.restype = ctypes.c_void_p
            kernel.FindResourceW.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p)
            kernel.FindResourceW.restype = ctypes.c_void_p
            kernel.SizeofResource.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
            kernel.SizeofResource.restype = ctypes.c_uint32
            kernel.LoadResource.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
            kernel.LoadResource.restype = ctypes.c_void_p
            kernel.LockResource.argtypes = (ctypes.c_void_p,)
            kernel.LockResource.restype = ctypes.c_void_p
            kernel.FreeLibrary.argtypes = (ctypes.c_void_p,)
            module = kernel.LoadLibraryExW(str(resource_file), None, 0x22)
            self.assertTrue(module, 'Generated metadata DLL could not load as data')
            try:
                resource = kernel.FindResourceW(module, 1, 'WEVT_TEMPLATE')
                self.assertTrue(resource, 'Manifest references a PE without its metadata resource')
                payload = ctypes.string_at(kernel.LockResource(kernel.LoadResource(module, resource)),
                                           kernel.SizeofResource(module, resource))
                self.assertIn(provider.bytes_le, payload)
                self.assertIn((name + '/Operational').encode('utf-16-le'), payload)
            finally:
                kernel.FreeLibrary(module)

    @unittest.skipUnless(os.name == 'nt', 'Windows manifest fixture contract')
    def test_manifest_build_fails_closed_when_installed_toolchain_is_missing(self):
        with tempfile.TemporaryDirectory(prefix='aegis-event-no-tools-') as temporary:
            directory = Path(temporary).resolve() / 'metadata'
            result = self.fixture_helpers(r'''
function Get-FixtureManifestTools { throw 'fixture_metadata_tools_missing' }
try { New-FixtureEventManifest $env:AEGIS_TEST_METADATA_ROOT ('AEGIS-Test-'+[guid]::NewGuid().ToString('N')+'-Read') ([guid]::NewGuid()); throw 'unexpected_success' }
catch { if($_.Exception.Message -cne 'fixture_metadata_tools_missing'){throw}; @{code=$_.Exception.Message}|ConvertTo-Json -Compress }
''', environment={'AEGIS_TEST_METADATA_ROOT': str(directory)}, helpers=('New-FixtureEventManifest',))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {'code': 'fixture_metadata_tools_missing'})
            self.assertFalse(directory.exists())

    @unittest.skipUnless(os.name == 'nt', 'Windows metadata ACL contract')
    def test_metadata_acl_preserves_existing_rules_and_cannot_inherit_into_private_siblings(self):
        result = self.fixture_helpers(r'''
$sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')
$original=[Security.AccessControl.DirectorySecurity]::new()
$original.SetSecurityDescriptorSddlForm('O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;S-1-5-80-9-8-7-6-5)')
$before=$original.GetSecurityDescriptorSddlForm('All')
$rows=@()
foreach($traverseOnly in @($true,$false)){
    $updated=Get-FixtureMetadataReadAcl $original $sid $traverseOnly
    $rules=@($updated.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    $grant=@($rules|Where-Object{$_.IdentityReference -eq $sid})
    if($grant.Count -ne 1 -or @($rules|Where-Object{$_.IdentityReference -ne $sid}).Count -ne 3){throw 'unexpected_acl_change'}
    $rows+=@{rights=[int]$grant[0].FileSystemRights;inheritance=[int]$grant[0].InheritanceFlags;propagation=[int]$grant[0].PropagationFlags;allow=$grant[0].AccessControlType -eq 'Allow';owner=$updated.GetOwner([Security.Principal.SecurityIdentifier]).Value;protected=$updated.AreAccessRulesProtected}
    $updated.RemoveAccessRuleSpecific($grant[0])
    if($updated.GetSecurityDescriptorSddlForm('All') -cne $before){throw 'existing_acl_changed'}
}
@{original_unchanged=$original.GetSecurityDescriptorSddlForm('All') -ceq $before;rows=$rows}|ConvertTo-Json -Depth 4 -Compress
''', helpers=('Get-FixtureMetadataReadAcl',))
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data['original_unchanged'])
        self.assertEqual(data['rows'], [
            dict(rights=0x100020, inheritance=0, propagation=0, allow=True,
                 owner='S-1-5-32-544', protected=True),
            dict(rights=0x1200A9, inheritance=3, propagation=0, allow=True,
                 owner='S-1-5-32-544', protected=True),
        ])

    @unittest.skipUnless(os.name == 'nt', 'Windows fixture diagnostics contract')
    def test_channel_setup_diagnostics_accept_only_fixed_codes(self):
        result = self.fixture_helpers(r'''
$rows=@()
foreach($message in @('fixture_metadata_tools_missing','fixture_metadata_compile_failed','fixture_provider_metadata_invalid','fixture_channel_configuration_invalid','fixture_event_write_failed','fixture_event_not_observed','synthetic-private/key.pem token=value','FIXTURE_EVENT_NOT_OBSERVED')){
    try { throw $message } catch { $rows+=@(Get-FixtureSetupFailure $_) }
}
ConvertTo-Json -InputObject $rows -Compress
''', helpers=('Get-FixtureSetupFailure',))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [
            'fixture_metadata_tools_missing', 'fixture_metadata_compile_failed',
            'fixture_provider_metadata_invalid', 'fixture_channel_configuration_invalid',
            'fixture_event_write_failed', 'fixture_event_not_observed', None, None,
        ])

    @unittest.skipUnless(os.name == 'nt', 'Windows gate diagnostic boundary')
    def test_outer_gate_accepts_known_setup_failures_and_rejects_unbounded_or_private_codes(self):
        result = self.fixture_helpers(r'''
$known=@('native_fixture_setup_failed','fixture_metadata_tools_missing','fixture_metadata_input_invalid','fixture_metadata_compile_timeout','fixture_metadata_compile_failed','fixture_metadata_acl_failed','fixture_channel_registration_failed','fixture_provider_metadata_invalid','fixture_channel_configuration_invalid','fixture_event_write_failed','fixture_event_not_observed')
Assert-GateFixtureFailureCodes $known
$rejected=0
foreach($case in @(@('synthetic-private/key.pem token=value'),@(1),(@('native_fixture_setup_failed')*65))){
    try { Assert-GateFixtureFailureCodes $case; throw 'unexpected_acceptance' }
    catch { if($_.Exception.Message -cne 'fixture_result_invalid'){throw};$rejected++ }
}
@{accepted=$known.Count;rejected=$rejected}|ConvertTo-Json -Compress
''', helpers=('Assert-GateFixtureFailureCodes',))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'accepted': 11, 'rejected': 3})

    @unittest.skipUnless(os.name == 'nt', 'Windows PowerShell stream contract')
    def test_ps51_origin_fixture_retains_internet_zone_and_inert_file(self):
        """Extract only the stream helper; never execute the elevated fixture."""
        with tempfile.TemporaryDirectory(prefix='aegis-origin-fixture-') as temporary:
            path = Path(temporary).resolve() / 'origin.ps1'
            body = b'# inert policy-origin fixture'
            path.write_bytes(body)
            environment = os.environ | {
                'AEGIS_TEST_ORIGIN_FILE': str(path),
                'AEGIS_TEST_ORIGIN_SCRIPT': str(ROOT / 'scripts/tests/agent/Test-ExecutionProvisioning.ps1'),
            }
            command = r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:AEGIS_TEST_ORIGIN_SCRIPT,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'fixture_parse_failed'}
$definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Set-FixtureInternetOrigin'},$false)
if(!$definition){throw 'fixture_origin_helper_missing'}
. ([scriptblock]::Create($definition.Extent.Text))
Set-FixtureInternetOrigin $env:AEGIS_TEST_ORIGIN_FILE
$zone=[string](Get-Content -LiteralPath $env:AEGIS_TEST_ORIGIN_FILE -Stream Zone.Identifier -Raw)
@{major=$PSVersionTable.PSVersion.Major;zone=$zone}|ConvertTo-Json -Compress
'''
            result = subprocess.run([
                str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'),
                '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command,
            ], env=environment, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data['major'], 5)
            self.assertEqual(data['zone'], '[ZoneTransfer]\r\nZoneId=3\r\n')
            self.assertEqual(path.read_bytes(), body)

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
