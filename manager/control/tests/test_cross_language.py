"""Python Manager -> real .NET validator, using generated synthetic local files.

No telemetry, rule, endpoint certificate or executable payload is installed or run.
"""
import base64
from datetime import timedelta
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from control.jobs import approve_job
from control.models import Device, RunnerRelease, Job
from control.signing import sign_payload


ROOT = Path(__file__).resolve().parents[3]
AGENT = Path(os.environ.get('AEGIS_AGENT_TEST_EXE',
    str(ROOT / 'agent/windows/Aegis.Agent/bin/Debug/net10.0/Aegis.Agent.exe')))


@unittest.skipUnless(os.name == 'nt', 'Windows catalog and .NET foreground validator')
class CrossLanguageTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def setUp(self):
        self.assertTrue(AGENT.is_file(), 'Build agent/windows/Aegis.Agent before Windows Manager tests')
        self.space = tempfile.TemporaryDirectory(prefix='am-')
        self.addCleanup(self.space.cleanup)
        self.root = Path(self.space.name).resolve()
        private_key = self.root / 'signing.pem'
        private_key.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        public_key = self.root / 'public.pem'
        public_key.write_bytes(self.key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        self.settings_override = override_settings(MANAGER_SIGNING_KEY=str(private_key))
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)
        source = importlib.util.spec_from_file_location('synthetic_kit_builder', ROOT / 'scripts/prepare_scn001_kit.py')
        builder = importlib.util.module_from_spec(source)
        source.loader.exec_module(builder)
        kit = self.root / 'kit'
        manifest = builder.prepare_kit(output_dir=kit, lab_directory=str(kit),
            target_host=os.environ['COMPUTERNAME'], rule_id=119901, parent_sid=91816, occupied_ids=frozenset())
        scenario = self.root / 'scenario.yaml'
        scenario.write_bytes((ROOT / 'scenarios/SCN-001-powershell-execution.yaml').read_bytes())
        profile = self.root / 'profile.json'
        profile.write_bytes((ROOT / 'tests/fixtures/wazuh/windows-telemetry/profile.json').read_bytes())
        runner = self.root / 'runner.ps1'
        runner.write_bytes((ROOT / 'demos/scn-001/Invoke-SafeDemo.ps1').read_bytes())
        hashes = {name + '_sha256': sha256(path.read_bytes()).hexdigest() for name, path in (
            ('scenario', scenario), ('profile', profile), ('runner', runner), ('kit', kit / 'kit.json'))}
        hashes['payload_sha256'] = manifest['payload_sha256']
        rules = {name: sha256((kit / (name + '.xml')).read_bytes()).hexdigest() for name in ('baseline', 'behavioral')}
        device = Device.objects.create(environment_id='synthetic-env', generation=1,
            certificate_sha256='a' * 64, wazuh_agent_id='901')
        release = RunnerRelease.objects.create(scenario_path=str(scenario), profile_path=str(profile),
            timeout_seconds=180, rule_hashes=rules, **hashes)
        owner = get_user_model().objects.create_superuser('synthetic-owner')
        now = timezone.now().replace(microsecond=0)
        job = Job.objects.create(device=device, release=release,
            not_before=now - timedelta(seconds=1), expires_at=now + timedelta(seconds=120),
            collection_start=now - timedelta(seconds=10), collection_end=now + timedelta(seconds=310),
            parameters=dict(run_label='A', rule_revision='baseline', rule_sha256=rules['baseline']))
        self.job = approve_job(job.id, owner)
        self.config = self.root / 'private.json'
        self.config.write_text(json.dumps(dict(manager_url='https://synthetic-manager.example.test/',
            agent_id=str(device.id), environment_id=device.environment_id, generation=1,
            client_certificate_sha256='a' * 64, signing_public_key_path=str(public_key),
            spool_directory=str(self.root / 'spool'), catalog=dict(scenario_path=str(scenario),
                profile_path=str(profile), runner_path=str(runner), kit_directory=str(kit),
                run_directory=str(self.root / 'runs'), expected_computer_name=os.environ['COMPUTERNAME'],
                allow_rehearsal=False, baseline_sha256=rules['baseline'],
                behavioral_sha256=rules['behavioral'], **hashes))), encoding='utf-8')

    def validate(self, envelope):
        path = self.root / 'envelope.json'
        path.write_text(json.dumps(envelope), encoding='utf-8')
        return subprocess.run([str(AGENT), '--config', str(self.config), '--validate-envelope', str(path)],
            capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)

    def test_actual_owner_approved_python_job_is_accepted_by_dotnet(self):
        result = self.validate(self.job.envelope)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout.strip(), b'AEGIS_ENVELOPE_VALID')
        self.assertEqual(result.stderr, b'')

    def test_tampering_signed_bytes_fails_in_dotnet(self):
        envelope = dict(self.job.envelope)
        raw = base64.b64decode(envelope['payload']).replace(b'"generation":1', b'"generation":2')
        envelope['payload'] = base64.b64encode(raw).decode()
        result = self.validate(envelope)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'AEGIS_SIGNATURE_REJECTED', result.stderr)

    def test_valid_signature_does_not_bypass_destination_or_schema(self):
        payload = json.loads(base64.b64decode(self.job.envelope['payload']))
        for changes in ({'agent_id': '00000000-0000-4000-8000-000000000001'},
                        {'unexpected_command': 'synthetic-never-executed'}):
            with self.subTest(changes=changes):
                envelope, _ = sign_payload(payload | changes)
                self.assertEqual(self.validate(envelope).returncode, 2)
