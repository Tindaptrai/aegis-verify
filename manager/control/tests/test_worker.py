"""Durable worker tests with synthetic receipts and source responses only."""
import importlib.util
import os
import secrets
import tempfile
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import TransactionTestCase, override_settings
from django.db import connection
from django.core.management import call_command, CommandError

from control.models import Device, RunnerRelease, Job, AuditEntry, DispatchLock
from control.signing import sign_payload
from control.tests import test_collection as fixtures
ROOT, FIXTURE = fixtures.ROOT, fixtures.FIXTURE
SyntheticTransport, page = fixtures.SyntheticTransport, fixtures.page


class WorkerTests(TransactionTestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('control.worker'), 'worker is not implemented')
        from control import worker
        self.worker = worker
        DispatchLock.objects.get_or_create(pk=1)
        from control import collection
        self.module = collection
        self.reader_credential = secrets.token_urlsafe(24)
        self.space = tempfile.TemporaryDirectory(prefix='aegis-worker-synthetic-')
        self.addCleanup(self.space.cleanup)
        self.root = Path(self.space.name)
        self.output = self.root / 'output'
        self.output.mkdir(mode=0o700)
        self.key_path = self.root / 'temporary-synthetic.pem'
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.settings = override_settings(MANAGER_SIGNING_KEY=str(self.key_path))
        self.settings.enable()
        self.addCleanup(self.settings.disable)
        # Tests use a temporary directory whose Windows inherited ACL is not private.
        # Only the platform ACL read is replaced; worker policy and path checks run.
        self.acl = patch('control.worker.read_windows_acl', return_value={
            'owner':'synthetic-owner', 'current':'synthetic-owner', 'rules':[
            {'sid':'synthetic-owner','allow':True,'rights':2032127,'propagate':0,'inherit':3}]})
        self.acl.start()
        self.addCleanup(self.acl.stop)
        self.start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.end = self.start + timedelta(minutes=10)
        self.device = Device.objects.create(environment_id='synthetic-env',
            certificate_sha256='1'*64, wazuh_agent_id='901')
        scenario = ROOT / 'scenarios/SCN-001-powershell-execution.yaml'
        profile = FIXTURE / 'profile.json'
        self.release = RunnerRelease.objects.create(scenario_path=str(scenario),
            profile_path=str(profile), scenario_sha256=sha256(scenario.read_bytes()).hexdigest(),
            profile_sha256=sha256(profile.read_bytes()).hexdigest(), runner_sha256='2'*64,
            kit_sha256='3'*64,payload_sha256='4'*64)
        self.job = Job.objects.create(device=self.device,release=self.release,
            execution_state='succeeded',not_before=self.start,expires_at=self.start+timedelta(seconds=60),
            collection_start=self.start,collection_end=self.end,approved_wazuh_agent_id='901',
            approved_generation=1,evaluation_bindings=[{'name':'target','value':'synthetic-endpoint'}])
        payload = dict(job_id=str(self.job.id),run_id=str(self.job.id),agent_id=str(self.device.id),
            environment_id='synthetic-env',generation=1,scenario_id='SCN-001',
            runner_id='scn001-safe-demo',runner_version='0.3.0',timeout_seconds=300,
            collection_start='2026-01-01T00:00:00Z',collection_end='2026-01-01T00:10:00Z')
        payload.update({name+'_sha256':getattr(self.release,name+'_sha256')
            for name in ('scenario','profile','runner','kit','payload')})
        self.job.envelope,self.job.payload_sha256 = sign_payload(payload)
        self.job.save()

    def run_one(self, responses, **kwargs):
        return self.worker.process_one(fixtures.CollectionTests.connection(self),self.output,
            now=kwargs.pop('now',self.end+timedelta(seconds=30)),
            transport=SyntheticTransport(responses),**kwargs)

    def test_late_window_then_empty_is_claimed_once(self):
        self.assertFalse(self.run_one([],now=self.end+timedelta(seconds=29)))
        self.assertTrue(self.run_one([page([])]))
        self.job.refresh_from_db()
        self.assertEqual(self.job.collection_state,'empty')
        self.assertIsNone(self.job.report)
        self.assertFalse(self.run_one([]))
        self.assertEqual(list(AuditEntry.objects.filter(job=self.job).values_list('action',flat=True)),
            ['collection_started','collection_empty'])

    def test_real_collector_and_engine_use_approval_snapshots(self):
        self.device.environment_id='mutated'; self.device.wazuh_agent_id='999'; self.device.save()
        rows=fixtures.CollectionTests.hits(self,detected=True)
        self.assertTrue(self.run_one([page(rows),page([],total=2)]))
        self.job.refresh_from_db()
        self.assertEqual(self.job.collection_state,'evaluated')
        self.assertEqual(self.job.report['evaluation']['final_status'],'Detected')
        self.assertEqual(len(self.job.report['evaluation']['evidence_index']),2)
        self.assertEqual(self.job.report['comparison_inputs']['context']['environment_id'],'synthetic-env')

    def test_failed_source_blocks_automatic_retry(self):
        from aegis_verify.connectors.wazuh.live import LiveError
        self.assertTrue(self.run_one([LiveError('connection_or_tls_failed')]))
        self.job.refresh_from_db()
        self.assertEqual(self.job.collection_state,'failed')
        self.assertEqual(self.job.error_code,'collection_failed')
        self.assertFalse(self.run_one([]))

    def test_collecting_after_crash_is_never_reclaimed(self):
        self.job.collection_state='collecting'; self.job.save()
        self.assertFalse(self.run_one([]))

    def test_tampered_pins_or_digest_fail_before_source(self):
        self.release.runner_sha256='f'*64; self.release.save()
        self.assertTrue(self.run_one([]))
        self.job.refresh_from_db()
        self.assertEqual(self.job.collection_state,'failed')
        self.assertEqual(self.job.error_code,'invalid_approved_job')

    def test_digest_tampering_fails(self):
        self.job.payload_sha256='f'*64; self.job.save()
        self.assertTrue(self.run_one([]))
        self.job.refresh_from_db()
        self.assertEqual(self.job.error_code,'invalid_approved_job')

    def test_existing_job_output_never_reuses_evidence(self):
        target=self.output / str(self.job.id); target.mkdir()
        (target / 'sentinel').write_bytes(b'old')
        self.assertTrue(self.run_one([]))
        self.job.refresh_from_db()
        self.assertEqual(self.job.error_code,'output_unavailable')
        self.assertEqual((target / 'sentinel').read_bytes(),b'old')

    def test_uncaught_collector_error_is_safe_and_durable(self):
        with patch('control.worker.collect_and_evaluate',side_effect=RuntimeError('synthetic-secret')):
            self.assertTrue(self.run_one([]))
        self.job.refresh_from_db()
        self.assertEqual(self.job.error_code,'collection_worker_failed')
        self.assertFalse(self.run_one([]))

    def test_checkout_output_root_rejected(self):
        with self.assertRaises(ValueError):
            self.worker.validate_output_root(ROOT)

    def test_signature_tampering_is_rejected(self):
        self.job.envelope['signature']='AA=='
        self.job.save()
        self.assertTrue(self.run_one([]))
        self.job.refresh_from_db()
        self.assertEqual(self.job.error_code,'invalid_approved_job')

    def test_collection_runs_after_claim_transaction_commits(self):
        original=self.worker.collect_and_evaluate
        def collect(spec,config,output,**kwargs):
            self.assertFalse(connection.in_atomic_block)
            self.assertEqual(Job.objects.get(pk=self.job.pk).collection_state,'collecting')
            return original(spec,config,output,**kwargs)
        with patch('control.worker.collect_and_evaluate',side_effect=collect):
            self.assertTrue(self.run_one([page([])]))
        self.job.refresh_from_db()
        self.assertEqual(self.job.collection_state,'empty')

    def test_other_crashed_collection_blocks_global_dispatch(self):
        other=Job.objects.create(device=self.device,release=self.release,execution_state='succeeded',
            collection_state='collecting',not_before=self.start,expires_at=self.end,
            collection_start=self.start,collection_end=self.end)
        self.assertFalse(self.run_one([]))
        self.job.refresh_from_db()
        self.assertEqual(self.job.collection_state,'pending')

    def test_command_rejects_bad_settle_and_private_configuration(self):
        with self.assertRaisesMessage(CommandError,'invalid_settle_seconds'):
            call_command('manager_worker',config='unused',output_root=str(self.output),settle_seconds=301)
        with self.assertRaisesMessage(CommandError,'invalid_private_worker_configuration'):
            call_command('manager_worker',config='missing-private-config',output_root=str(self.output),once=True)

    def test_command_once_handles_at_most_one_job(self):
        from control import collection
        with patch('control.management.commands.manager_worker.load_connection',
                   return_value=fixtures.CollectionTests.connection(self)), patch(
                   'control.management.commands.manager_worker.process_one',return_value=False) as process:
            call_command('manager_worker',config='synthetic-config',output_root=str(self.output),
                once=True,settle_seconds=17)
        self.assertEqual(process.call_count,1)
        self.assertEqual(process.call_args.kwargs['settle_seconds'],17)

    def test_recovery_requires_exclusive_process_lock(self):
        self.assertTrue(hasattr(self.worker,'worker_lock'),'worker process lock is missing')
        self.job.collection_state='collecting'; self.job.save()
        with self.worker.worker_lock(self.output):
            with self.assertRaisesMessage(ValueError,'worker_already_running'):
                self.worker.recover_interrupted(self.output)
        self.job.refresh_from_db()
        self.assertEqual(self.job.collection_state,'collecting')
        self.assertTrue((self.output / '.worker.lock').exists())

    def test_recovery_is_explicit_and_leaves_collection_blocked(self):
        self.assertTrue(hasattr(self.worker,'recover_interrupted'),'explicit recovery is missing')
        self.job.collection_state='collecting'; self.job.save()
        AuditEntry.objects.create(job=self.job,action='collection_started',
            actor='worker:' + sha256(os.path.normcase(str(self.output.resolve())).encode()).hexdigest())
        self.assertFalse(self.run_one([]))
        self.assertEqual(self.worker.recover_interrupted(self.output),1)
        self.job.refresh_from_db()
        self.assertEqual(self.job.collection_state,'failed')
        self.assertEqual(self.job.error_code,'worker_interrupted')
        self.assertIsNone(self.job.report)
        self.assertFalse(self.run_one([]))
        self.assertTrue(AuditEntry.objects.filter(job=self.job,action='collection_interrupted').exists())

    def test_command_recovery_does_not_load_source_configuration(self):
        self.job.collection_state='collecting'; self.job.save()
        AuditEntry.objects.create(job=self.job,action='collection_started',
            actor='worker:' + sha256(os.path.normcase(str(self.output.resolve())).encode()).hexdigest())
        with patch('control.management.commands.manager_worker.load_connection') as load:
            call_command('manager_worker',output_root=str(self.output),recover_interrupted=True)
        load.assert_not_called()
        self.job.refresh_from_db()
        self.assertEqual(self.job.error_code,'worker_interrupted')

    def test_other_output_root_cannot_bypass_active_worker_lock(self):
        self.job.collection_state='collecting'; self.job.save()
        AuditEntry.objects.create(job=self.job,action='collection_started',
            actor='worker:' + sha256(os.path.normcase(str(self.output.resolve())).encode()).hexdigest())
        alternate=self.root / 'alternate'; alternate.mkdir(mode=0o700)
        with self.worker.worker_lock(self.output):
            with self.assertRaisesMessage(ValueError,'collection_output_root_mismatch'):
                self.worker.recover_interrupted(alternate)
        self.job.refresh_from_db()
        self.assertEqual(self.job.collection_state,'collecting')
