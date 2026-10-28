"""Offline v2 collection authority; all credentials/source responses are synthetic."""
import base64
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import secrets
import tempfile
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.contrib.auth import get_user_model
from django.db import connection as database, models
from django.test import TransactionTestCase, override_settings

from control import execution_services as services, worker
from control.execution_connections import register_execution_connection, resolve_execution_connection
from control.execution_contracts import (PROTOCOL, PROVIDER_ID, ApproveInput, BindingInput,
    ExecutionDeviceDTO, PollRequest, PreviewInput, canonical_bytes, decode_contract)
from control.execution_models import DeviceExecutionBinding, RegisteredExecutionConnection
from control.execution_ownership import transfer_execution_ownership
from control.execution_signing import verify_execution_envelope
from control.models import AuditEntry, Device, DispatchLock, Job, RunnerRelease
from control.tests.test_collection import FIXTURE, ROOT, SyntheticTransport, page
from accounts.models import AccountMutationLock


class ExecutionCollectionFixture:
    """Real manager authority and canonical inputs, replacing only external boundaries."""
    def setUp(self):
        super().setUp()
        self.space = tempfile.TemporaryDirectory(prefix='aegis-v2-collection-synthetic-')
        self.addCleanup(self.space.cleanup)
        self.root = Path(self.space.name)
        self.output = self.root / 'output'
        self.output.mkdir(mode=0o700)
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.owner = get_user_model().objects.create_superuser('collection-owner', password=secrets.token_urlsafe(24))
        DispatchLock.objects.get_or_create(pk=1)
        AccountMutationLock.objects.get_or_create(pk=1)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.key_path = self.root / 'execution.pem'
        self.key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.settings = override_settings(MANAGER_EXECUTION_SIGNING_KEY=str(self.key_path))
        self.settings.enable(); self.addCleanup(self.settings.disable)
        # Temporary test folders inherit host ACLs. Only the OS ACL read is injected;
        # the private-path/config/pin policies and all source/intake logic run normally.
        acl = dict(owner='synthetic-owner', current='synthetic-owner', rules=[
            dict(sid='synthetic-owner', allow=True, rights=2032127, propagate=0, inherit=3)])
        for target in ('control.worker.read_windows_acl', 'control.collection.read_windows_acl'):
            handle = patch(target, return_value=acl)
            handle.start(); self.addCleanup(handle.stop)
        self.reader_credential = secrets.token_urlsafe(24)
        self.config_path = self.root / 'reader.json'
        ca = self.root / 'synthetic-ca.pem'
        ca.write_bytes(b'synthetic-placeholder-not-used-for-TLS')
        self.config_path.write_bytes(canonical_bytes(dict(endpoint='https://synthetic-indexer.example.test',
            username='synthetic-reader', password=self.reader_credential, ca_file=str(ca),
            index='wazuh-alerts-*', collection_mode='unknown')))
        self.config_path.chmod(0o600)
        self.registered = register_execution_connection(self.owner, expected_revision=None,
            config_path=self.config_path, output_root=self.output)
        self.connection, _ = resolve_execution_connection(str(self.registered.connection_id), 1)
        self.scenario_path, self.profile_path = self.root / 'scenario.yaml', self.root / 'profile.json'
        self.scenario_path.write_bytes((ROOT / 'scenarios/SCN-001-powershell-execution.yaml').read_bytes())
        self.profile_path.write_bytes((FIXTURE / 'profile.json').read_bytes())
        self.release = RunnerRelease.objects.create(scenario_path=str(self.scenario_path), profile_path=str(self.profile_path),
            scenario_sha256=sha256(self.scenario_path.read_bytes()).hexdigest(),
            profile_sha256=sha256(self.profile_path.read_bytes()).hexdigest(), runner_sha256='b'*64,
            kit_sha256='c'*64, payload_sha256='d'*64, rule_hashes={'baseline':'e'*64,'behavioral':'f'*64},
            timeout_seconds=180, evaluation_bindings=[{'name':'target','value':'synthetic-endpoint'}])
        self.device = Device.objects.create(connection_kind='paired_presence', environment_id='synthetic-env',
            certificate_sha256='a'*64, certificate_not_before=self.now-timedelta(days=366),
            certificate_expires_at=self.now+timedelta(days=1096), os='windows', architecture='x64')
        transfer_execution_ownership(self.owner, dict(connection_id=str(self.registered.connection_id),
            environment_id='synthetic-env', wazuh_agent_id='901'), None, str(self.device.pk),
            dict(paired_device_id=str(self.device.pk), legacy_device_id=None), 'Reviewed synthetic fixture',
            evidence_refs=['fixture:review'])
        services.set_execution_binding(self.owner, str(self.device.pk), BindingInput(None, True, PROVIDER_ID,
            self.release.pk, 'b'*64, str(self.registered.connection_id), 1, '901'))
        self.binding = DeviceExecutionBinding.objects.get(device=self.device, is_current=True)
        self.identity = services.ExecutionIdentity(str(self.device.pk), 1, self.device.certificate_sha256)
        self.poll = PollRequest(protocol=PROTOCOL, device_id=str(self.device.pk), generation=1,
            binding_id=str(self.binding.binding_id), binding_revision=1)

    def ready(self, device_id, *, now, active_job_id=None):
        # Local Windows readiness and independently timed probes have their own suites.
        return ExecutionDeviceDTO(str(self.device.pk), PROVIDER_ID, str(self.binding.binding_id), 1,
            'installed_supported', True, (), None, None, self.release.pk, self.binding.release_sha256,
            str(self.registered.connection_id), '901')

    def approved(self):
        with patch('control.execution_services.execution_readiness', side_effect=self.ready):
            preview = services.preview_execution(self.owner, PreviewInput(str(self.device.pk), PROVIDER_ID, 1, 'A', 'baseline'), now=self.now)
            dto = services.approve_execution(self.owner, ApproveInput(preview.preview_id, preview.preview_sha256,
                str(uuid.uuid4())), now=self.now)
        return Job.objects.get(pk=dto.job_id)

    def succeeded(self, *, state='succeeded'):
        job = self.approved()
        with patch('control.execution_services.execution_readiness', side_effect=self.ready):
            envelope = services.poll_execution(self.identity, self.poll, now=self.now)
            verified = verify_execution_envelope(envelope, self.key.public_key())
            self.assertEqual(verified.job_id, str(job.pk))
            start = canonical_bytes(asdict(self.poll) | dict(start_request_id=str(uuid.uuid4()), job_sha256=job.job_sha256))
            decode_contract('StartAck', services.authorize_execution_start(self.identity, str(job.pk), start, now=self.now))
        stamp = lambda value: value.strftime('%Y-%m-%dT%H:%M:%SZ')
        receipt = canonical_bytes(asdict(self.poll) | dict(receipt_id=str(uuid.uuid4()), job_id=str(job.pk),
            job_sha256=job.job_sha256, state=state, started_at=stamp(self.now) if state != 'execution_unknown' else None,
            finished_at=stamp(self.now+timedelta(seconds=180)), exit_code=0 if state=='succeeded' else None,
            cleanup_succeeded=state=='succeeded'))
        ack = services.accept_execution_receipt(self.identity, receipt, now=self.now+timedelta(seconds=180))
        decode_contract('ReceiptAck', ack)
        job.refresh_from_db()
        self.receipt, self.receipt_ack = receipt, ack
        return job

    def run_one(self, job, responses=(), **kwargs):
        self.transport = SyntheticTransport(responses)
        return worker.process_one(self.connection, self.output, now=kwargs.pop('now',job.collection_end+timedelta(seconds=30)),
            transport=self.transport, execution_connection=kwargs.pop('execution_connection',self.registered), **kwargs)

    def hits(self, *, detected=False):
        rows = []
        for number, name in enumerate(('sysmon1', 'powershell4104'), 1):
            value = json.loads((FIXTURE / (name+'.synthetic.json')).read_bytes())
            value.update(_id=f'synthetic-{number}', _index='wazuh-alerts-synthetic')
            value['_source']['synthetic_unknown'] = {'retained': 'raw-only'}
            if detected and name == 'powershell4104': value['_source']['rule']['id']='synthetic-detection-only'
            rows.append(value)
        return rows

    def corrupt(self, job, **changes):
        # Simulate privileged storage corruption; ordinary ORM authority writes refuse it.
        models.QuerySet.update(Job.objects.filter(pk=job.pk), **changes)
        job.refresh_from_db()

    def assert_rejected(self, job):
        self.assertTrue(self.run_one(job))
        job.refresh_from_db()
        self.assertEqual((job.collection_state,job.error_code,job.report), ('failed','invalid_approved_job',None))
        self.assertEqual(self.transport.calls, [])
        self.assertFalse((self.output / str(job.pk)).exists())
        self.assertEqual(list(AuditEntry.objects.filter(job=job, action__startswith='collection_').values_list('action',flat=True)),
            ['collection_rejected'])
        self.assertFalse(self.run_one(job))


class ExecutionCollectionTests(ExecutionCollectionFixture, TransactionTestCase):
    def test_approved_collection_helper_uses_only_frozen_authority(self):
        self.assertIsNotNone(importlib.util.find_spec('control.execution_collection'), 'v2 collection adapter is missing')
        from control.execution_collection import approved_execution_collection
        job = self.succeeded()
        spec, row = approved_execution_collection(job)
        self.assertEqual((spec.job_id,spec.environment_id,spec.wazuh_agent_id), (str(job.pk),'synthetic-env','901'))
        self.assertEqual(spec.bindings, ({'name':'target','value':'synthetic-endpoint'},))
        self.assertEqual((row.connection_id,row.revision), (self.registered.connection_id,1))

    def test_v2_uses_snapshot_after_mutable_release_change(self):
        job = self.succeeded()
        RunnerRelease.objects.filter(pk=self.release.pk).update(scenario_path='changed-path',profile_path='changed-profile',
            scenario_sha256='f'*64,profile_sha256='f'*64,runner_sha256='f'*64,timeout_seconds=300,evaluation_bindings=[])
        Device.objects.filter(pk=self.device.pk).update(environment_id='mutated',wazuh_agent_id='999')
        Job.objects.filter(pk=job.pk).update(evaluation_bindings=[],parameters={},approved_wazuh_agent_id='999')
        self.assertTrue(self.run_one(job,[page(self.hits(detected=True)),page([],total=2)]))
        job.refresh_from_db()
        self.assertEqual(job.collection_state,'evaluated')
        self.assertEqual(job.report['evaluation']['final_status'],'Detected')
        self.assertEqual(job.report['comparison_inputs']['context']['environment_id'],'synthetic-env')
        self.assertEqual(self.transport.calls[0][2]['query']['bool']['filter'][0],{'term':{'agent.id':'901'}})

    def test_no_registration_and_other_registration_skip_without_claim(self):
        job = self.succeeded()
        self.assertFalse(self.run_one(job, execution_connection=None))
        other = RegisteredExecutionConnection.objects.create(connection_id=uuid.uuid4(),revision=1,
            config_path=self.registered.config_path,config_sha256=self.registered.config_sha256,
            output_root_path=self.registered.output_root_path,output_root_fingerprint=self.registered.output_root_fingerprint,
            reviewed_by=self.owner)
        self.assertFalse(self.run_one(job, execution_connection=other))
        next_revision = RegisteredExecutionConnection.objects.create(connection_id=self.registered.connection_id,revision=2,
            config_path=self.registered.config_path,config_sha256=self.registered.config_sha256,
            output_root_path=self.registered.output_root_path,output_root_fingerprint=self.registered.output_root_fingerprint,
            reviewed_by=self.owner)
        self.assertFalse(self.run_one(job, execution_connection=next_revision))
        job.refresh_from_db(); self.assertEqual(job.collection_state,'pending')
        self.assertEqual(self.transport.calls,[])
        self.assertFalse(AuditEntry.objects.filter(job=job,action__startswith='collection_').exists())

    def test_protocol_family_never_falls_back(self):
        job = self.succeeded()
        self.corrupt(job,protocol_family='unknown-family')
        self.assert_rejected(job)

    def test_v2_bad_signature_never_uses_v1_envelope(self):
        job = self.succeeded()
        envelope = json.loads(bytes(job.envelope_bytes)); envelope['signature']='AA=='
        self.corrupt(job,envelope_bytes=canonical_bytes(envelope))
        self.assert_rejected(job)

    def test_rejected_pending_job_cannot_retain_a_previous_report(self):
        job = self.succeeded()
        self.corrupt(job,envelope_bytes=b'{}',report={'synthetic_stale_report':True})
        self.assert_rejected(job)

    def test_original_signed_bytes_and_stored_payload_must_agree(self):
        job = self.succeeded()
        self.corrupt(job,signed_payload_bytes=bytes(job.signed_payload_bytes)+b' ')
        self.assert_rejected(job)

    def test_snapshot_digest_must_match_actual_bytes_and_signed_snapshot(self):
        job = self.succeeded()
        from control.execution_models import JobApprovalSnapshot
        models.QuerySet.update(JobApprovalSnapshot.objects.filter(pk=job.approval_snapshot_id),snapshot_sha256='f'*64)
        self.assert_rejected(job)

    def test_valid_signature_on_changed_snapshot_field_is_rejected(self):
        job = self.succeeded()
        payload = json.loads(bytes(job.signed_payload_bytes)); payload['environment_id']='different-env'
        raw = canonical_bytes(payload)
        signature = self.key.sign(raw,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
        envelope = canonical_bytes(dict(protocol=PROTOCOL,key_id='manager-execution-v2',payload=base64.b64encode(raw).decode(),
            signature=base64.b64encode(signature).decode()))
        self.corrupt(job,envelope_bytes=envelope,signed_payload_bytes=raw,job_sha256=sha256(raw).hexdigest())
        self.assert_rejected(job)

    def test_signature_verification_preserves_original_noncanonical_payload_bytes(self):
        job = self.succeeded()
        raw = b' \n' + bytes(job.signed_payload_bytes) + b'\n'
        signature = self.key.sign(raw,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
        envelope = canonical_bytes(dict(protocol=PROTOCOL,key_id='manager-execution-v2',payload=base64.b64encode(raw).decode(),
            signature=base64.b64encode(signature).decode()))
        self.corrupt(job,envelope_bytes=envelope,signed_payload_bytes=raw,job_sha256=sha256(raw).hexdigest())
        self.assertTrue(self.run_one(job,[page([])]))
        job.refresh_from_db(); self.assertEqual(job.collection_state,'empty')
        self.assertEqual(bytes(job.signed_payload_bytes),raw)

    def test_changed_private_scenario_bytes_rejected_before_claim(self):
        job = self.succeeded(); self.scenario_path.write_bytes(self.scenario_path.read_bytes()+b'\n')
        self.assert_rejected(job)

    def test_changed_private_profile_bytes_rejected_before_claim(self):
        job = self.succeeded(); self.profile_path.write_bytes(self.profile_path.read_bytes()+b' ')
        self.assert_rejected(job)

    def test_changed_private_config_rejected_before_claim(self):
        job = self.succeeded(); self.config_path.write_bytes(self.config_path.read_bytes()+b' ')
        self.assert_rejected(job)

    def test_changed_running_config_cannot_substitute_for_approved_source(self):
        from dataclasses import replace
        job = self.succeeded(); self.connection=replace(self.connection,password=secrets.token_urlsafe(24))
        self.assert_rejected(job)

    def test_changed_output_root_cannot_substitute_for_approved_root(self):
        job = self.succeeded(); self.output=self.root/'other-output'; self.output.mkdir(mode=0o700)
        self.assert_rejected(job)

    def test_settle_boundary_and_claim_is_committed_before_source_io(self):
        job = self.succeeded()
        # A caller's legacy settle override cannot shorten the v2 reviewed boundary.
        self.assertFalse(self.run_one(job,now=job.collection_end+timedelta(seconds=29,microseconds=999999),settle_seconds=0))
        original = worker.collect_and_evaluate
        def observed(spec,config,output,**kwargs):
            self.assertFalse(database.in_atomic_block)
            self.assertEqual(Job.objects.get(pk=job.pk).collection_state,'collecting')
            self.assertEqual(AuditEntry.objects.filter(job=job,action='collection_started').count(),1)
            return original(spec,config,output,**kwargs)
        with patch('control.worker.collect_and_evaluate',side_effect=observed):
            self.assertTrue(self.run_one(job,[page([])]))
        job.refresh_from_db(); self.assertEqual(job.collection_state,'empty'); self.assertIsNone(job.report)

    def test_failed_and_unknown_execution_never_evaluated(self):
        for state in ('failed','execution_unknown','queued','leased','started'):
            with self.subTest(state=state):
                job = self.approved()
                Job.objects.filter(pk=job.pk).update(execution_state=state)
                try:
                    self.assertFalse(self.run_one(job))
                    self.assertEqual(self.transport.calls,[])
                finally:
                    Job.objects.filter(pk=job.pk).update(collection_state='reconciled')

    def test_crashed_claim_requires_explicit_recovery_and_owner_reconciliation(self):
        job = self.succeeded()
        Job.objects.filter(pk=job.pk).update(collection_state='collecting')
        AuditEntry.objects.create(job=job,action='collection_started',actor=worker._root_actor(self.output.resolve()))
        self.assertFalse(self.run_one(job))
        with worker.worker_lock(self.output):
            with self.assertRaisesMessage(ValueError,'worker_already_running'): worker.recover_interrupted(self.output)
        self.assertEqual(worker.recover_interrupted(self.output),1)
        self.assertFalse(self.run_one(job))
        services.reconcile_execution(self.owner,str(job.pk),reason='Reviewed synthetic interrupted output',evidence_refs=['fixture:journal'])
        job.refresh_from_db(); self.assertEqual(job.collection_state,'reconciled')
        next_job=self.succeeded(); self.assertTrue(self.run_one(next_job,[page([])]))

    def test_existing_uuid_output_never_reused(self):
        job=self.succeeded(); target=self.output/str(job.pk); target.mkdir(); (target/'sentinel').write_bytes(b'old')
        self.assertTrue(self.run_one(job))
        job.refresh_from_db(); self.assertEqual((job.collection_state,job.error_code),('failed','output_unavailable'))
        self.assertEqual((target/'sentinel').read_bytes(),b'old'); self.assertEqual(self.transport.calls,[])

    def test_partial_shards_fail_without_report_and_block_next_dispatch(self):
        job=self.succeeded(); raw=json.loads(page(self.hits())); raw['_shards']={'total':2,'successful':1,'failed':1}
        self.assertTrue(self.run_one(job,[canonical_bytes(raw)]))
        job.refresh_from_db(); self.assertEqual((job.collection_state,job.error_code,job.report),('failed','collection_failed',None))
        self.assertFalse(self.run_one(job))
        with self.assertRaises(ValueError): self.approved()

    def test_scroll_cleanup_error_never_evaluates_complete_pages(self):
        job=self.succeeded()
        class CleanupFailure(SyntheticTransport):
            def request(self,method,path,body):
                if method=='DELETE': return b'{"succeeded":false}'
                return super().request(method,path,body)
        transport=CleanupFailure([page(self.hits(detected=True)),page([],total=2)])
        self.assertTrue(worker.process_one(self.connection,self.output,now=job.collection_end+timedelta(seconds=30),
            transport=transport,execution_connection=self.registered))
        job.refresh_from_db(); self.assertEqual((job.collection_state,job.error_code,job.report),('failed','collection_cleanup_failed',None))
