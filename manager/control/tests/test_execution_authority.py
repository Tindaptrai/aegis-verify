"""Synthetic authority fixtures; only the future readiness boundary is injected."""
import hashlib
import importlib
import importlib.util
import tempfile
import uuid
from dataclasses import asdict, replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import override_settings
from django.utils import timezone

from accounts.tests.helpers import AccountsCase
from control.execution_contracts import (PROTOCOL, PROVIDER_ID, BindingInput, PreviewInput,
    ApproveInput, PollRequest, ExecutionDeviceDTO, canonical_bytes, decode_contract)
from control.execution_models import RegisteredExecutionConnection, DeviceExecutionBinding
from control.models import Device, Job, RunnerRelease, AuditEntry, DispatchLock


class ExecutionFixture:
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('control.execution_services'), 'execution services are missing')
        self.service = importlib.import_module('control.execution_services')
        self.ownership = importlib.import_module('control.execution_ownership')
        self.temp = tempfile.TemporaryDirectory(prefix='aegis-synthetic-execution-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.now = timezone.now().replace(microsecond=0)
        DispatchLock.objects.get_or_create(pk=1)
        scenario, profile, config = root / 'scenario.yaml', root / 'profile.json', root / 'config.json'
        for path, raw in ((scenario, b'synthetic scenario'), (profile, b'{}'), (config, b'{}')):
            path.write_bytes(raw)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        key_path = root / 'execution.pem'
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.settings_override = override_settings(MANAGER_EXECUTION_SIGNING_KEY=str(key_path))
        self.settings_override.enable(); self.addCleanup(self.settings_override.disable)
        self.release = RunnerRelease.objects.create(scenario_path=str(scenario), profile_path=str(profile),
            scenario_sha256=hashlib.sha256(scenario.read_bytes()).hexdigest(), profile_sha256=hashlib.sha256(profile.read_bytes()).hexdigest(),
            runner_sha256='b'*64, kit_sha256='c'*64, payload_sha256='d'*64,
            rule_hashes={'baseline': 'e'*64, 'behavioral': 'f'*64}, timeout_seconds=180)
        self.connection = RegisteredExecutionConnection.objects.create(revision=1, config_path=str(config),
            config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(), output_root_fingerprint='b'*64, reviewed_by=self.owner)
        self.device = Device.objects.create(connection_kind='paired_presence', environment_id='synthetic-env',
            certificate_sha256='a'*64, certificate_not_before=self.now-timedelta(days=1),
            certificate_expires_at=self.now+timedelta(days=1), os='windows', architecture='x64')
        self.resource = dict(connection_id=str(self.connection.connection_id), environment_id=self.device.environment_id, wazuh_agent_id='901')
        self.reviewed = dict(paired_device_id=str(self.device.pk), legacy_device_id=None)
        self.owner_row = self.ownership.transfer_execution_ownership(self.owner, self.resource, None,
            str(self.device.pk), self.reviewed, 'Reviewed synthetic fixture', evidence_refs=['fixture:review'])
        self.binding_input = BindingInput(None, True, PROVIDER_ID, self.release.pk, 'b'*64,
            str(self.connection.connection_id), 1, '901')
        self.service.set_execution_binding(self.owner, str(self.device.pk), self.binding_input)
        self.binding = DeviceExecutionBinding.objects.get(device=self.device, is_current=True)
        self.identity = self.service.ExecutionIdentity(str(self.device.pk), 1, self.device.certificate_sha256)
        self.poll = PollRequest(protocol=PROTOCOL, device_id=str(self.device.pk), generation=1,
            binding_id=str(self.binding.binding_id), binding_revision=1)

    def ready(self, device_id, *, now, active_job_id=None):
        return ExecutionDeviceDTO(str(self.device.pk), PROVIDER_ID, str(self.binding.binding_id), self.binding.revision,
            'installed_supported', True, (), None, None, self.release.pk, self.binding.release_sha256,
            str(self.connection.connection_id), '901')

    def preview(self, actor=None, now=None):
        with patch('control.execution_services.execution_readiness', side_effect=self.ready):
            return self.service.preview_execution(actor or self.operator,
                PreviewInput(str(self.device.pk), PROVIDER_ID, self.binding.revision, 'A', 'baseline'), now=now or self.now)

    def approval(self, preview=None, key=None):
        preview = preview or self.preview()
        return ApproveInput(preview.preview_id, preview.preview_sha256, key or str(uuid.uuid4()))

    def approve(self, request=None, now=None, actor=None):
        request = request or self.approval()
        with patch('control.execution_services.execution_readiness', side_effect=self.ready):
            return self.service.approve_execution(actor or self.operator, request, now=now or self.now)

    def leased(self):
        dto = self.approve()
        with patch('control.execution_services.execution_readiness', side_effect=self.ready):
            first = self.service.poll_execution(self.identity, self.poll, now=self.now)
            self.assertEqual(self.service.poll_execution(self.identity, self.poll, now=self.now), first)
        return Job.objects.get(pk=dto.job_id)

    def start(self, job, request_id=None):
        raw = canonical_bytes(asdict(self.poll) | dict(start_request_id=request_id or str(uuid.uuid4()), job_sha256=job.job_sha256))
        with patch('control.execution_services.execution_readiness', side_effect=self.ready):
            ack = self.service.authorize_execution_start(self.identity, str(job.pk), raw, now=self.now)
        return raw, ack

    def receipt(self, job, state='succeeded'):
        stamp = lambda t: t.strftime('%Y-%m-%dT%H:%M:%SZ')
        return canonical_bytes(asdict(self.poll) | dict(receipt_id=str(uuid.uuid4()), job_id=str(job.pk),
            job_sha256=job.job_sha256, state=state, started_at=stamp(self.now) if state != 'execution_unknown' else None,
            finished_at=stamp(self.now+timedelta(seconds=180)), exit_code=0 if state=='succeeded' else None,
            cleanup_succeeded=state=='succeeded'))


class ExecutionCase(ExecutionFixture, AccountsCase):
    pass


class ExecutionAuthorityTests(ExecutionCase):
    def test_missing_execution_signing_authority_is_unavailable_and_creates_no_job(self):
        from control.execution_contracts import ExecutionError
        request=self.approval()
        with override_settings(MANAGER_EXECUTION_SIGNING_KEY=None):
            with self.assertRaises(ExecutionError) as denied: self.approve(request)
        self.assertEqual(denied.exception.status,503)
        self.assertFalse(Job.objects.exists())

    def test_admin_saves_recheck_owner_permission_and_cannot_mint_pairing(self):
        from django.contrib.admin.sites import site
        from django.test import RequestFactory
        request=RequestFactory().post('/admin/'); request.user=self.owner
        new=Device(environment_id='synthetic',certificate_sha256='f'*64,connection_kind='paired_presence')
        with self.assertRaises(ValueError): site._registry[Device].save_model(request,new,None,False)
        get_user_model().objects.filter(pk=self.owner.pk).update(is_active=False)
        self.device.hostname='stale authority'
        with self.assertRaises(PermissionError): site._registry[Device].save_model(request,self.device,None,True)

    def test_start_retry_cannot_bypass_reconciliation_or_new_readiness_denial(self):
        job=self.leased(); raw,_=self.start(job)
        denied=replace(self.ready(str(self.device.pk),now=self.now),ready=False,blocking_codes=('worker_unavailable',))
        with patch('control.execution_services.execution_readiness',return_value=denied):
            with self.assertRaises(ValueError): self.service.authorize_execution_start(self.identity,str(job.pk),raw,now=self.now)
        self.service.reconcile_execution(self.owner,str(job.pk),reason='Reviewed journal',evidence_refs=['fixture:journal'])
        with patch('control.execution_services.execution_readiness',side_effect=self.ready):
            with self.assertRaises(ValueError): self.service.authorize_execution_start(self.identity,str(job.pk),raw,now=self.now)

    def test_binding_change_rejected_when_busy_and_disable_does_not_change_revision(self):
        job=self.leased()
        changed=replace(self.binding_input,expected_revision=1,installation_profile_sha256='c'*64)
        with self.assertRaises(ValueError): self.service.set_execution_binding(self.owner,str(self.device.pk),changed)
        self.service.set_execution_binding(self.owner,str(self.device.pk),replace(self.binding_input,expected_revision=1,enabled=False))
        self.binding.refresh_from_db()
        self.assertEqual(self.binding.revision,1)
        self.assertEqual(bytes(Job.objects.get(pk=job.pk).envelope_bytes),bytes(job.envelope_bytes))
        with patch('control.execution_services.execution_readiness',side_effect=self.ready):
            with self.assertRaises(ValueError): self.service.poll_execution(self.identity,self.poll,now=self.now)

    def test_idle_binding_revision_retires_old_mapping_and_owner_notes_are_atomic(self):
        from control.execution_models import ExecutionTargetOwnership, ExecutionOwnerDecision
        self.service.set_execution_binding(self.owner,str(self.device.pk),replace(self.binding_input,expected_revision=1,installation_profile_sha256='c'*64))
        self.assertEqual(DeviceExecutionBinding.objects.filter(device=self.device,is_current=True).get().revision,2)
        self.binding.refresh_from_db(); self.assertFalse(self.binding.is_current)
        count=ExecutionOwnerDecision.objects.count()
        with self.assertRaises(ValueError): self.ownership.transfer_execution_ownership(self.owner,self.resource,1,str(self.device.pk),
            self.reviewed,'Invalid note',evidence_refs=['bad\nref'])
        self.assertEqual(ExecutionTargetOwnership.objects.get().revision,1)
        self.assertEqual(ExecutionOwnerDecision.objects.count(),count)

    def test_cancel_start_serial_states_and_receipt_id_collision(self):
        job=self.leased(); self.start(job)
        with self.assertRaises(ValueError): self.service.cancel_execution(self.operator,str(job.pk))
        raw=self.receipt(job)
        self.service.accept_execution_receipt(self.identity,raw,now=self.now+timedelta(seconds=180))
        self.service.reconcile_execution(self.owner,str(job.pk),reason='Reviewed fixture',evidence_refs=['fixture:review'])
        next_job=self.leased(); self.start(next_job)
        import json
        receipt=json.loads(self.receipt(next_job)); receipt['receipt_id']=json.loads(raw)['receipt_id']
        with self.assertRaises(ValueError): self.service.accept_execution_receipt(self.identity,canonical_bytes(receipt),now=self.now+timedelta(seconds=180))

    def test_preview_rechecks_changed_private_config_bytes(self):
        request=self.approval()
        Path(self.connection.config_path).write_bytes(b'{"synthetic_changed":true}')
        with self.assertRaises(ValueError): self.approve(request)
        self.assertFalse(Job.objects.exists())

    def test_production_readiness_is_default_deny(self):
        dto = self.service.execution_readiness(str(self.device.pk), now=self.now)
        self.assertFalse(dto.ready)
        with self.assertRaises(ValueError): self.service.preview_execution(self.operator,
            PreviewInput(str(self.device.pk), PROVIDER_ID, 1, 'A', 'baseline'), now=self.now)
        self.assertFalse(Job.objects.exists())

    def test_preview_windows_and_exact_30_second_approval_boundary(self):
        preview = self.preview()
        self.assertEqual(preview.summary.collection_start, (self.now-timedelta(seconds=30)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        self.assertEqual(preview.summary.expires_at, (self.now+timedelta(seconds=120)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        self.assertEqual(preview.summary.collection_end, (self.now+timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        request = self.approval(preview)
        with self.assertRaises(ValueError): self.approve(request, now=self.now+timedelta(seconds=91))
        dto = self.approve(request, now=self.now+timedelta(seconds=90))
        self.assertEqual(dto.summary, preview.summary)
        self.assertEqual(Job.objects.get().expires_at, self.now+timedelta(seconds=120))

    def test_actor_bound_single_approval_and_current_permission_replay(self):
        request = self.approval()
        with self.assertRaises(ValueError): self.approve(request, actor=self.owner)
        first = self.approve(request)
        self.assertEqual(self.approve(request).job_id, first.job_id)
        with self.assertRaises(ValueError): self.approve(replace(request, preview_sha256='f'*64))
        with self.assertRaises(ValueError): self.approve(replace(request, idempotency_key=str(uuid.uuid4())))
        self.assertEqual(Job.objects.count(), 1)
        self.assertEqual(AuditEntry.objects.filter(action='approved').count(), 1)
        self.operator.groups.clear()
        with self.assertRaises(PermissionError): self.approve(request)

    def test_binding_device_permission_is_separate_from_connection_permission(self):
        actor = get_user_model().objects.create_user('synthetic-device-manager')
        actor.user_permissions.set(Permission.objects.filter(content_type__app_label='accounts', codename__in=['view','manage_devices']))
        self.service.set_execution_binding(actor, str(self.device.pk), replace(self.binding_input, expected_revision=1, enabled=False))
        self.assertFalse(DeviceExecutionBinding.objects.get(pk=self.binding.pk).enabled)
        with self.assertRaises(PermissionError): self.service.set_execution_binding(self.operator, str(self.device.pk), self.binding_input)
        with self.assertRaises(PermissionError): self.ownership.transfer_execution_ownership(actor,
            self.resource, 1, str(self.device.pk), self.reviewed, 'Review', evidence_refs=['fixture:review'])

    def test_release_mapping_and_connection_drift_conflict(self):
        request = self.approval()
        self.release.timeout_seconds = 181; self.release.save()
        with self.assertRaises(ValueError): self.approve(request)
        self.release.timeout_seconds = 180; self.release.save()
        Device.objects.filter(pk=self.device.pk).update(wazuh_agent_id='902')
        with self.assertRaises(ValueError): self.approve(request)
        Device.objects.filter(pk=self.device.pk).update(wazuh_agent_id='901')
        RegisteredExecutionConnection.objects.create(connection_id=self.connection.connection_id, revision=2,
            config_path=self.connection.config_path, config_sha256=self.connection.config_sha256,
            output_root_fingerprint='c'*64, reviewed_by=self.owner)
        with self.assertRaises(ValueError): self.approve(request)
        self.assertFalse(Job.objects.exists())

    def test_exact_start_and_receipt_retries_once_and_disable_preserves_receipt(self):
        job = self.leased(); raw, ack = self.start(job)
        with patch('control.execution_services.execution_readiness', side_effect=self.ready):
            self.assertEqual(self.service.authorize_execution_start(self.identity, str(job.pk), raw, now=self.now), ack)
            with self.assertRaises(ValueError): self.start(job)
        self.service.set_execution_binding(self.owner, str(self.device.pk), replace(self.binding_input, expected_revision=1, enabled=False))
        with self.assertRaises(ValueError): self.service.authorize_execution_start(self.identity, str(job.pk), raw, now=self.now)
        receipt = self.receipt(job)
        ack = self.service.accept_execution_receipt(self.identity, receipt, now=self.now+timedelta(seconds=180))
        self.assertEqual(self.service.accept_execution_receipt(self.identity, receipt, now=self.now+timedelta(seconds=181)), ack)
        with self.assertRaises(ValueError): self.service.accept_execution_receipt(self.identity, receipt+b' ', now=self.now+timedelta(seconds=181))
        job.refresh_from_db()
        self.assertEqual(job.execution_state, 'succeeded'); self.assertEqual(job.collection_state, 'pending')
        self.assertIsNone(job.report)
        self.assertEqual(AuditEntry.objects.filter(job=job, action='start_authorized').count(), 1)
        self.assertEqual(AuditEntry.objects.filter(job=job, action='receipt_accepted').count(), 1)

    def test_cancelled_lease_remains_ambiguous_until_owner_evidence_reconciliation(self):
        from control.execution_models import ExecutionOwnerDecision
        job = self.leased(); self.service.cancel_execution(self.operator, str(job.pk))
        self.service.accept_execution_receipt(self.identity, self.receipt(job, 'execution_unknown'), now=self.now+timedelta(seconds=180))
        with self.assertRaises(ValueError): self.preview()
        with self.assertRaises(PermissionError): self.service.reconcile_execution(self.operator, str(job.pk), reason='Reviewed', evidence_refs=['fixture:journal'])
        with self.assertRaises(ValueError): self.service.reconcile_execution(self.owner, str(job.pk), reason='', evidence_refs=[])
        result = self.service.reconcile_execution(self.owner, str(job.pk), reason='Reviewed synthetic journal', evidence_refs=['fixture:journal'])
        self.assertEqual(result.collection_state, 'reconciled')
        decision = ExecutionOwnerDecision.objects.get(job=job)
        self.assertEqual(decision.evidence_refs, ['fixture:journal'])
        with self.assertRaises(ValueError): ExecutionOwnerDecision.objects.filter(pk=decision.pk).update(reason='rewrite')

    def test_receipts_denied_after_revoke_archive_or_certificate_expiry(self):
        job = self.leased(); self.start(job); receipt = self.receipt(job)
        for values in ({'revoked': True}, {'revoked': True, 'archived_at': self.now}, {'certificate_expires_at': self.now}):
            with self.subTest(values=values):
                Device.objects.filter(pk=self.device.pk).update(**values)
                with self.assertRaises(PermissionError): self.service.accept_execution_receipt(self.identity, receipt, now=self.now+timedelta(seconds=180))
                Device.objects.filter(pk=self.device.pk).update(revoked=False, archived_at=None, certificate_expires_at=self.now+timedelta(days=1))

    def test_legacy_handoff_blocks_linked_ambiguity_but_not_unrelated_claims(self):
        from control.jobs import claim_job
        legacy = Device.objects.create(environment_id='synthetic-env', certificate_sha256='f'*64, wazuh_agent_id='901')
        reviewed = dict(paired_device_id=str(self.device.pk), legacy_device_id=str(legacy.pk))
        linked = Job.objects.create(device=legacy, release=self.release, execution_state='failed',
            not_before=self.now, expires_at=self.now+timedelta(seconds=120), collection_start=self.now, collection_end=self.now+timedelta(seconds=300))
        with self.assertRaises(ValueError): self.ownership.transfer_execution_ownership(self.owner,
            self.resource, 1, str(self.device.pk), reviewed, 'Handoff', evidence_refs=['fixture:review'])
        linked.collection_state='reconciled'; linked.save()
        self.ownership.transfer_execution_ownership(self.owner, self.resource, 1, str(self.device.pk), reviewed, 'Handoff', evidence_refs=['fixture:review'])
        with self.assertRaises(PermissionError): claim_job(legacy)
        other = Device.objects.create(environment_id='other', certificate_sha256='e'*64, wazuh_agent_id='999')
        self.assertIsNone(claim_job(other))
        self.ownership.transfer_execution_ownership(self.owner, self.resource, 2, str(legacy.pk), reviewed, 'Explicit rollback', evidence_refs=['fixture:review'])
        self.assertIsNone(claim_job(legacy))

    def test_admin_and_legacy_reconcile_cannot_bypass_v2_authority(self):
        from django.contrib.admin.sites import site
        from django.test import RequestFactory
        from control.jobs import reconcile_job
        request = RequestFactory().post('/admin/'); request.user=self.owner
        readonly = site._registry[Device].get_readonly_fields(request, self.device)
        for field in ('connection_kind','generation','certificate_sha256','environment_id','wazuh_agent_id','revoked'):
            self.assertIn(field, readonly)
        job = self.leased()
        with self.assertRaises(ValueError): reconcile_job(job.pk, self.owner)
        self.release.timeout_seconds=181
        with self.assertRaises(ValueError): site._registry[RunnerRelease].save_model(request, self.release, None, True)
