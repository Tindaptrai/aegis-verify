from datetime import timedelta
from django.test import TestCase
from django.utils import timezone
from control.models import Device, Job, RunnerRelease
from .test_execution_contracts import DIGEST, UUID, snapshot_data, raw


class ExecutionModelTests(TestCase):
    def test_binding_release_and_connection_revisions_reject_rewrite(self):
        from django.contrib.auth import get_user_model
        from django.db import IntegrityError, transaction
        from control.execution_models import DeviceExecutionBinding, RegisteredExecutionConnection, BindingAdmissionAudit
        from control.execution_contracts import decode_contract, canonical_bytes
        import hashlib
        owner = get_user_model().objects.create_superuser('synthetic-owner')
        device = Device.objects.create(environment_id='synthetic-env', certificate_sha256=DIGEST)
        release = RunnerRelease.objects.create(scenario_path='scenario', profile_path='profile',
            scenario_sha256=DIGEST, profile_sha256=DIGEST, runner_sha256=DIGEST, kit_sha256=DIGEST, payload_sha256=DIGEST)
        definition = {k: v for k, v in snapshot_data()['release'].items() if k not in ('parameters', 'release_sha256')}
        frozen = canonical_bytes(decode_contract('ReleaseDefinition', raw(definition)))
        values = dict(binding_id=UUID, revision=1, device=device, approved_device_id=device.pk,
            approved_generation=1, approved_certificate_sha256=DIGEST, approved_environment_id='synthetic-env',
            release=release, release_bytes=frozen, release_sha256=hashlib.sha256(frozen).hexdigest(),
            installation_profile_sha256=DIGEST, artifact_set_sha256=DIGEST,
            connection_id=UUID, connection_revision=1, wazuh_agent_id='901', reviewed_by=owner)
        binding = DeviceExecutionBinding.objects.create(**values)
        with self.assertRaises(ValueError): DeviceExecutionBinding.objects.filter(pk=binding.pk).update(release_bytes=b'changed')
        binding.release_bytes = b'changed'
        with self.assertRaises(ValueError): binding.save()
        binding.set_enabled(False, owner)
        self.assertFalse(DeviceExecutionBinding.objects.get(pk=binding.pk).enabled)
        self.assertEqual(BindingAdmissionAudit.objects.get(binding=binding).actor_id, owner.pk)
        with self.assertRaises(ValueError): DeviceExecutionBinding.objects.filter(pk=binding.pk).update(enabled=True)
        with self.assertRaises(IntegrityError), transaction.atomic():
            DeviceExecutionBinding.objects.create(**(values | {'binding_id': 'b1111111-1111-4111-8111-111111111111'}))
        connection = RegisteredExecutionConnection.objects.create(connection_id=UUID, revision=1,
            config_path='private/config', config_sha256=DIGEST, output_root_fingerprint=DIGEST, reviewed_by=owner)
        connection.config_sha256 = 'b' * 64
        with self.assertRaises(ValueError): connection.save()
        with self.assertRaises(ValueError): RegisteredExecutionConnection.objects.filter(pk=connection.pk).update(config_path='changed')
        with self.assertRaises(ValueError): RegisteredExecutionConnection.objects.create(connection_id=UUID, revision=0,
            config_path='private/config', config_sha256=DIGEST, output_root_fingerprint=DIGEST, reviewed_by=owner)

    def test_ownership_revision_is_monotonic_and_audited(self):
        from django.contrib.auth import get_user_model
        from control.execution_models import ExecutionTargetOwnership, ExecutionOwnershipAudit
        owner = get_user_model().objects.create_superuser('synthetic-owner')
        target = ExecutionTargetOwnership.objects.create(connection_id=UUID, environment_id='synthetic-env',
            wazuh_agent_id='901', reviewed_paired_device_id=UUID, active_executor_id=UUID)
        with self.assertRaises(ValueError): ExecutionTargetOwnership.objects.filter(pk=target.pk).update(active_executor_id='b1111111-1111-4111-8111-111111111111')
        target.revision = 0
        with self.assertRaises(ValueError): target.save()
        target.refresh_from_db()
        target.record_transfer(actor=owner, expected_revision=1, reviewed_legacy_device_id=None,
            reviewed_paired_device_id=UUID, active_executor_id=UUID)
        self.assertEqual(target.revision, 2)
        self.assertEqual(ExecutionOwnershipAudit.objects.get(ownership=target).revision, 2)
        with self.assertRaises(ValueError): target.record_transfer(actor=owner, expected_revision=1,
            reviewed_legacy_device_id=None, reviewed_paired_device_id=UUID, active_executor_id=UUID)

    def test_admin_cannot_write_execution_authority_on_draft_jobs(self):
        from django.contrib.admin.sites import site
        from django.test import RequestFactory
        from django.contrib.auth import get_user_model
        from control.execution_models import JobApprovalSnapshot
        request = RequestFactory().get('/admin/')
        request.user = get_user_model().objects.create_superuser('synthetic-owner')
        self.assertFalse(site._registry[JobApprovalSnapshot].has_add_permission(request))
        self.assertFalse(site._registry[JobApprovalSnapshot].has_change_permission(request))
        for name in ('protocol_family', 'approval_snapshot', 'binding', 'preview', 'job_sha256', 'start_request_id', 'terminal_receipt_id'):
            self.assertIn(name, site._registry[Job].get_readonly_fields(request))

    def test_job_frozen_bytes_cannot_be_rewritten_by_save_or_queryset(self):
        from control.execution_models import JobApprovalSnapshot
        from control.execution_contracts import decode_contract, snapshot_bytes
        import hashlib
        device = Device.objects.create(environment_id='synthetic-env', certificate_sha256=DIGEST)
        release = RunnerRelease.objects.create(scenario_path='scenario', profile_path='profile',
            scenario_sha256=DIGEST, profile_sha256=DIGEST, runner_sha256=DIGEST, kit_sha256=DIGEST, payload_sha256=DIGEST)
        data = snapshot_bytes(decode_contract('JobApprovalSnapshotData', raw(snapshot_data())))
        snapshot = JobApprovalSnapshot.objects.create(snapshot_bytes=data, snapshot_sha256=hashlib.sha256(data).hexdigest())
        now = timezone.now()
        job = Job.objects.create(device=device, release=release, protocol_family='windows_execution_v2',
            approval_snapshot=snapshot, envelope_bytes=b'original', signed_payload_bytes=b'payload',
            not_before=now, expires_at=now, collection_start=now, collection_end=now)
        with self.assertRaises(ValueError): Job.objects.filter(pk=job.pk).update(envelope_bytes=b'changed')
        job.envelope_bytes = b'changed'
        with self.assertRaises(ValueError): job.save()
        with self.assertRaises(ValueError): Job.objects.bulk_update([job], ['envelope_bytes'])
        with self.assertRaises(ValueError): Job.objects.bulk_create([job], update_conflicts=True,
            update_fields=['envelope_bytes'], unique_fields=['id'])
        self.assertEqual(bytes(Job.objects.get(pk=job.pk).envelope_bytes), b'original')

    def test_snapshot_is_immutable(self):
        from control.execution_models import JobApprovalSnapshot, DeviceExecutionBinding, RegisteredExecutionConnection
        from control.execution_contracts import decode_contract, snapshot_bytes
        data = snapshot_bytes(decode_contract('JobApprovalSnapshotData', raw(snapshot_data())))
        snapshot = JobApprovalSnapshot.objects.create(snapshot_bytes=data, snapshot_sha256=__import__('hashlib').sha256(data).hexdigest())
        snapshot.snapshot_bytes = b'changed'
        with self.assertRaises(ValueError): snapshot.save()
        with self.assertRaises(ValueError): JobApprovalSnapshot.objects.filter(pk=snapshot.pk).update(snapshot_bytes=b'changed')
        with self.assertRaises(ValueError): JobApprovalSnapshot.objects.filter(pk=snapshot.pk).delete()
        with self.assertRaises(ValueError): JobApprovalSnapshot.objects.bulk_update([snapshot], ['snapshot_bytes'])
        self.assertEqual(bytes(JobApprovalSnapshot.objects.get(pk=snapshot.pk).snapshot_bytes), data)
        with self.assertRaises(ValueError): JobApprovalSnapshot.objects.create(snapshot_bytes=data, snapshot_sha256='b' * 64)

    def test_v1_rows_keep_null_snapshot(self):
        device = Device.objects.create(environment_id='synthetic-env', certificate_sha256=DIGEST)
        release = RunnerRelease.objects.create(scenario_path='scenario', profile_path='profile',
            scenario_sha256=DIGEST, profile_sha256=DIGEST, runner_sha256=DIGEST, kit_sha256=DIGEST, payload_sha256=DIGEST)
        now = timezone.now()
        job = Job.objects.create(device=device, release=release, not_before=now, expires_at=now + timedelta(seconds=120),
                                 collection_start=now, collection_end=now + timedelta(seconds=300))
        job.refresh_from_db()
        self.assertEqual(job.protocol_family, 'legacy_v1')
        self.assertIsNone(job.approval_snapshot_id)
        self.assertIsNone(job.binding_id)
        self.assertIsNone(job.envelope_bytes)
