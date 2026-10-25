"""Each server-owned readiness conjunct, using synthetic authority only."""
from dataclasses import replace
from datetime import timedelta
import importlib
import json
import uuid
from unittest.mock import patch
from accounts.tests.helpers import AccountsCase
from control.tests.test_execution_authority import ExecutionFixture
from control.execution_contracts import PROTOCOL, ReadinessRequest, canonical_bytes
from control.execution_models import LocalExecutionReadiness, CollectionWorkerLease, DeviceExecutionBinding
from control.models import Device, Job


class ExecutionReadinessTests(ExecutionFixture, AccountsCase):
    def setUp(self):
        super().setUp()
        self.module = importlib.import_module('control.execution_readiness')
        Device.objects.filter(pk=self.device.pk).update(agent_version='0.3.0', last_heartbeat_at=self.now)
        self.device.refresh_from_db()
        self.request = ReadinessRequest(protocol=PROTOCOL,device_id=str(self.device.pk),generation=1,
            binding_id=str(self.binding.binding_id),binding_revision=1,installation_profile_sha256=self.binding.installation_profile_sha256,
            artifact_set_sha256=self.binding.artifact_set_sha256,ready=True,blocking_codes=())
        self.module.record_local_readiness(self.identity, self.request, received_at=self.now)
        self.lease = CollectionWorkerLease.objects.create(instance_id=uuid.uuid4(),
            connection_id=self.connection.connection_id, connection_revision=1,
            config_sha256=self.connection.config_sha256, output_root_fingerprint=self.connection.output_root_fingerprint,
            started_at=self.now, last_seen_at=self.now, health_code='healthy',
            source_probe_status='healthy', source_probe_succeeded_at=self.now)
        self.resolver = patch('control.execution_readiness.resolve_execution_connection', return_value=(None, None))
        self.resolver.start(); self.addCleanup(self.resolver.stop)

    def dto(self, **kwargs): return self.module.execution_readiness(str(self.device.pk), now=self.now, **kwargs)
    def blocked(self, code):
        result = self.dto(); self.assertFalse(result.ready); self.assertIn(code, result.blocking_codes)

    def test_all_conjuncts_ready_and_public_projection_has_no_private_authority(self):
        result = self.dto(); self.assertTrue(result.ready)
        raw = canonical_bytes(result).decode()
        for secret in (self.connection.config_path, self.connection.config_sha256, 'output_root', 'config_path'):
            self.assertNotIn(secret, raw)

    def test_platform_version_environment_identity_and_presence_fail_separately(self):
        for field, value, code in [('os','linux','unsupported_platform'), ('architecture','arm64','unsupported_platform'),
            ('agent_version','0.2.0','upgrade_required'), ('environment_id','old.dot','environment_invalid'),
            ('revoked',True,'identity_unavailable'), ('last_heartbeat_at',self.now-timedelta(seconds=30,microseconds=1),'local_stale')]:
            old = getattr(self.device, field)
            Device.objects.filter(pk=self.device.pk).update(**{field:value})
            self.blocked(code)
            Device.objects.filter(pk=self.device.pk).update(**{field:old})
        self.device.refresh_from_db(); self.assertEqual(self.device.environment_id, 'synthetic-env')

    def test_local_report_binding_hash_and_clock_are_not_self_authorizing(self):
        for changes, code in [({'generation':2},'identity_unavailable'), ({'binding_revision':2},'profile_mismatch'),
            ({'installation_profile_sha256':'c'*64},'profile_mismatch'), ({'artifact_set_sha256':'d'*64},'artifact_mismatch'),
            ({'ready':False,'blocking_codes':['clock_uncertain']},'clock_uncertain'),
            ({'received_at':self.now-timedelta(seconds=30,microseconds=1)},'local_stale')]:
            row = LocalExecutionReadiness.objects.get(device=self.device)
            old = {k:getattr(row,k) for k in changes}
            LocalExecutionReadiness.objects.filter(pk=row.pk).update(**changes)
            self.blocked(code)
            LocalExecutionReadiness.objects.filter(pk=row.pk).update(**old)
        self.binding.set_enabled(False,self.owner); self.blocked('binding_disabled')

    def test_mapping_ownership_missing_grant_and_installer_success_cannot_enable(self):
        Device.objects.filter(pk=self.device.pk).update(wazuh_agent_id='other'); self.blocked('mapping_missing')
        Device.objects.filter(pk=self.device.pk).update(wazuh_agent_id='901')
        with patch('control.execution_readiness.guard_execution_owner', side_effect=ValueError('private')):
            self.blocked('ownership_conflict')
        LocalExecutionReadiness.objects.all().delete(); self.blocked('local_stale')
        DeviceExecutionBinding.objects.filter(pk=self.binding.pk).update(is_current=False); self.blocked('binding_missing')

    def test_exact_freshness_boundaries_and_wrong_connection_revision(self):
        Device.objects.filter(pk=self.device.pk).update(last_heartbeat_at=self.now-timedelta(seconds=30))
        LocalExecutionReadiness.objects.filter(device=self.device).update(received_at=self.now-timedelta(seconds=30))
        CollectionWorkerLease.objects.filter(pk=self.lease.pk).update(last_seen_at=self.now-timedelta(seconds=30), source_probe_succeeded_at=self.now-timedelta(seconds=60))
        self.assertTrue(self.dto().ready)
        CollectionWorkerLease.objects.filter(pk=self.lease.pk).update(source_probe_succeeded_at=self.now-timedelta(seconds=60,microseconds=1))
        self.blocked('source_unavailable')
        CollectionWorkerLease.objects.filter(pk=self.lease.pk).update(last_seen_at=self.now-timedelta(seconds=30,microseconds=1))
        self.blocked('worker_unavailable')
        CollectionWorkerLease.objects.filter(pk=self.lease.pk).update(last_seen_at=self.now, connection_revision=2)
        self.blocked('worker_unavailable')

    def test_only_same_approved_active_job_can_be_excluded(self):
        job = self.leased()
        self.blocked('busy')
        self.assertTrue(self.dto(active_job_id=str(job.pk)).ready)
        job.collection_state='failed'; job.save(update_fields=['collection_state'])
        self.blocked('reconciliation_required')
        self.assertFalse(self.dto(active_job_id=str(job.pk)).ready)

    def test_intake_binds_verified_identity_and_stores_exact_closed_report(self):
        ack = self.module.record_local_readiness(self.identity, self.request, received_at=self.now)
        self.assertTrue(ack.accepted)
        self.assertEqual(bytes(LocalExecutionReadiness.objects.get(device=self.device).report_bytes), canonical_bytes(self.request))
        with self.assertRaises(PermissionError):
            self.module.record_local_readiness(replace(self.identity, certificate_sha256='f'*64), self.request, received_at=self.now)
        with self.assertRaises(Exception):
            self.module.record_local_readiness(self.identity, replace(self.request,binding_revision=2), received_at=self.now)
