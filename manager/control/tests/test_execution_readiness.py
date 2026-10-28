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
        from control.worker_health import current_scope_sha256
        CollectionWorkerLease.objects.filter(pk=self.lease.pk).update(source_probe_scope_sha256=current_scope_sha256(self.connection))
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

    def test_old_success_cannot_cover_new_reviewed_profile_or_admission_reenable(self):
        from control import worker_health
        from control.execution_contracts import BindingInput
        from aegis_verify.connectors.wazuh.live import ProbeResult
        from control.collection import WazuhConnection
        connection=WazuhConnection('https://indexer.example.test','synthetic-reader','synthetic-test',None,'wazuh-alerts-*')
        def successful_round():
            with patch.object(worker_health,'_authority',return_value=(connection,None,[DeviceExecutionBinding.objects.get(device=self.device,is_current=True)])),patch.object(worker_health,'probe',return_value=ProbeResult(True,'healthy')):
                return worker_health.probe_connection(self.connection,now=self.now,clock=lambda:0)
        first=successful_round()
        worker_health.refresh_worker_health(self.lease.pk,self.connection,now=self.now,probe_result=first)
        self.assertTrue(self.dto().ready)
        # Same connection/source query, but a newly reviewed profile/grant scope.
        self.service.set_execution_binding(self.owner,str(self.device.pk),replace(self.binding_input,expected_revision=1,installation_profile_sha256='c'*64))
        self.binding=DeviceExecutionBinding.objects.get(device=self.device,is_current=True)
        self.request=replace(self.request,binding_revision=2,installation_profile_sha256='c'*64,artifact_set_sha256=self.binding.artifact_set_sha256)
        self.module.record_local_readiness(self.identity,self.request,received_at=self.now)
        self.blocked('source_unavailable')
        worker_health.refresh_worker_health(self.lease.pk,self.connection,now=self.now,probe_result=None)
        self.blocked('source_unavailable')
        second=successful_round()
        worker_health.refresh_worker_health(self.lease.pk,self.connection,now=self.now,probe_result=second)
        self.assertTrue(self.dto().ready)
        self.binding.set_enabled(False,self.owner)
        self.binding.set_enabled(True,self.owner)
        self.blocked('source_unavailable')
        worker_health.refresh_worker_health(self.lease.pk,self.connection,now=self.now,probe_result=None)
        self.blocked('source_unavailable')
        worker_health.refresh_worker_health(self.lease.pk,self.connection,now=self.now,probe_result=successful_round())
        self.assertTrue(self.dto().ready)

    def test_scope_mutation_after_round_compare_cannot_publish_success(self):
        from control import worker_health
        from aegis_verify.connectors.wazuh.live import ProbeResult
        from control.collection import WazuhConnection
        connection=WazuhConnection('https://indexer.example.test','synthetic-reader','synthetic-test',None,'wazuh-alerts-*')
        with patch.object(worker_health,'_authority',return_value=(connection,None,[self.binding])),patch.object(worker_health,'probe',return_value=ProbeResult(True,'healthy')):
            successful=worker_health.probe_connection(self.connection,now=self.now,clock=lambda:0)
        self.assertTrue(successful.healthy)
        # Change after the round's final comparison, before publication.
        self.binding.set_enabled(False,self.owner); self.binding.set_enabled(True,self.owner)
        from django.test.utils import CaptureQueriesContext
        from django.db import connection as database
        with CaptureQueriesContext(database) as queries:
            worker_health.refresh_worker_health(self.lease.pk,self.connection,now=self.now,probe_result=successful)
        sql=[query['sql'].lower() for query in queries]
        fence=next(i for i,text in enumerate(sql) if 'control_dispatchlock' in text)
        compare=next(i for i,text in enumerate(sql) if 'control_deviceexecutionbinding' in text)
        publish=next(i for i,text in enumerate(sql) if text.startswith('update "control_collectionworkerlease"'))
        self.assertLess(fence,compare); self.assertLess(compare,publish)
        self.blocked('source_unavailable')

    def test_new_source_scope_with_fresh_local_report_waits_for_all_scope_round(self):
        from control import worker_health
        from control.collection import WazuhConnection
        from aegis_verify.connectors.wazuh.live import ProbeResult
        connection=WazuhConnection('https://indexer.example.test','synthetic-reader','synthetic-test',None,'wazuh-alerts-*')
        def round_result(scopes):
            with patch.object(worker_health,'_authority',return_value=(connection,None,scopes)),patch.object(worker_health,'probe',return_value=ProbeResult(True,'healthy')) as probe:
                result=worker_health.probe_connection(self.connection,now=self.now,clock=lambda:0)
                seen=[call.args[0].agent_id for call in probe.call_args_list]
            return result,seen
        first,_=round_result([self.binding])
        worker_health.refresh_worker_health(self.lease.pk,self.connection,now=self.now,probe_result=first)
        self.assertTrue(self.dto().ready)
        new_device=Device.objects.create(connection_kind='paired_presence',environment_id='synthetic-env',
            certificate_sha256='9'*64,certificate_not_before=self.now-timedelta(days=1),
            certificate_expires_at=self.now+timedelta(days=1),os='windows',architecture='x64',
            agent_version='0.3.0',last_heartbeat_at=self.now)
        self.ownership.transfer_execution_ownership(self.owner,self.resource|dict(wazuh_agent_id='902'),None,
            str(new_device.pk),dict(paired_device_id=str(new_device.pk),legacy_device_id=None),
            'Reviewed new synthetic scope',evidence_refs=['fixture:scope-B'])
        self.service.set_execution_binding(self.owner,str(new_device.pk),replace(self.binding_input,wazuh_agent_id='902',installation_profile_sha256='c'*64))
        new_binding=DeviceExecutionBinding.objects.get(device=new_device,is_current=True)
        identity=self.service.ExecutionIdentity(str(new_device.pk),1,new_device.certificate_sha256)
        request=replace(self.request,device_id=str(new_device.pk),binding_id=str(new_binding.binding_id),installation_profile_sha256='c'*64)
        self.module.record_local_readiness(identity,request,received_at=self.now)
        dto=self.module.execution_readiness(str(new_device.pk),now=self.now)
        self.assertFalse(dto.ready); self.assertIn('source_unavailable',dto.blocking_codes)
        worker_health.refresh_worker_health(self.lease.pk,self.connection,now=self.now,probe_result=None)
        self.assertFalse(self.module.execution_readiness(str(new_device.pk),now=self.now).ready)
        current=list(DeviceExecutionBinding.objects.filter(is_current=True,enabled=True).order_by('pk'))
        result,seen=round_result(current)
        self.assertEqual(seen,['901','902'])
        worker_health.refresh_worker_health(self.lease.pk,self.connection,now=self.now,probe_result=result)
        self.assertTrue(self.module.execution_readiness(str(new_device.pk),now=self.now).ready)
