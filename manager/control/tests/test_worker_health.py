"""Worker liveness and source freshness are separate authorities."""
import importlib
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
import uuid
import threading
import time
import copy
import os
import subprocess
from types import SimpleNamespace
from django.test import SimpleTestCase
from contextlib import contextmanager
from django.core.management import call_command, CommandError
from accounts.tests.helpers import AccountsCase
from control.tests.test_execution_authority import ExecutionFixture
from control.execution_models import CollectionWorkerLease


class WorkerHealthTests(ExecutionFixture, AccountsCase):
    def setUp(self):
        super().setUp()
        self.health = importlib.import_module('control.worker_health')

    def test_execution_authority_requires_exact_rsa3072_for_health_and_collection(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from django.conf import settings
        from control.execution_collection import _public_key
        path = Path(settings.MANAGER_EXECUTION_SIGNING_KEY)
        path.chmod(0o600)
        # Only private connection resolution and the OS ACL boundary are injected;
        # actual key bytes, binding and release pins go through production validation.
        with patch.object(self.health, 'resolve_execution_connection', return_value=(object(), Path(self.temp.name))), \
                patch.object(self.health, 'read_windows_acl', return_value={'synthetic_acl_boundary': True}) as acl_reader, \
                patch.object(self.health, 'validate_windows_acl') as acl_validator:
            for bits in (3072, 4096):
                with self.subTest(bits=bits):
                    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
                    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                    if bits == 3072:
                        self.assertEqual(len(self.health._authority(self.connection)[2]), 1)
                        self.assertEqual(_public_key().key_size, 3072)
                    else:
                        with self.assertRaises(ValueError): self.health._authority(self.connection)
                        with self.assertRaises(ValueError): _public_key()
            if os.name == 'nt':
                acl_reader.assert_called_with(path)
                acl_validator.assert_called_with(acl_reader.return_value, directory=False)

    def test_native_acl_probe_failure_still_refuses_authority(self):
        if os.name != 'nt': self.skipTest('Windows ACL authority boundary')
        with patch.object(self.health, 'resolve_execution_connection', return_value=(object(), Path(self.temp.name))), \
                patch.object(self.health, 'read_windows_acl', side_effect=subprocess.TimeoutExpired('synthetic_acl_probe', 10)), \
                patch.object(self.health, 'validate_windows_acl') as validator:
            with self.assertRaises(subprocess.TimeoutExpired): self.health._authority(self.connection)
            validator.assert_not_called()

    def test_keepalive_does_not_refresh_source_success(self):
        from aegis_verify.connectors.wazuh.live import ProbeResult
        row = CollectionWorkerLease.objects.create(instance_id=uuid.uuid4(),connection_id=self.connection.connection_id,
            connection_revision=1,config_sha256=self.connection.config_sha256,
            output_root_fingerprint=self.connection.output_root_fingerprint,started_at=self.now,last_seen_at=self.now,
            health_code='healthy',source_probe_status='healthy',source_probe_succeeded_at=self.now)
        self.health.refresh_worker_health(row.pk,self.connection,now=self.now+timedelta(seconds=10),probe_result=None)
        row.refresh_from_db(); self.assertEqual(row.source_probe_succeeded_at,self.now)
        self.assertEqual(row.last_seen_at,self.now+timedelta(seconds=10))
        self.health.refresh_worker_health(row.pk,self.connection,now=self.now+timedelta(seconds=20),probe_result=ProbeResult(False,'source_unavailable'))
        row.refresh_from_db(); self.assertEqual(row.source_probe_status,'source_unavailable')
        self.assertEqual(row.source_probe_succeeded_at,self.now)

    def test_lease_cannot_switch_connection_revision(self):
        row = CollectionWorkerLease.objects.create(instance_id=uuid.uuid4(),connection_id=self.connection.connection_id,
            connection_revision=2,config_sha256=self.connection.config_sha256,output_root_fingerprint='b'*64,
            started_at=self.now,last_seen_at=self.now,health_code='healthy')
        with self.assertRaises(ValueError):
            self.health.refresh_worker_health(row.pk,self.connection,now=self.now,probe_result=None)

    def test_connection_registration_is_permission_revision_and_idle_guarded(self):
        module = importlib.import_module('control.execution_connections')
        with patch.object(module,'private_connection',return_value=(Path(self.connection.config_path),None,'a'*64)), patch.object(module,'validate_output_root',return_value=Path(self.temp.name)):
            with self.assertRaises(PermissionError):
                module.register_execution_connection(self.operator,expected_revision=None,config_path='private',output_root='private')
            first = module.register_execution_connection(self.owner,expected_revision=None,config_path='private',output_root='private')
            second = module.register_execution_connection(self.owner,connection_id=str(first.connection_id),expected_revision=1,config_path='private',output_root='private')
            self.assertEqual(second.revision,2); self.assertEqual(second.connection_id,first.connection_id)
            with self.assertRaises(Exception): module.register_execution_connection(self.owner,connection_id=str(first.connection_id),expected_revision=1,config_path='private',output_root='private')
            self.leased()
            with self.assertRaises(Exception): module.register_execution_connection(self.owner,expected_revision=None,config_path='private',output_root='private')

    def test_historical_blank_output_path_fails_closed(self):
        module = importlib.import_module('control.execution_connections')
        with self.assertRaises(ValueError): module.resolve_execution_connection(self.connection.connection_id,1)

    def test_connection_resolve_rechecks_exact_config_and_output_fingerprint(self):
        module=importlib.import_module('control.execution_connections')
        with patch.object(module,'private_connection',return_value=(Path(self.connection.config_path),object(),'a'*64)), patch.object(module,'validate_output_root',return_value=Path(self.temp.name)):
            row=module.register_execution_connection(self.owner,expected_revision=None,config_path='private',output_root='private')
            _, root=module.resolve_execution_connection(row.connection_id,1)
            self.assertEqual(root,Path(self.temp.name))
            with patch.object(module,'private_connection',return_value=(Path(self.connection.config_path),object(),'c'*64)):
                with self.assertRaisesMessage(ValueError,'invalid_private_execution_connection'):
                    module.resolve_execution_connection(row.connection_id,1)
            with patch.object(module,'validate_output_root',return_value=Path(self.temp.name)/'other'):
                with self.assertRaises(ValueError): module.resolve_execution_connection(row.connection_id,1)

    def test_all_reviewed_scopes_must_probe_and_over_budget_round_cannot_publish_success(self):
        from control.collection import WazuhConnection
        from aegis_verify.connectors.wazuh.live import ProbeResult
        connection=WazuhConnection('https://indexer.example.test','synthetic-reader','synthetic-test',None,'wazuh-alerts-*')
        first=copy.copy(self.binding); first.approved_environment_id='synthetic-A'
        second=copy.copy(self.binding); second.pk=first.pk+1; second.wazuh_agent_id='902'; second.approved_environment_id='synthetic-B'
        scopes=[first,second]
        seen=[]
        def probe(cfg,**kwargs):
            seen.append((cfg.agent_id,cfg.environment_id,cfg.start,cfg.end))
            return ProbeResult(True,'healthy')
        with patch.object(self.health,'_authority',return_value=(connection,None,scopes)),patch.object(self.health,'_scopes',return_value=scopes),patch.object(self.health,'probe',side_effect=probe):
            self.assertTrue(self.health.probe_connection(self.connection,now=self.now,clock=lambda:0).healthy)
            self.assertEqual([(v[0],v[1]) for v in seen],[('901','synthetic-A'),('902','synthetic-B')])
            self.assertEqual(seen[0][2],(self.now-timedelta(seconds=60)).strftime('%Y-%m-%dT%H:%M:%SZ'))
            with patch.object(self.health,'_scopes',return_value=[]):
                self.assertFalse(self.health.probe_connection(self.connection,now=self.now,clock=lambda:0).healthy)
            times=iter([0,0,0,51])
            self.assertFalse(self.health.probe_connection(self.connection,now=self.now,clock=lambda:next(times)).healthy)

    def test_v2_command_passes_registration_identity_and_never_falls_back(self):
        from control.management.commands import manager_worker as command
        from control import execution_connections
        captured=[]
        @contextmanager
        def health(row):
            self.assertEqual(row.pk,self.connection.pk)
            yield SimpleNamespace(stop=threading.Event())
        def unavailable(connection,root,**kwargs):
            captured.append(kwargs)
            raise TypeError('synthetic dispatcher not yet available')
        with patch.object(command,'validate_output_root',return_value=Path(self.temp.name)), patch.object(command,'worker_lock',return_value=__import__('contextlib').nullcontext()), patch.object(execution_connections,'resolve_execution_connection',return_value=(object(),Path(self.temp.name))), patch.object(self.health,'execution_worker_health',side_effect=health),patch.object(command,'process_one',side_effect=unavailable):
            with self.assertRaisesMessage(CommandError,'collection_worker_unavailable'):
                call_command('manager_worker',execution_connection=str(self.connection.connection_id),execution_revision=1,output_root=self.temp.name,once=True)
            self.assertEqual(len(captured),1)
            self.assertEqual(captured[0]['execution_connection'].pk,self.connection.pk)
            with self.assertRaisesMessage(CommandError,'invalid_private_worker_configuration'):
                call_command('manager_worker',config='synthetic-private',execution_connection=str(self.connection.connection_id),execution_revision=1,output_root=self.temp.name,once=True)


class WorkerIndependentLoopTests(SimpleTestCase):
    def test_blocked_source_does_not_stop_keepalive_or_reclaim_jobs(self):
        module=importlib.import_module('control.worker_health')
        entered,release,refreshed=threading.Event(),threading.Event(),threading.Event()
        ticks=[]
        def blocked(connection):
            entered.set(); release.wait(2)
            from aegis_verify.connectors.wazuh.live import ProbeResult
            return ProbeResult(False,'source_unavailable')
        def refresh(*args,**kwargs):
            if kwargs['probe_result'] is None:
                ticks.append(time.monotonic())
                if len(ticks)>=3: refreshed.set()
        connection=SimpleNamespace(connection_id=uuid.uuid4(),revision=1,config_sha256='a'*64,output_root_fingerprint='b'*64)
        worker=module.WorkerHealth(connection,keepalive_interval=.02)
        with patch.object(module,'_authority'), patch.object(module,'probe_connection',side_effect=blocked), patch.object(module,'refresh_worker_health',side_effect=refresh), patch.object(module.CollectionWorkerLease.objects,'create'), patch.object(module,'close_old_connections'):
            try:
                worker.start(); self.assertTrue(entered.wait(1)); self.assertTrue(refreshed.wait(1))
                self.assertFalse(release.is_set()); self.assertGreaterEqual(len(ticks),3)
                self.assertLess(max(b-a for a,b in zip(ticks,ticks[1:])),.5)
            finally:
                worker.stop.set(); release.set()
                for thread in worker.threads: thread.join(2)
