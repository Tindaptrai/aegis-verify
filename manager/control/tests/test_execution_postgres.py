"""Real row-lock races; SQLite cannot satisfy this verification gate."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Barrier, Event
from unittest import skipUnless
from unittest.mock import patch
import uuid

from django.contrib.auth.models import Group,Permission
from django.db import connection,connections
from django.test import TransactionTestCase,override_settings
from accounts.models import AccountMutationLock
from accounts.permissions import PRESETS,PRESET_GROUP_NAMES
from accounts.services import authority_mutation
from accounts.tests.helpers import AccountsCase
from control.models import Job,Device,AuditEntry
from control.execution_models import ExecutionIdempotency,ExecutionTargetOwnership
from .test_execution_authority import ExecutionFixture


@skipUnless(connection.vendor=='postgresql','Requires actual PostgreSQL row locks; SQLite skips are not race evidence')
class ExecutionPostgresTests(ExecutionFixture,TransactionTestCase):
    def setUp(self):
        AccountMutationLock.objects.get_or_create(pk=1)
        for role,name in PRESET_GROUP_NAMES.items():
            group,_=Group.objects.get_or_create(name=name)
            group.permissions.set(Permission.objects.filter(content_type__app_label='accounts',codename__in=PRESETS[role]))
        AccountsCase.setUpTestData.__func__(type(self))
        super().setUp()

    def race(self,first,second,*,table='control_dispatchlock',second_first=False):
        barrier=Barrier(2); second_finished=Event()
        def worker(index,operation):
            connections.close_all()
            reached=False
            try:
                with connection.cursor() as cursor:
                    cursor.execute('SET statement_timeout = 15000')
                    cursor.execute('SELECT pg_backend_pid()'); pid=cursor.fetchone()[0]
                def before_lock(execute,sql,params,many,context):
                    nonlocal reached
                    if not reached and table in sql and 'FOR UPDATE' in sql:
                        reached=True; barrier.wait(timeout=10)
                        if index==0 and second_first and not second_finished.wait(timeout=15):
                            raise AssertionError('Competing transaction did not finish')
                    return execute(sql,params,many,context)
                with connection.execute_wrapper(before_lock):
                    try: operation(); outcome='ok'
                    except (PermissionError,ValueError): outcome='denied'
                return pid,reached,outcome
            finally:
                if index==1: second_finished.set()
                connections.close_all()
        with patch('control.execution_services.execution_readiness',side_effect=self.ready):
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures=[executor.submit(worker,index,operation) for index,operation in enumerate((first,second))]
                results=[future.result(timeout=30) for future in futures]
        self.assertEqual(len({item[0] for item in results}),2)
        self.assertTrue(all(item[1] for item in results))
        return [item[2] for item in results]

    def test_two_approvals_same_key_return_one_job_and_audit(self):
        request=self.approval()
        operation=lambda:self.service.approve_execution(self.operator,request,now=self.now)
        # Both human operations first serialize on account authority.
        self.assertEqual(self.race(operation,operation,table='accounts_accountmutationlock'),['ok','ok'])
        self.assertEqual(Job.objects.count(),1)
        self.assertEqual(AuditEntry.objects.filter(action='approved').count(),1)

    def test_idempotency_collision_different_previews_has_one_winner(self):
        first=self.approval(); second=self.approval(key=first.idempotency_key)
        outcomes=self.race(lambda:self.service.approve_execution(self.operator,first,now=self.now),
            lambda:self.service.approve_execution(self.operator,second,now=self.now),table='accounts_accountmutationlock')
        self.assertCountEqual(outcomes,['ok','denied'])
        self.assertEqual(Job.objects.count(),1); self.assertEqual(ExecutionIdempotency.objects.count(),1)

    def test_start_cancel_serializes_one_winner(self):
        from control.execution_contracts import canonical_bytes
        from dataclasses import asdict
        job=self.leased()
        raw=canonical_bytes(asdict(self.poll)|dict(start_request_id=str(uuid.uuid4()),job_sha256=job.job_sha256))
        outcomes=self.race(lambda:self.service.authorize_execution_start(self.identity,str(job.pk),raw,now=self.now),
            lambda:self.service.cancel_execution(self.operator,str(job.pk)))
        self.assertCountEqual(outcomes,['ok','denied'])
        self.assertLessEqual(AuditEntry.objects.filter(job=job,action='start_authorized').count(),1)

    def test_revoke_committed_before_start_prevents_authorization(self):
        from control.execution_contracts import canonical_bytes
        from dataclasses import asdict
        from devices.services import revoke_device
        job=self.leased(); raw=canonical_bytes(asdict(self.poll)|dict(start_request_id=str(uuid.uuid4()),job_sha256=job.job_sha256))
        outcomes=self.race(lambda:self.service.authorize_execution_start(self.identity,str(job.pk),raw,now=self.now),
            lambda:revoke_device(actor=self.owner,device_id=self.device.pk),second_first=True)
        self.assertEqual(outcomes,['denied','ok'])
        self.assertIsNone(Job.objects.get(pk=job.pk).start_ack_bytes)

    def test_archive_committed_before_binding_change_cannot_be_reactivated(self):
        from devices.archive import archive_device
        outcomes=self.race(lambda:self.service.set_execution_binding(self.owner,str(self.device.pk),
            replace(self.binding_input,expected_revision=1,installation_profile_sha256='c'*64)),
            lambda:archive_device(actor=self.owner,device_id=self.device.pk),table='accounts_accountmutationlock',second_first=True)
        self.assertEqual(outcomes,['denied','ok'])
        self.assertIsNotNone(Device.objects.get(pk=self.device.pk).archived_at)

    def test_permission_removal_committed_before_approve_prevents_job(self):
        request=self.approval()
        def revoke_permission():
            with authority_mutation(actor=self.owner): self.operator.groups.clear()
        outcomes=self.race(lambda:self.service.approve_execution(self.operator,request,now=self.now),
            revoke_permission,table='accounts_accountmutationlock',second_first=True)
        self.assertEqual(outcomes,['denied','ok']); self.assertFalse(Job.objects.exists())

    def test_handoff_committed_before_legacy_claim_prevents_dispatch(self):
        from control.jobs import claim_job
        legacy=Device.objects.create(environment_id='synthetic-env',certificate_sha256='f'*64,wazuh_agent_id='901')
        reviewed=dict(paired_device_id=str(self.device.pk),legacy_device_id=str(legacy.pk))
        self.ownership.transfer_execution_ownership(self.owner,self.resource,1,str(legacy.pk),reviewed,'Reviewed rollback',evidence_refs=['fixture:review'])
        outcomes=self.race(lambda:claim_job(legacy),lambda:self.ownership.transfer_execution_ownership(self.owner,
            self.resource,2,str(self.device.pk),reviewed,'Reviewed handoff',evidence_refs=['fixture:review']),second_first=True)
        self.assertEqual(outcomes,['denied','ok'])
        self.assertEqual(ExecutionTargetOwnership.objects.get().active_executor_id,self.device.pk)

    def test_legacy_and_v2_approval_global_single_flight(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from pathlib import Path
        from control.jobs import approve_job
        legacy=Device.objects.create(environment_id='unrelated',certificate_sha256='f'*64,wazuh_agent_id='902')
        job=Job.objects.create(device=legacy,release=self.release,parameters={'run_label':'A','rule_revision':'baseline','rule_sha256':'e'*64},
            not_before=self.now,expires_at=self.now+timedelta(seconds=120),collection_start=self.now-timedelta(seconds=30),collection_end=self.now+timedelta(seconds=300))
        request=self.approval()
        key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
        path=Path(self.temp.name)/'legacy.pem'
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        with override_settings(MANAGER_SIGNING_KEY=str(path)):
            outcomes=self.race(lambda:approve_job(job.pk,self.operator),lambda:self.service.approve_execution(self.operator,request,now=self.now),table='accounts_accountmutationlock')
        self.assertCountEqual(outcomes,['ok','denied'])
        self.assertEqual(Job.objects.filter(execution_state='queued').count(),1)
