"""Actual PostgreSQL publication races; SQLite is not concurrency evidence."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest import skipUnless
import uuid
from django.contrib.auth.models import Group, Permission
from django.db import connection, connections
from django.test import TransactionTestCase, Client
from accounts.models import AccountMutationLock
from accounts.permissions import PRESETS, PRESET_GROUP_NAMES
from accounts.tests.helpers import AccountsCase
from .test_api import ConnectionsFixture


@skipUnless(connection.vendor == 'postgresql', 'Requires actual PostgreSQL row locks; SQLite is not race evidence')
class PostgresTests(ConnectionsFixture, TransactionTestCase):
    login_human = AccountsCase.login_human
    human_post = AccountsCase.human_post

    def setUp(self):
        AccountMutationLock.objects.get_or_create(pk=1)
        for role, name in PRESET_GROUP_NAMES.items():
            group, _ = Group.objects.get_or_create(name=name)
            group.permissions.set(Permission.objects.filter(content_type__app_label='accounts',codename__in=PRESETS[role]))
        AccountsCase.setUpTestData.__func__(type(self))
        super().setUp()

    def race(self, operations):
        barrier = Barrier(2)
        def execute(operation):
            connections.close_all()
            reached = False
            client = Client(enforce_csrf_checks=True)
            client.cookies = self.client.cookies.copy()
            def before_lock(execute, sql, params, many, context):
                nonlocal reached
                if not reached and 'accounts_accountmutationlock' in sql and 'FOR UPDATE' in sql:
                    reached = True
                    barrier.wait(timeout=10)
                return execute(sql,params,many,context)
            try:
                with connection.cursor() as cursor:
                    cursor.execute('SET statement_timeout = 15000')
                    cursor.execute('SELECT pg_backend_pid()')
                    pid = cursor.fetchone()[0]
                with connection.execute_wrapper(before_lock):
                    response = operation(client)
                return pid, reached, response.status_code
            finally:
                connections.close_all()
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(execute,operations))
        self.assertEqual(len({item[0] for item in results}),2)
        self.assertTrue(all(item[1] for item in results))
        return [item[2] for item in results]

    def test_same_draft_same_key_publishes_exactly_one_registration(self):
        from connections.models import ManagedSource, ConnectionAudit
        from control.execution_models import RegisteredExecutionConnection
        draft = self.make_draft()
        body = dict(draft_id=draft['draft_id'],idempotency_key=str(uuid.uuid4()))
        operation = lambda client:self.post('wazuh/save',body,client)
        self.assertCountEqual(self.race([operation,operation]),[201,200])
        self.assertEqual(ManagedSource.objects.count(),1)
        self.assertEqual(RegisteredExecutionConnection.objects.count(),1)
        self.assertEqual(ConnectionAudit.objects.filter(action='saved').count(),1)

    def test_candidate_compare_swap_has_one_winner(self):
        from connections.services import managed_candidate
        first = self.save(self.make_draft()).json()
        second = self.save(self.make_draft()).json()
        operations = [lambda client, source=source:self.post(source['id']+'/prepare',{'expected_candidate_id':None},client)
                      for source in (first,second)]
        self.assertCountEqual(self.race(operations),[200,409])
        self.assertIn(managed_candidate()['candidate_id'],[first['id'],second['id']])

    def test_competing_source_versions_have_one_winner(self):
        from connections.models import ManagedSource
        first = self.save(self.make_draft()).json()
        drafts = [self.make_draft(source_id=first['source_id'],expected_version=1) for _ in range(2)]
        operations = [lambda client, draft=draft:self.post('wazuh/save',dict(draft_id=draft['draft_id'],
            idempotency_key=str(uuid.uuid4())),client) for draft in drafts]
        self.assertCountEqual(self.race(operations),[201,409])
        self.assertEqual(ManagedSource.objects.count(),2)
