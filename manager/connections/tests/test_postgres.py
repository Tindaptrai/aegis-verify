"""Actual PostgreSQL publication races; SQLite is not concurrency evidence."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from unittest import skipUnless
import uuid
from django.db import connection, connections, transaction
from django.test import Client
from .test_api import ConnectionsTransactionCase


@skipUnless(connection.vendor == 'postgresql', 'Requires actual PostgreSQL row locks; SQLite is not race evidence')
class PostgresTests(ConnectionsTransactionCase):
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

    def authority_changed_during_io(self, change):
        """Distinct PostgreSQL sessions, committed revocation while probe waits.

        The network boundary is paused deterministically; PostgreSQL authority
        locking and session reads are real. This is not native TLS/lab evidence.
        """
        from connections.models import ConnectionDraft, ManagedSource, ConnectionAudit
        from control.execution_models import RegisteredExecutionConnection
        from control.execution_ownership import lock_human_authority
        self.client = self.login_human(self.admin)
        prior = self.make_draft()
        entered, release = Event(), Event()
        probe_pid = []

        def blocked_probe(**kwargs):
            self.assertFalse(connection.in_atomic_block)
            with connection.cursor() as cursor:
                cursor.execute('SELECT pg_backend_pid()')
                probe_pid.append(cursor.fetchone()[0])
            entered.set()
            if not release.wait(timeout=10):
                raise AssertionError('authority mutation did not release probe')

        self.probe.side_effect = blocked_probe
        client = Client(enforce_csrf_checks=True)
        client.cookies = self.client.cookies.copy()
        token = client.get('/api/v1/auth/session').json()['csrf_token']
        def request():
            connections.close_all()
            try:
                with connection.cursor() as cursor:
                    cursor.execute('SET statement_timeout = 15000')
                return client.post('/api/v1/connections/wazuh/test', self.data,
                    content_type='application/json', HTTP_X_CSRFTOKEN=token)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(request)
            try:
                self.assertTrue(entered.wait(timeout=10))
                with connection.cursor() as cursor:
                    cursor.execute('SET statement_timeout = 5000')
                    cursor.execute('SELECT pg_backend_pid()')
                    mutation_pid = cursor.fetchone()[0]
                with transaction.atomic():
                    lock_human_authority()
                    change()
            finally:
                release.set()
                with connection.cursor() as cursor:
                    cursor.execute('SET statement_timeout = 0')
            response = pending.result(timeout=20)
        self.assertEqual(len(probe_pid), 1)
        self.assertNotEqual(probe_pid[0], mutation_pid)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {'error': {'code': 'permission_denied'}})
        self.assertEqual(ConnectionDraft.objects.filter(state='failed').count(), 1)
        self.assertEqual(set(self.files), {prior['draft_id']})
        # Neither the previously tested draft nor the interrupted one can be
        # saved by the now-stale session. Use the original cookie and CSRF token.
        for draft in ConnectionDraft.objects.all():
            response = self.client.post('/api/v1/connections/wazuh/save',
                dict(draft_id=str(draft.pk), idempotency_key=str(uuid.uuid4())),
                content_type='application/json', HTTP_X_CSRFTOKEN=token)
            self.assertIn(response.status_code, (401, 403))
        self.assertFalse(ManagedSource.objects.exists())
        self.assertFalse(RegisteredExecutionConnection.objects.exists())
        self.assertFalse(ConnectionAudit.objects.filter(action='saved').exists())

    def test_generation_rotation_during_io_blocks_test_and_save(self):
        from accounts.models import AccountSecurity
        from django.db.models import F
        self.authority_changed_during_io(lambda: AccountSecurity.objects.filter(user=self.admin)
                                        .update(generation=F('generation')+1))

    def test_session_rotation_during_io_blocks_test_and_save(self):
        from django.contrib.sessions.backends.db import SessionStore
        def rotate():
            session = SessionStore(session_key=self.client.session.session_key)
            session.cycle_key()
        self.authority_changed_during_io(rotate)

    def test_permission_revocation_during_io_blocks_test_and_save(self):
        self.authority_changed_during_io(lambda: self.admin.groups.clear())
