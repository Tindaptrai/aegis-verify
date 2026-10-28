"""Catalog races require real PostgreSQL sessions and observed blocking locks."""
import io
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connection, connections
from django.test import TransactionTestCase, override_settings

from accounts.models import AccountMutationLock
from accounts.services import update_product_user
from catalog.errors import CatalogError
from catalog.models import CatalogAudit, ScenarioPackageVersion
from catalog.services import import_package, publish_package, unpublish_package
from .helpers import build_sample, package_zip, sample_members


@skipUnless(connection.vendor == 'postgresql', 'Requires real PostgreSQL catalog row locks; SQLite is not concurrency coverage')
class PostgreSQLCatalogTests(TransactionTestCase):
    def setUp(self):
        AccountMutationLock.objects.get_or_create(pk=1)
        users = get_user_model().objects
        self.owner = users.create_superuser('synthetic-owner', password='synthetic-password')
        self.publisher = users.create_user('synthetic-publisher', password='synthetic-password')
        self.publisher.user_permissions.set(Permission.objects.filter(content_type__app_label='accounts', codename__in=('view', 'import_scenarios', 'publish_scenarios')))
        directory = tempfile.TemporaryDirectory(prefix='aegis-pg-catalog-')
        self.addCleanup(directory.cleanup)
        setting = override_settings(PRIVATE_ROOT=Path(directory.name))
        setting.enable()
        self.addCleanup(setting.disable)

    def ordered_race(self, first, second):
        locked, release, attempting = Event(), Event(), Event()
        pids = {}

        def worker(index, operation):
            connections.close_all()
            try:
                with connection.cursor() as cursor:
                    cursor.execute('SET statement_timeout = 15000')
                    cursor.execute('SELECT pg_backend_pid()')
                    pids[index] = cursor.fetchone()[0]
                intercepted = False

                def observe(execute, sql, params, many, context):
                    nonlocal intercepted
                    if not intercepted and 'accounts_accountmutationlock' in sql and 'FOR UPDATE' in sql:
                        intercepted = True
                        if index == 0:
                            result = execute(sql, params, many, context)
                            locked.set()
                            if not release.wait(15):
                                raise AssertionError('Catalog lock coordinator timed out')
                            return result
                        if not locked.wait(10):
                            raise AssertionError('First catalog lock never acquired')
                        attempting.set()
                    return execute(sql, params, many, context)

                with connection.execute_wrapper(observe):
                    try:
                        return operation()
                    except CatalogError as error:
                        return error.code
                    except PermissionError:
                        return 'permission_denied'
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            first_result, second_result = pool.submit(worker, 0, first), pool.submit(worker, 1, second)
            try:
                self.assertTrue(attempting.wait(10))
                deadline, blocked = time.monotonic() + 10, False
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute('SELECT pg_blocking_pids(%s)', [pids[1]])
                        blocked = pids[0] in cursor.fetchone()[0]
                    if blocked:
                        break
                    time.sleep(.01)
                self.assertTrue(blocked, 'Second real transaction must wait on catalog authority lock')
            finally:
                release.set()
            results = [first_result.result(timeout=20), second_result.result(timeout=20)]
        self.assertNotEqual(pids[0], pids[1])
        return results

    def import_sample(self, raw=None):
        row, created = import_package(actor=self.publisher, stream=io.BytesIO(build_sample() if raw is None else raw))
        return 'created' if created else 'existing'

    def demote(self):
        update_product_user(actor=self.owner, user_id=self.publisher.pk, display_name='Synthetic', capabilities=('view',), active=True)
        return 'demoted'

    def test_identical_concurrent_import_creates_one_row_and_one_audit(self):
        self.assertEqual(self.ordered_race(self.import_sample, self.import_sample), ['created', 'existing'])
        self.assertEqual(ScenarioPackageVersion.objects.count(), 1)
        self.assertEqual(CatalogAudit.objects.count(), 1)

    def test_conflicting_import_cannot_replace_winning_version(self):
        changed = package_zip(dict(reversed(list(sample_members().items()))))
        self.assertEqual(self.ordered_race(self.import_sample, lambda: self.import_sample(changed)), ['created', 'version_conflict'])
        self.assertEqual(ScenarioPackageVersion.objects.count(), 1)

    def test_demotion_wins_then_import_is_denied(self):
        self.assertEqual(self.ordered_race(self.demote, self.import_sample), ['demoted', 'permission_denied'])
        self.assertEqual(ScenarioPackageVersion.objects.count(), 0)

    def test_import_wins_then_demotion_preserves_authorized_history(self):
        self.assertEqual(self.ordered_race(self.import_sample, self.demote), ['created', 'demoted'])
        self.assertEqual(ScenarioPackageVersion.objects.count(), 1)

    def test_concurrent_publish_is_idempotent(self):
        self.import_sample()
        row = ScenarioPackageVersion.objects.get()
        def publish():
            return publish_package(actor=self.publisher, package_id=row.pk, sha256=row.sha256).status
        self.assertEqual(self.ordered_race(publish, publish), ['published', 'published'])
        self.assertEqual(CatalogAudit.objects.filter(action='published').count(), 1)

    def test_demotion_wins_then_publish_is_denied(self):
        self.import_sample()
        row = ScenarioPackageVersion.objects.get()
        publish = lambda: publish_package(actor=self.publisher, package_id=row.pk, sha256=row.sha256).status
        self.assertEqual(self.ordered_race(self.demote, publish), ['demoted', 'permission_denied'])
        row.refresh_from_db()
        self.assertEqual(row.status, 'draft')
