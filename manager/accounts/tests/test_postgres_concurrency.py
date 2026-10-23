"""Actual row-lock tests. SQLite skips do not verify serialization.

Each worker owns a database connection. An execute wrapper only places a
barrier immediately before the real singleton SELECT FOR UPDATE; it never
replaces database execution, policy checks, services, forms or Admin routes.
"""
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from threading import Barrier
from unittest import skipUnless

from django.contrib.admin.models import LogEntry
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.management import call_command
from django.db import connection, connections
from django.test import Client, TransactionTestCase
from django.urls import reverse

from accounts.errors import AccountError
from accounts.models import AccountMutationLock, AccountSecurity, AuthAudit
from accounts.permissions import CAPABILITIES, PRESETS, PRESET_GROUP_NAMES, effective_product_permissions
from accounts.services import update_product_user
from .test_admin import user_form


@skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL singleton row locks; SQLite does not satisfy this gate")
class PostgreSQLAuthorityTests(TransactionTestCase):
    def setUp(self):
        AccountMutationLock.objects.get_or_create(pk=1)
        for role, name in PRESET_GROUP_NAMES.items():
            group, _ = Group.objects.get_or_create(name=name)
            group.permissions.set(Permission.objects.filter(content_type__app_label="accounts", codename__in=PRESETS[role]))

    def administrators(self):
        users = get_user_model().objects
        self.first = users.create_user("synthetic-first", password="synthetic-password")
        self.second = users.create_user("synthetic-second", password="synthetic-password")
        group = Group.objects.get(name="AEGIS Administrators")
        self.first.groups.add(group)
        self.second.groups.add(group)
        self.technician = users.create_user("synthetic-technician", password="synthetic-password", is_staff=True)
        self.technician.user_permissions.set(Permission.objects.filter(content_type__app_label="auth"))

    def race(self, first, second):
        barrier = Barrier(2)

        def worker(operation):
            connections.close_all()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET statement_timeout = 15000")
                    cursor.execute("SELECT pg_backend_pid()")
                    backend_id = cursor.fetchone()[0]
                reached_lock = False

                def before_lock(execute, sql, params, many, context):
                    nonlocal reached_lock
                    if not reached_lock and "accounts_accountmutationlock" in sql and "FOR UPDATE" in sql:
                        reached_lock = True
                        barrier.wait(timeout=10)
                    return execute(sql, params, many, context)

                with connection.execute_wrapper(before_lock):
                    result = operation()
                return backend_id, reached_lock, result
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker, operation) for operation in (first, second)]
            results = [future.result(timeout=25) for future in futures]
        self.assertEqual(len({result[0] for result in results}), 2, "Workers must own distinct PostgreSQL connections")
        self.assertTrue(all(result[1] for result in results), "Both operations must reach the real singleton lock")
        return [result[2] for result in results]

    def demote_self(self, user_id):
        user = get_user_model().objects.get(pk=user_id)
        try:
            update_product_user(actor=user, user_id=user_id, display_name="Synthetic demoted",
                                capabilities=("view",), active=True)
            return "committed"
        except AccountError as error:
            return error.code

    def admin_post(self, route, data):
        client = Client()
        client.force_login(get_user_model().objects.get(pk=self.technician.pk))
        response = client.post(route, data)
        return "committed" if response.status_code == 302 else (response.status_code, response.content.decode())

    def assert_one_admin_and_one_audit(self, results):
        self.assertEqual(results.count("committed"), 1)
        rejected = next(result for result in results if result != "committed")
        self.assertIn(rejected, ["last_admin", (409, "last_admin")])
        usable = [user for user in get_user_model().objects.filter(is_active=True)
                  if user.has_usable_password() and effective_product_permissions(user) == set(CAPABILITIES)]
        self.assertEqual(len(usable), 1)
        self.assertEqual(AuthAudit.objects.count(), 1)

    def test_simultaneous_product_self_demotions_serialize_final_policy(self):
        self.administrators()
        results = self.race(lambda: self.demote_self(self.first.pk), lambda: self.demote_self(self.second.pk))
        self.assert_one_admin_and_one_audit(results)
        rejected_id = self.first.pk if results[0] != "committed" else self.second.pk
        self.assertEqual(AccountSecurity.objects.get(user_id=rejected_id).display_name, "")
        self.assertEqual(AuthAudit.objects.get().target_id, self.second.pk if rejected_id == self.first.pk else self.first.pk)

    def test_product_demotion_and_actual_admin_lock_share_transaction(self):
        self.administrators()
        route = reverse("admin:auth_user_change", args=[self.second.pk])
        data = user_form(self.second, is_active="")
        results = self.race(lambda: self.demote_self(self.first.pk), lambda: self.admin_post(route, data))
        self.assert_one_admin_and_one_audit(results)
        self.second.refresh_from_db()
        self.assertEqual(self.second.is_active, results[1] != "committed")
        self.assertEqual(AccountSecurity.objects.get(user=self.second).generation, 2 if results[1] == "committed" else 1)
        self.assertEqual(LogEntry.objects.count(), 1 if results[1] == "committed" else 0)

    def test_two_admin_outer_changeforms_serialize_user_m2m(self):
        self.administrators()
        first_route = reverse("admin:auth_user_change", args=[self.first.pk])
        second_route = reverse("admin:auth_user_change", args=[self.second.pk])
        first_data, second_data = user_form(self.first, groups=[]), user_form(self.second, groups=[])
        results = self.race(lambda: self.admin_post(first_route, first_data), lambda: self.admin_post(second_route, second_data))
        self.assert_one_admin_and_one_audit(results)
        self.assertEqual(LogEntry.objects.count(), 1)
        rejected_id = self.first.pk if results[0] != "committed" else self.second.pk
        self.assertEqual(set(get_user_model().objects.get(pk=rejected_id).groups.values_list("name", flat=True)), {"AEGIS Administrators"})

    def test_admin_password_disable_and_group_m2m_share_transaction(self):
        self.administrators()
        external = Group.objects.create(name="Synthetic external authority")
        external.permissions.set(Permission.objects.filter(content_type__app_label="accounts"))
        self.second.groups.set([external])
        first_hash = self.first.password
        password_route = reverse("admin:auth_user_password_change", args=[self.first.pk])
        group_route = reverse("admin:auth_group_change", args=[external.pk])
        results = self.race(
            lambda: self.admin_post(password_route, {"usable_password": "false", "unset-password": "1"}),
            lambda: self.admin_post(group_route, {"name": external.name, "permissions": [], "_save": "Save"}),
        )
        self.assert_one_admin_and_one_audit(results)
        self.assertEqual(LogEntry.objects.count(), 1)
        self.first.refresh_from_db()
        if results[0] == "committed":
            self.assertFalse(self.first.has_usable_password())
            self.assertEqual(external.permissions.count(), 8)
            self.assertEqual(AuthAudit.objects.get().action, "password_reset")
        else:
            self.assertEqual(self.first.password, first_hash)
            self.assertEqual(external.permissions.count(), 0)
            self.assertEqual(AuthAudit.objects.get().action, "group_updated")

    def test_simultaneous_explicit_bootstrap_creates_only_one_initial_account(self):
        def bootstrap():
            output = StringIO()
            call_command("bootstrap_manager_owner", new_install=True, stdout=output)
            return output.getvalue().strip()

        self.assertCountEqual(self.race(bootstrap, bootstrap), ["owner_created", "existing_users_unchanged"])
        user = get_user_model().objects.get()
        self.assertEqual(user.username, "aegis")
        self.assertTrue(user.check_password("aegis"))
        self.assertFalse(user.is_staff or user.is_superuser)
        self.assertEqual(effective_product_permissions(user), set(CAPABILITIES))
        self.assertEqual(AccountSecurity.objects.get(user=user).generation, 1)
