from io import StringIO

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command, CommandError
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase

from accounts.models import AccountMutationLock, AccountSecurity
from accounts.permissions import effective_product_permissions


class BootstrapTests(TestCase):
    def bootstrap(self, **options):
        output = StringIO()
        call_command("bootstrap_manager_owner", stdout=output, **options)
        return output.getvalue().strip()

    def test_explicit_new_install_flag_is_required(self):
        with self.assertRaisesMessage(CommandError, "new_install_required"):
            self.bootstrap()
        self.assertFalse(get_user_model().objects.exists())

    def test_fresh_install_creates_hashed_product_admin_without_technical_flags(self):
        self.assertEqual(self.bootstrap(new_install=True), "owner_created")
        user = get_user_model().objects.get(username="aegis")
        self.assertTrue(user.check_password("aegis"))
        self.assertNotEqual(user.password, "aegis")
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertEqual(set(user.groups.values_list("name", flat=True)), {"AEGIS Administrators"})
        self.assertIn("manage_users", effective_product_permissions(user))
        self.assertTrue(AccountSecurity.objects.filter(user=user, generation=1).exists())

    def test_existing_user_and_repeated_bootstrap_never_reset_state(self):
        self.bootstrap(new_install=True)
        user = get_user_model().objects.get(username="aegis")
        user.set_password("synthetic-test-password")
        user.is_active = False
        user.save()
        user.groups.clear()
        snapshot = (user.password, user.is_active)
        self.assertEqual(self.bootstrap(new_install=True), "existing_users_unchanged")
        user.refresh_from_db()
        self.assertEqual((user.password, user.is_active), snapshot)
        self.assertFalse(user.groups.exists())
        self.assertEqual(get_user_model().objects.count(), 1)

    def test_any_existing_user_prevents_default_creation(self):
        user = get_user_model().objects.create_user("legacy", password="synthetic-test-password", is_staff=True)
        encoded = user.password
        self.assertEqual(self.bootstrap(new_install=True), "existing_users_unchanged")
        user.refresh_from_db()
        self.assertEqual(user.password, encoded)
        self.assertTrue(user.is_staff)
        self.assertFalse(get_user_model().objects.filter(username="aegis").exists())

    def test_missing_presets_abort_without_creating_user(self):
        Group.objects.filter(name="AEGIS Viewers").delete()
        with self.assertRaisesMessage(CommandError, "account_presets_not_migrated"):
            self.bootstrap(new_install=True)
        self.assertFalse(get_user_model().objects.exists())

    def test_modified_admin_preset_aborts_without_rewriting_group(self):
        group = Group.objects.get(name="AEGIS Administrators")
        group.permissions.clear()
        with self.assertRaisesMessage(CommandError, "account_presets_not_migrated"):
            self.bootstrap(new_install=True)
        self.assertFalse(get_user_model().objects.exists())
        self.assertFalse(group.permissions.exists())


class SeedMigrationTests(TransactionTestCase):
    migrate_to = [("accounts", "0001_initial")]

    def setUp(self):
        executor = MigrationExecutor(connection)
        executor.migrate([("accounts", None)])
        self.old_apps = executor.loader.project_state([("auth", "0012_alter_user_first_name_max_length")]).apps
        # A simulated first install starts without the previous test DB's seed.
        self.old_apps.get_model("auth", "Group").objects.filter(name__in=["AEGIS Administrators", "AEGIS Operators", "AEGIS Viewers"]).delete()

    def tearDown(self):
        self.old_apps.get_model("auth", "Group").objects.filter(name__in=["AEGIS Administrators", "AEGIS Operators", "AEGIS Viewers"]).delete()
        MigrationExecutor(connection).migrate(self.migrate_to)
        super().tearDown()

    def test_seed_preserves_existing_users_and_external_memberships(self):
        User = self.old_apps.get_model("auth", "User")
        GroupModel = self.old_apps.get_model("auth", "Group")
        group = GroupModel.objects.create(name="Synthetic legacy group")
        user = User.objects.create(username="legacy", password="synthetic-encoded-unchanged", is_staff=True, is_superuser=True, is_active=False)
        user.groups.add(group)
        MigrationExecutor(connection).migrate(self.migrate_to)
        user.refresh_from_db()
        self.assertEqual((user.password, user.is_staff, user.is_superuser, user.is_active), ("synthetic-encoded-unchanged", True, True, False))
        self.assertEqual(list(user.groups.values_list("name", flat=True)), ["Synthetic legacy group"])
        self.assertTrue(AccountSecurity.objects.filter(user_id=user.pk, generation=1).exists())
        self.assertTrue(AccountMutationLock.objects.filter(pk=1).exists())
        self.assertFalse(User.objects.filter(username="aegis").exists())

    def test_reserved_name_collision_aborts_without_granting_existing_members(self):
        User = self.old_apps.get_model("auth", "User")
        GroupModel = self.old_apps.get_model("auth", "Group")
        group = GroupModel.objects.create(name="AEGIS Operators")
        user = User.objects.create(username="legacy", password="synthetic-encoded-unchanged")
        user.groups.add(group)
        with self.assertRaisesMessage(RuntimeError, "reserved_account_group_exists"):
            MigrationExecutor(connection).migrate(self.migrate_to)
        self.assertEqual(GroupModel.objects.filter(name__startswith="AEGIS ").count(), 1)
        self.assertFalse(group.permissions.exists())
        self.assertEqual(list(user.groups.values_list("pk", flat=True)), [group.pk])
        self.assertNotIn("accounts_accountsecurity", connection.introspection.table_names())
