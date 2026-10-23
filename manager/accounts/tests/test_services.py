import json

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission

from accounts.errors import AccountError
from accounts.models import AccountSecurity, AuthAudit
from accounts.permissions import CAPABILITIES, effective_product_permissions
from accounts.services import create_product_user, reset_product_password, update_product_user
from .helpers import AccountsCase


class ProductMutationTests(AccountsCase):
    def create(self, **changes):
        values = dict(actor=self.admin, username="synthetic-new", display_name="Synthetic User",
                      password="synthetic-password", capabilities=("view",), active=True)
        values.update(changes)
        return create_product_user(**values)

    def update(self, user=None, **changes):
        user = user or self.viewer
        values = dict(actor=self.admin, user_id=user.pk, display_name="Updated",
                      capabilities=("view",), active=True)
        values.update(changes)
        return update_product_user(**values)

    def assert_error(self, code, status, operation):
        before = AuthAudit.objects.count()
        with self.assertRaises(AccountError) as error:
            operation()
        self.assertEqual((error.exception.code, error.exception.status), (code, status))
        self.assertEqual(AuthAudit.objects.count(), before)

    def test_create_uses_django_hashing_and_security_display_name(self):
        user = self.create()
        self.assertTrue(user.check_password("synthetic-password"))
        self.assertNotEqual(user.password, "synthetic-password")
        self.assertEqual(user.account_security.display_name, "Synthetic User")
        self.assertFalse(user.is_staff or user.is_superuser)
        self.assertEqual(set(user.groups.values_list("name", flat=True)), {"AEGIS Viewers"})
        audit = AuthAudit.objects.get()
        self.assertEqual((audit.action, audit.actor_id, audit.target_id), ("user_created", self.admin.pk, user.pk))
        encoded = json.dumps([audit.before, audit.after])
        self.assertNotIn("synthetic-password", encoded)
        self.assertNotIn(user.password, encoded)

    def test_inactive_creation_audits_assigned_preset_grants(self):
        user = self.create(active=False, capabilities=("view", "run_jobs", "export_evidence"))
        self.assertEqual(AuthAudit.objects.get().after["capabilities"], ["export_evidence", "run_jobs", "view"])
        self.assertEqual(effective_product_permissions(user), set())

    def test_inactive_grant_update_audits_retained_and_external_grants(self):
        external = Group.objects.create(name="Synthetic locked audit inheritance")
        external.permissions.add(Permission.objects.get(content_type__app_label="accounts", codename="export_evidence"))
        self.viewer.groups.add(external)
        self.viewer.is_active = False
        self.viewer.save(update_fields=["is_active"])
        self.update(capabilities=("view", "run_jobs", "export_evidence"), active=False)
        audit = AuthAudit.objects.get()
        self.assertEqual(audit.before["capabilities"], ["export_evidence", "view"])
        self.assertEqual(audit.after["capabilities"], ["export_evidence", "run_jobs", "view"])
        self.assertFalse(audit.before["is_active"] or audit.after["is_active"])
        self.assertEqual(effective_product_permissions(self.viewer), set())
        self.update(capabilities=("view", "manage_devices", "export_evidence"), active=False)
        audit = AuthAudit.objects.latest("pk")
        self.assertEqual(audit.before["capabilities"], ["export_evidence", "run_jobs", "view"])
        self.assertEqual(audit.after["capabilities"], ["export_evidence", "manage_devices", "view"])
        self.assertEqual(set(self.viewer.groups.values_list("name", flat=True)), {external.name})

    def test_presets_and_custom_effective_union_preserve_unrelated_authority(self):
        unrelated = Permission.objects.get(codename="change_group")
        external = Group.objects.create(name="Synthetic inherited")
        external.permissions.add(Permission.objects.get(content_type__app_label="accounts", codename="export_evidence"))
        for grants, expected_group in [(("view",), "AEGIS Viewers"),
                                        (("view", "run_jobs", "export_evidence"), "AEGIS Operators"),
                                        (CAPABILITIES, "AEGIS Administrators")]:
            user = self.create(username="synthetic-" + expected_group.split()[-1], capabilities=grants)
            self.assertEqual(set(user.groups.values_list("name", flat=True)), {expected_group})
        self.operator.groups.add(external)
        self.operator.user_permissions.add(unrelated)
        self.update(self.operator, capabilities=("view", "export_evidence", "manage_devices"))
        self.assertEqual(effective_product_permissions(self.operator), {"view", "export_evidence", "manage_devices"})
        self.assertEqual(set(self.operator.groups.values_list("name", flat=True)), {"Synthetic inherited"})
        self.assertEqual(set(self.operator.user_permissions.values_list("codename", flat=True)), {"view", "manage_devices", "change_group"})
        self.update(self.operator, capabilities=("view", "run_jobs", "export_evidence"))
        self.assertEqual(set(self.operator.groups.values_list("name", flat=True)), {"Synthetic inherited", "AEGIS Operators"})
        self.assertEqual(set(self.operator.user_permissions.values_list("codename", flat=True)), {"change_group"})

    def test_inherited_grants_cannot_be_removed(self):
        external = Group.objects.create(name="Synthetic external")
        external.permissions.add(Permission.objects.get(content_type__app_label="accounts", codename="run_jobs"))
        self.viewer.groups.add(external)
        self.assert_error("inherited_capabilities_required", 409, lambda: self.update())
        self.assertEqual(effective_product_permissions(self.viewer), {"view", "run_jobs"})

    def test_locked_account_inherited_grants_are_still_immutable(self):
        external = Group.objects.create(name="Synthetic locked inheritance")
        external.permissions.add(Permission.objects.get(content_type__app_label="accounts", codename="run_jobs"))
        self.viewer.groups.add(external)
        self.viewer.is_active = False
        self.viewer.save()
        self.assert_error("inherited_capabilities_required", 409, lambda: self.update(active=True))
        self.viewer.refresh_from_db()
        self.assertFalse(self.viewer.is_active)

    def test_invalid_capabilities_and_view_prerequisite(self):
        for grants, code in [(("view", "view"), "invalid_capabilities"), (("unknown",), "invalid_capabilities"),
                             (("run_jobs",), "view_required"), ("view", "invalid_capabilities"), ((1,), "invalid_capabilities")]:
            with self.subTest(grants=grants):
                self.assert_error(code, 400, lambda: self.create(capabilities=grants))

    def test_username_normalization_validation_duplicate_and_immutability(self):
        user = self.create(username="synthetic-\uff41")
        self.assertEqual(user.username, "synthetic-a")
        self.assert_error("username_exists", 409, lambda: self.create(username="synthetic-a"))
        self.assert_error("invalid_username", 400, lambda: self.create(username="bad name"))
        self.assert_error("invalid_username", 400, lambda: self.create(username="x" * 151))
        self.assert_error("invalid_request", 400, lambda: self.update(username="changed"))
        self.viewer.refresh_from_db()
        self.assertEqual(self.viewer.username, "viewer")

    def test_privilege_fields_and_wrong_types_are_rejected(self):
        for values in [dict(is_staff=True), dict(is_superuser=True), dict(active=1), dict(display_name=1), dict(display_name="x" * 151)]:
            with self.subTest(values=values):
                code = "invalid_display_name" if "display_name" in values else "invalid_request"
                self.assert_error(code, 400, lambda: self.create(**values))

    def test_password_bounds_and_reset_no_sensitive_audit(self):
        for password in ["short", "x" * 1025, None]:
            self.assert_error("invalid_password", 400, lambda: self.create(password=password))
            self.assert_error("invalid_password", 400, lambda: reset_product_password(actor=self.admin, user_id=self.viewer.pk, new_password=password))
        reset_product_password(actor=self.admin, user_id=self.viewer.pk, new_password="synthetic-reset")
        self.viewer.refresh_from_db()
        self.assertTrue(self.viewer.check_password("synthetic-reset"))
        audit = AuthAudit.objects.get(action="password_reset")
        encoded = json.dumps([audit.before, audit.after])
        self.assertNotIn("synthetic-reset", encoded)
        self.assertNotIn(self.viewer.password, encoded)
        user = self.create(password="x" * 1024)
        self.assertTrue(user.check_password("x" * 1024))

    def test_password_rejection_never_echoes_supplied_values(self):
        for password in ("tiny", "synthetic-private-" * 100):
            with self.assertRaises(AccountError) as error:
                self.create(password=password)
            self.assertEqual(str(error.exception), "invalid_password")
            self.assertNotIn(password, str(error.exception))

    def test_existing_short_password_is_preserved_when_updating_grants(self):
        self.viewer.set_password("old")
        self.viewer.save()
        before = self.viewer.password
        self.update()
        self.viewer.refresh_from_db()
        self.assertEqual(self.viewer.password, before)

    def test_empty_capabilities_are_a_valid_custom_set(self):
        user = self.create(capabilities=())
        self.assertFalse(user.groups.exists())
        self.assertFalse(user.user_permissions.exists())
        self.assertEqual(effective_product_permissions(user), set())

    def test_edited_preset_cannot_grant_more_than_requested(self):
        group = Group.objects.get(name="AEGIS Viewers")
        group.permissions.set(Permission.objects.filter(content_type__app_label="accounts"))
        user = self.create()
        self.assertEqual(effective_product_permissions(user), {"view"})
        self.assertFalse(user.groups.exists())
        self.update(self.operator)
        self.assertEqual(effective_product_permissions(self.operator), {"view"})

    def test_edited_preset_cannot_grant_less_than_requested(self):
        group = Group.objects.get(name="AEGIS Operators")
        group.permissions.clear()
        user = self.create(capabilities=("view", "run_jobs", "export_evidence"))
        self.assertEqual(effective_product_permissions(user), {"view", "run_jobs", "export_evidence"})

    def test_edited_preset_cannot_introduce_technical_permissions(self):
        group = Group.objects.get(name="AEGIS Viewers")
        group.permissions.add(Permission.objects.get(codename="change_user"))
        user = self.create()
        self.assertEqual(effective_product_permissions(user), {"view"})
        self.assertFalse(user.has_perm("auth.change_user"))
        self.assertFalse(user.groups.exists())

    def test_product_admin_cannot_mutate_technical_accounts(self):
        for target in [self.owner, get_user_model().objects.create_user("synthetic-staff", password="synthetic-password", is_staff=True)]:
            before = target.password
            self.assert_error("technical_account_readonly", 403, lambda: reset_product_password(actor=self.admin, user_id=target.pk, new_password="synthetic-new-password"))
            self.assert_error("technical_account_readonly", 403, lambda: self.update(target))
            target.refresh_from_db()
            self.assertEqual(target.password, before)

    def test_lock_unlock_increments_generation_once_and_keeps_user(self):
        self.update(active=False)
        self.viewer.refresh_from_db()
        self.assertFalse(self.viewer.is_active)
        self.assertEqual(AccountSecurity.objects.get(user=self.viewer).generation, 2)
        self.update(active=False)
        self.update(active=True)
        self.assertEqual(AccountSecurity.objects.get(user=self.viewer).generation, 2)
        self.assertTrue(get_user_model().objects.filter(pk=self.viewer.pk).exists())

    def test_self_lock_rolls_back_generation_and_audit(self):
        self.assert_error("self_lock", 409, lambda: self.update(self.admin, capabilities=CAPABILITIES, active=False))
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)
        self.assertEqual(AccountSecurity.objects.get(user=self.admin).generation, 1)

    def test_last_usable_admin_demote_rolls_back_all_changes(self):
        self.owner.set_unusable_password()
        self.owner.save()
        self.assert_error("last_admin", 409, lambda: self.update(self.admin))
        self.assertEqual(effective_product_permissions(self.admin), set(CAPABILITIES))
        self.assertEqual(AccountSecurity.objects.get(user=self.admin).display_name, "")

    def test_loaded_actor_authority_is_reloaded(self):
        self.admin.get_all_permissions()
        self.admin.groups.clear()
        with self.assertRaises(PermissionError):
            self.create()
        self.assertFalse(get_user_model().objects.filter(username="synthetic-new").exists())
        self.admin.groups.add(Group.objects.get(name="AEGIS Administrators"))
        self.create()

    def test_unknown_target_and_malformed_identifier_are_fixed_errors(self):
        self.assert_error("user_not_found", 400, lambda: self.update(user_id=999999))
        self.assert_error("invalid_request", 400, lambda: self.update(user_id=True))
