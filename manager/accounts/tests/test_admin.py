from django.contrib import admin, messages
from django.contrib.admin.models import LogEntry
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.urls import reverse

from accounts.models import AccountSecurity, AuthAudit
from accounts.permissions import CAPABILITIES, effective_product_permissions
from .helpers import AccountsCase


def user_form(user, **changes):
    values = dict(username=user.username, first_name=user.first_name, last_name=user.last_name,
                  email=user.email, is_active="on", groups=list(user.groups.values_list("pk", flat=True)),
                  user_permissions=list(user.user_permissions.values_list("pk", flat=True)),
                  date_joined_0="2026-10-01", date_joined_1="00:00:00", _save="Save")
    if user.is_staff:
        values["is_staff"] = "on"
    if user.is_superuser:
        values["is_superuser"] = "on"
    values.update(changes)
    return values


class TechnicalAdminTests(AccountsCase):
    def setUp(self):
        self.client.force_login(self.owner)

    def change(self, user, **changes):
        return self.client.post(reverse("admin:auth_user_change", args=[user.pk]), user_form(user, **changes))

    def password(self, user, **changes):
        data = dict(password1="synthetic-new-password", password2="synthetic-new-password", usable_password="true")
        data.update(changes)
        return self.client.post(reverse("admin:auth_user_password_change", args=[user.pk]), data)

    def only_owner_is_admin(self):
        self.admin.groups.clear()

    def assert_rejected(self, response):
        self.assertEqual(response.status_code, 409)
        self.assertContains(response, "last_admin", status_code=409)
        self.assertFalse(AuthAudit.objects.exists())
        self.assertFalse(LogEntry.objects.exists())
        self.assertFalse(any(message.level == messages.SUCCESS for message in messages.get_messages(response.wsgi_request)))

    def test_user_outer_changeform_catches_final_m2m_demotion(self):
        self.only_owner_is_admin()
        before = self.owner.password
        response = self.change(self.owner, is_superuser="", groups=[])
        self.assert_rejected(response)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.is_superuser)
        self.assertEqual(self.owner.password, before)

    def test_user_changeform_restores_final_direct_and_group_grants(self):
        self.owner.is_superuser = False
        self.owner.user_permissions.add(*Permission.objects.filter(content_type__app_label="auth"))
        self.owner.save()
        self.admin.groups.clear()
        self.admin.user_permissions.add(*Permission.objects.filter(content_type__app_label="accounts"))
        response = self.change(self.admin, user_permissions=[])
        self.assert_rejected(response)
        self.assertEqual(effective_product_permissions(self.admin), set(CAPABILITIES))

    def test_lock_increments_generation_and_records_safe_audit(self):
        response = self.change(self.viewer, is_active="")
        self.assertEqual(response.status_code, 302)
        self.viewer.refresh_from_db()
        self.assertFalse(self.viewer.is_active)
        self.assertEqual(AccountSecurity.objects.get(user=self.viewer).generation, 2)
        self.assertEqual(AuthAudit.objects.get().action, "user_updated")

    def test_last_admin_lock_rolls_back_generation(self):
        self.only_owner_is_admin()
        response = self.change(self.owner, is_active="")
        self.assert_rejected(response)
        self.assertEqual(AccountSecurity.objects.get(user=self.owner).generation, 1)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.is_active)

    def test_last_admin_password_disable_rolls_back_hash_and_session(self):
        self.only_owner_is_admin()
        before = self.owner.password
        session_key = self.client.session.session_key
        response = self.password(self.owner, password1="", password2="", usable_password="false", **{"unset-password": "1"})
        self.assert_rejected(response)
        self.owner.refresh_from_db()
        self.assertEqual(self.owner.password, before)
        self.assertEqual(self.client.session.session_key, session_key)
        self.assertEqual(self.client.get(reverse("admin:index")).status_code, 200)

    def test_technical_admin_can_reset_technical_target_password(self):
        response = self.password(self.owner)
        self.assertEqual(response.status_code, 302)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.check_password("synthetic-new-password"))
        self.assertEqual(AuthAudit.objects.get().action, "password_reset")

    def test_technical_admin_product_password_bounds(self):
        for value in ("short", "x" * 1025):
            response = self.password(self.viewer, password1=value, password2=value)
            self.assertEqual(response.status_code, 200)
            self.viewer.refresh_from_db()
            self.assertTrue(self.viewer.check_password("synthetic-test-password"))
        self.assertFalse(AuthAudit.objects.exists())

    def test_technical_admin_can_create_product_user_with_audit(self):
        response = self.client.post(reverse("admin:auth_user_add"), dict(username="synthetic-added",
                                    password1="synthetic-created-password", password2="synthetic-created-password",
                                    usable_password="true", _save="Save"))
        self.assertEqual(response.status_code, 302)
        user = get_user_model().objects.get(username="synthetic-added")
        self.assertTrue(user.check_password("synthetic-created-password"))
        self.assertFalse(user.is_staff or user.is_superuser)
        self.assertEqual(AuthAudit.objects.get().action, "user_created")

    def test_technical_admin_creation_rejects_short_product_password(self):
        response = self.client.post(reverse("admin:auth_user_add"), dict(username="synthetic-short",
                                    password1="short", password2="short", usable_password="true", _save="Save"))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(get_user_model().objects.filter(username="synthetic-short").exists())
        self.assertFalse(AuthAudit.objects.exists())

    def test_conflicting_password_disable_does_not_write_false_audit(self):
        before = self.viewer.password
        response = self.password(self.viewer, password1="", password2="", usable_password="false")
        self.assertEqual(response.status_code, 302)
        self.viewer.refresh_from_db()
        self.assertEqual(self.viewer.password, before)
        self.assertFalse(AuthAudit.objects.exists())
        self.assertFalse(LogEntry.objects.exists())

    def test_last_staff_superuser_requires_usable_password(self):
        self.only_owner_is_admin()
        replacement = get_user_model().objects.create_user("synthetic-unusable", is_superuser=True)
        self.assertFalse(replacement.has_usable_password())
        self.assert_rejected(self.change(self.owner, is_active=""))

    def test_external_group_removal_is_guarded_after_m2m(self):
        group = Group.objects.create(name="Synthetic authority")
        group.permissions.set(Permission.objects.filter(content_type__app_label="accounts"))
        self.admin.groups.set([group])
        self.owner.is_superuser = False
        self.owner.user_permissions.add(*Permission.objects.filter(content_type__app_label="auth"))
        self.owner.save()
        response = self.client.post(reverse("admin:auth_group_change", args=[group.pk]), dict(name=group.name, permissions=[], _save="Save"))
        self.assert_rejected(response)
        self.assertEqual(effective_product_permissions(self.admin), set(CAPABILITIES))

    def test_group_edits_and_user_m2m_edits_remain_available(self):
        group = Group.objects.create(name="Synthetic editable")
        permission = Permission.objects.get(content_type__app_label="accounts", codename="view")
        response = self.client.post(reverse("admin:auth_group_change", args=[group.pk]), dict(name="Synthetic renamed", permissions=[permission.pk], _save="Save"))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(AuthAudit.objects.get().action, "group_updated")
        self.assertEqual(self.change(self.viewer, groups=[group.pk]).status_code, 302)
        self.assertEqual(set(self.viewer.groups.values_list("name", flat=True)), {"Synthetic renamed"})

    def test_group_add_is_audited_without_password_metadata(self):
        permission = Permission.objects.get(content_type__app_label="accounts", codename="view")
        response = self.client.post(reverse("admin:auth_group_add"), dict(name="Synthetic new group", permissions=[permission.pk], _save="Save"))
        self.assertEqual(response.status_code, 302)
        audit = AuthAudit.objects.get()
        self.assertEqual(audit.action, "group_created")
        self.assertEqual(audit.after, {"group_name": "Synthetic new group", "capabilities": ["view"]})

    def test_user_and_group_deletions_are_denied_before_logging(self):
        for model, obj in [("user", self.viewer), ("group", Group.objects.get(name="AEGIS Viewers"))]:
            with self.subTest(model=model):
                self.assertEqual(self.client.get(reverse("admin:auth_" + model + "_delete", args=[obj.pk])).status_code, 403)
                self.assertEqual(self.client.post(reverse("admin:auth_" + model + "_delete", args=[obj.pk]), {"post": "yes"}).status_code, 403)
                self.client.post(reverse("admin:auth_" + model + "_changelist"), {"action": "delete_selected", "_selected_action": [obj.pk], "post": "yes"})
                self.assertTrue(type(obj).objects.filter(pk=obj.pk).exists())
        self.assertFalse(LogEntry.objects.exists())
        self.assertFalse(AuthAudit.objects.exists())

    def test_direct_admin_deletion_hooks_are_denied(self):
        from django.core.exceptions import PermissionDenied
        for model, obj in [(get_user_model(), self.viewer), (Group, Group.objects.get(name="AEGIS Viewers"))]:
            registered = admin.site._registry[model]
            with self.assertRaises(PermissionDenied):
                registered.delete_model(None, obj)
            with self.assertRaises(PermissionDenied):
                registered.delete_queryset(None, model.objects.filter(pk=obj.pk))

    def test_product_admin_cannot_enter_technical_admin(self):
        self.client.force_login(self.admin)
        response = self.password(self.owner)
        self.assertEqual(response.status_code, 302)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.check_password("synthetic-test-password"))
