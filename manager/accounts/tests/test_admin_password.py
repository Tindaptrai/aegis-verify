"""Native Admin own-password route, using real CSRF-protected human sessions."""
from unittest.mock import patch

from django.contrib.auth.models import Permission
from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse

from accounts.contracts import user_dto
from accounts.models import AccountSecurity, AuthAudit
from accounts.permissions import CAPABILITIES, effective_product_permissions
from .helpers import AccountsCase
from .test_admin import user_form


class NativeAdminPasswordTests(AccountsCase):
    def post_password(self, client, **changes):
        data = dict(old_password="synthetic-test-password", new_password1="synthetic-new-password",
                    new_password2="synthetic-new-password")
        data.update(changes)
        return client.post(reverse("admin:password_change"), data,
                           HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value)

    def test_native_password_change_retains_only_current_cookie_and_deadline_with_audit(self):
        client = self.login_human(self.owner)
        other = self.login_human(self.owner)
        deadline, old_key = client.session["aegis_deadline"], client.session.session_key
        with patch("accounts.sessions.time", return_value=self.login_epoch + 3600):
            response = self.post_password(client)
        self.assertRedirects(response, reverse("admin:password_change_done"))
        self.assertEqual(client.session["aegis_generation"], 2)
        self.assertEqual(client.session["aegis_deadline"], deadline)
        self.assertNotEqual(client.session.session_key, old_key)
        self.assertFalse(other.get("/api/v1/auth/session").json()["authenticated"])
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.check_password("synthetic-new-password"))
        audit = AuthAudit.objects.get()
        self.assertEqual((audit.action, audit.actor_id, audit.target_id),
                         ("password_changed", self.owner.pk, self.owner.pk))
        self.assertEqual((audit.before["generation"], audit.after["generation"]), (1, 2))
        self.assertNotIn(self.owner.password, repr((audit.before, audit.after)))
        self.assertNotIn("synthetic-new-password", repr((audit.before, audit.after)))
        with patch("accounts.sessions.time", return_value=deadline):
            self.assertFalse(client.get("/api/v1/auth/session").json()["authenticated"])

    def test_native_password_requires_current_password_and_matching_bounded_replacement(self):
        client = self.login_human(self.owner)
        for changes in ({"old_password": "synthetic-wrong"}, {"new_password2": "synthetic-mismatch"},
                        {"new_password1": "tiny", "new_password2": "tiny"},
                        {"new_password1": "x" * 1025, "new_password2": "x" * 1025}):
            with self.subTest(fields=tuple(changes)):
                response = self.post_password(client, **changes)
                self.assertEqual(response.status_code, 200)
                self.owner.refresh_from_db()
                self.assertTrue(self.owner.check_password("synthetic-test-password"))
                self.assertEqual(AccountSecurity.objects.get(user=self.owner).generation, 1)
                self.assertFalse(AuthAudit.objects.exists())

    def test_native_policy_rejection_rolls_back_password_generation_audit_and_cookie(self):
        self.owner.is_superuser = False
        self.owner.save(update_fields=["is_superuser"])
        self.admin.groups.clear()
        client = self.login_human(self.owner)
        key, session = client.session.session_key, dict(client.session)
        response = self.post_password(client)
        self.assertContains(response, "last_admin", status_code=409)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.check_password("synthetic-test-password"))
        self.assertEqual(AccountSecurity.objects.get(user=self.owner).generation, 1)
        self.assertFalse(AuthAudit.objects.exists())
        self.assertEqual(client.session.session_key, key)
        self.assertEqual(dict(client.session), session)
        self.assertEqual(client.get(reverse("admin:index")).status_code, 200)

    def test_native_password_requires_csrf_and_technical_access(self):
        client = self.login_human(self.owner)
        self.assertEqual(client.post(reverse("admin:password_change"), {}).status_code, 403)
        client = self.login_human(self.admin)
        self.assertEqual(self.post_password(client).status_code, 302)
        self.assertFalse(AuthAudit.objects.exists())

    def test_native_revalidates_generation_after_route_entry(self):
        client = self.login_human(self.owner)
        technician = self.login_human(self.owner)
        original_dispatch = PasswordChangeView.dispatch

        def reset_before_form(view, request, *args, **kwargs):
            response = technician.post(reverse("admin:auth_user_password_change", args=[self.owner.pk]), {
                "password1": "synthetic-reset-password", "password2": "synthetic-reset-password",
                "usable_password": "true",
            }, HTTP_X_CSRFTOKEN=technician.cookies["csrftoken"].value)
            self.assertEqual(response.status_code, 302)
            return original_dispatch(view, request, *args, **kwargs)

        # Middleware/route entry has loaded the old User. This boundary hook
        # runs a real competing Admin write before form handling; it is not a
        # concurrency claim (the PostgreSQL tests exercise actual row locks).
        with patch.object(PasswordChangeView, "dispatch", reset_before_form):
            response = self.post_password(client)
        self.assertEqual(response.status_code, 401)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.check_password("synthetic-reset-password"))
        self.assertEqual(list(AuthAudit.objects.values_list("action", flat=True)), ["password_reset"])
        self.assertNotIn("_auth_user_id", client.session)

    def test_native_revalidates_deadline_after_route_entry(self):
        client = self.login_human(self.owner)
        deadline = client.session["aegis_deadline"]
        original_dispatch = PasswordChangeView.dispatch

        def expire_before_form(view, request, *args, **kwargs):
            with patch("accounts.sessions.time", return_value=deadline):
                return original_dispatch(view, request, *args, **kwargs)

        with patch.object(PasswordChangeView, "dispatch", expire_before_form):
            response = self.post_password(client)
        self.assertEqual(response.status_code, 401)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.check_password("synthetic-test-password"))
        self.assertFalse(AuthAudit.objects.exists())
        self.assertNotIn("_auth_user_id", client.session)

    def test_native_lock_unlock_after_route_entry_cannot_restamp_revoked_cookie(self):
        self.admin.is_staff = True
        self.admin.user_permissions.add(*Permission.objects.filter(content_type__app_label="auth"))
        self.admin.save(update_fields=["is_staff"])
        client = self.login_human(self.owner)
        technician = self.login_human(self.admin)
        original_dispatch = PasswordChangeView.dispatch

        def lock_unlock_before_form(view, request, *args, **kwargs):
            for active in ("", "on"):
                response = technician.post(reverse("admin:auth_user_change", args=[self.owner.pk]),
                                           user_form(self.owner, is_active=active),
                                           HTTP_X_CSRFTOKEN=technician.cookies["csrftoken"].value)
                self.assertEqual(response.status_code, 302)
            return original_dispatch(view, request, *args, **kwargs)

        with patch.object(PasswordChangeView, "dispatch", lock_unlock_before_form):
            response = self.post_password(client)
        self.assertEqual(response.status_code, 401)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.is_active)
        self.assertTrue(self.owner.check_password("synthetic-test-password"))
        self.assertEqual(AccountSecurity.objects.get(user=self.owner).generation, 2)
        self.assertEqual(list(AuthAudit.objects.values_list("action", flat=True)), ["user_updated", "user_updated"])
        self.assertNotIn("_auth_user_id", client.session)

    def test_locked_technical_audit_keeps_assigned_superuser_grants(self):
        technician = self.admin
        technician.is_staff = True
        technician.user_permissions.add(*Permission.objects.filter(content_type__app_label="auth"))
        technician.save(update_fields=["is_staff"])
        client = self.login_human(technician)
        response = client.post(reverse("admin:auth_user_change", args=[self.owner.pk]),
                               user_form(self.owner, is_active=""),
                               HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value)
        self.assertEqual(response.status_code, 302)
        audit = AuthAudit.objects.get()
        self.assertEqual(audit.after["capabilities"], sorted(CAPABILITIES))
        self.assertFalse(audit.after["is_active"])
        self.assertEqual(effective_product_permissions(self.owner), set())

    def test_locked_direct_grant_without_view_is_audited_and_matches_dto(self):
        client = self.login_human(self.owner)
        permission = Permission.objects.get(content_type__app_label="accounts", codename="manage_devices")
        response = client.post(reverse("admin:auth_user_change", args=[self.viewer.pk]),
                               user_form(self.viewer, is_active="", groups=[], user_permissions=[permission.pk]),
                               HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value)
        self.assertEqual(response.status_code, 302)
        audit = AuthAudit.objects.get()
        self.assertEqual(audit.before["capabilities"], ["view"])
        self.assertEqual(audit.after["capabilities"], ["manage_devices"])
        self.assertEqual(user_dto(self.viewer, self.owner)["capabilities"], ["manage_devices"])
        self.assertEqual(effective_product_permissions(self.viewer), set())
