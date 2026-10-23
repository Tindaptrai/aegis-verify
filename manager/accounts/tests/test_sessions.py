from unittest.mock import patch
from time import time

from django.contrib.auth.models import Group
from django.test import Client
from django.db import transaction

from accounts.models import AccountSecurity, AuthAudit
from accounts.services import reset_product_password, update_product_user
from .helpers import AccountsCase


class HumanSessionTests(AccountsCase):
    def test_old_cookie_rejected_after_lock_then_unlock_without_intermediate_request(self):
        client = self.login_human(self.viewer)
        for active in (False, True):
            update_product_user(actor=self.admin, user_id=self.viewer.pk, display_name="", capabilities=("view",), active=active)
        self.assertFalse(client.get("/api/v1/auth/session").json()["authenticated"])
        self.assertNotIn("_auth_user_id", client.session)

    def test_polling_does_not_extend_eight_hour_deadline(self):
        client = self.login_human(self.viewer)
        deadline = client.session["aegis_deadline"]
        self.assertEqual(deadline - self.login_epoch, 8 * 60 * 60)
        with patch("accounts.sessions.time", return_value=self.login_epoch + 7 * 60 * 60):
            for _ in range(3):
                self.assertTrue(client.get("/api/v1/auth/session").json()["authenticated"])
        self.assertEqual(client.session["aegis_deadline"], deadline)
        with patch("accounts.sessions.time", return_value=deadline):
            self.assertFalse(client.get("/api/v1/auth/session").json()["authenticated"])

    def test_admin_login_has_security_markers(self):
        client = Client(enforce_csrf_checks=True)
        client.get("/admin/login/")
        login_epoch = int(time())
        with patch("accounts.sessions.time", return_value=login_epoch):
            response = client.post("/admin/login/", {"username": "owner", "password": "synthetic-test-password", "next": "/admin/"},
                                   HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(client.session["aegis_generation"], 1)
        self.assertEqual(client.session["aegis_deadline"], login_epoch + 28800)
        self.assertEqual(client.get("/admin/").status_code, 200)
        with patch("accounts.sessions.time", return_value=login_epoch + 28800):
            self.assertEqual(client.get("/admin/").status_code, 302)

    def test_legacy_cookie_without_markers_requires_relogin(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.owner)
        session = client.session
        for marker in ("aegis_generation", "aegis_deadline"):
            session.pop(marker, None)
        session.save()
        self.assertFalse(client.get("/api/v1/auth/session").json()["authenticated"])
        self.assertEqual(client.get("/admin/").status_code, 302)

    def test_own_password_retains_current_session_original_deadline_only(self):
        client = self.login_human(self.viewer)
        other = self.login_human(self.viewer)
        deadline = client.session["aegis_deadline"]
        key = client.session.session_key
        with patch("accounts.sessions.time", return_value=self.login_epoch + 3600):
            response = self.human_post(client, "/api/v1/auth/password", {"current_password": "synthetic-test-password", "new_password": "synthetic-new-password"})
        self.assertEqual(response.status_code, 204)
        self.assertNotEqual(client.session.session_key, key)
        self.assertEqual(client.session["aegis_deadline"], deadline)
        self.assertEqual(client.session["aegis_generation"], 2)
        self.assertTrue(client.get("/api/v1/auth/session").json()["authenticated"])
        self.assertFalse(other.get("/api/v1/auth/session").json()["authenticated"])
        with patch("accounts.sessions.time", return_value=deadline):
            self.assertFalse(client.get("/api/v1/auth/session").json()["authenticated"])
        audit = AuthAudit.objects.get(action="password_changed")
        self.assertEqual(audit.target_id, self.viewer.pk)
        self.assertNotIn("synthetic-new-password", str(audit.after))

    def test_reset_password_revokes_every_other_session(self):
        clients = [self.login_human(self.viewer), self.login_human(self.viewer)]
        reset_product_password(actor=self.admin, user_id=self.viewer.pk, new_password="synthetic-reset-password")
        self.assertEqual(AccountSecurity.objects.get(user=self.viewer).generation, 2)
        for client in clients:
            self.assertFalse(client.get("/api/v1/auth/session").json()["authenticated"])

    def test_admin_password_reset_revokes_existing_human_cookie(self):
        client = self.login_human(self.viewer)
        admin_client = self.login_human(self.owner)
        token = admin_client.get("/api/v1/auth/session").json()["csrf_token"]
        response = admin_client.post(f"/admin/auth/user/{self.viewer.pk}/password/", {
            "password1": "synthetic-admin-reset", "password2": "synthetic-admin-reset", "usable_password": "true"}, HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(AccountSecurity.objects.get(user=self.viewer).generation, 2)
        self.assertFalse(client.get("/api/v1/auth/session").json()["authenticated"])

    def test_generation_changes_only_for_persisted_password_and_rolls_back(self):
        self.viewer.set_password("synthetic-not-persisted")
        self.viewer.save(update_fields=["last_name"])
        self.assertEqual(AccountSecurity.objects.get(user=self.viewer).generation, 1)
        self.viewer.refresh_from_db()
        self.viewer.save(update_fields=["password"])
        self.assertEqual(AccountSecurity.objects.get(user=self.viewer).generation, 1)
        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                self.viewer.set_password("synthetic-rollback")
                self.viewer.save(update_fields=["password"])
                self.assertEqual(AccountSecurity.objects.get(user=self.viewer).generation, 2)
                raise RuntimeError("synthetic rollback")
        self.assertEqual(AccountSecurity.objects.get(user=self.viewer).generation, 1)

    def test_role_change_is_reflected_on_next_request(self):
        client = self.login_human(self.viewer)
        self.viewer.groups.set([Group.objects.get(name="AEGIS Operators")])
        response = client.get("/api/v1/auth/session")
        self.assertEqual(response.json()["user"]["role"], "operator")
        self.assertEqual(response.json()["user"]["capabilities"], ["view", "run_jobs", "export_evidence"])

    def test_invalid_markers_or_missing_security_flush_session(self):
        for marker, value in (("aegis_generation", True), ("aegis_deadline", "9999999999"), ("aegis_generation", 900)):
            client = self.login_human(self.viewer)
            session = client.session
            session[marker] = value
            session.save()
            self.assertFalse(client.get("/api/v1/auth/session").json()["authenticated"])

    def test_wrong_current_or_invalid_new_password_changes_nothing(self):
        client = self.login_human(self.viewer)
        for current, new, code in (("wrong-private", "synthetic-new-password", "current_password_invalid"),
                                    ("synthetic-test-password", "tiny", "invalid_password"),
                                    ("synthetic-test-password", "x" * 1025, "invalid_password")):
            response = self.human_post(client, "/api/v1/auth/password", {"current_password": current, "new_password": new})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json(), {"error": {"code": code}})
        self.assertEqual(AccountSecurity.objects.get(user=self.viewer).generation, 1)
        self.assertFalse(AuthAudit.objects.exists())

    def test_agent_endpoint_does_not_enforce_human_markers_or_csrf(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post("/agent/v1/poll", {"protocol": "0.1.0"}, content_type="application/json")
        self.assertEqual(response.status_code, 403)
        self.assertNotEqual(response.json(), {"error": {"code": "permission_denied"}})
