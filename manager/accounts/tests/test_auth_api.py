import json

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import Client, RequestFactory

from accounts.models import AccountSecurity, AuthAudit
from .helpers import AccountsCase


class AuthenticationApiTests(AccountsCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)

    def test_anonymous_session_bootstraps_csrf_without_account_writes(self):
        before = AccountSecurity.objects.count()
        response = self.client.get("/api/v1/auth/session")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(set(response.json()), {"authenticated", "csrf_token", "user", "expires_at"})
        self.assertFalse(response.json()["authenticated"])
        self.assertIsNone(response.json()["user"])
        self.assertIsNone(response.json()["expires_at"])
        self.assertTrue(response.json()["csrf_token"])
        self.assertEqual(AccountSecurity.objects.count(), before)

    def test_missing_and_invalid_csrf_are_fixed_json_403_and_admin_stays_html(self):
        for token in (None, "x" * 64):
            headers = {} if token is None else {"HTTP_X_CSRFTOKEN": token}
            response = self.client.post("/api/v1/auth/login", {}, content_type="application/json", **headers)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json(), {"error": {"code": "permission_denied"}})
            self.assertEqual(response["Cache-Control"], "no-store")
        response = self.client.post("/admin/login/", {"username": "owner"})
        self.assertEqual(response.status_code, 403)
        self.assertIn("text/html", response["Content-Type"])

    def test_generic_login_failures_and_no_sensitive_echo(self):
        locked = get_user_model().objects.create_user("synthetic-locked", password="synthetic-test-password", is_active=False)
        for username, password in (("synthetic-unknown", "private-wrong"), (locked.username, "synthetic-test-password"),
                                   (self.viewer.username, "private-wrong")):
            response = self.human_post(self.client, "/api/v1/auth/login", {"username": username, "password": password})
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json(), {"error": {"code": "invalid_credentials"}})
            self.assertEqual(response["Cache-Control"], "no-store")

    def test_login_rotates_key_and_csrf_and_accepts_existing_short_password(self):
        self.viewer.set_password("old")
        self.viewer.save()
        session = self.client.session
        session["synthetic"] = "rotation-test"
        session.save()
        previous_key = session.session_key
        previous_token = self.client.get("/api/v1/auth/session").json()["csrf_token"]
        response = self.client.post("/api/v1/auth/login", {"username": "viewer", "password": "old"},
                                    content_type="application/json", HTTP_X_CSRFTOKEN=previous_token)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["authenticated"])
        self.assertEqual(response.json()["user"]["username"], "viewer")
        self.assertNotEqual(self.client.session.session_key, previous_key)
        rejected = self.client.post("/api/v1/auth/logout", {}, content_type="application/json", HTTP_X_CSRFTOKEN=previous_token)
        self.assertEqual(rejected.status_code, 403)

    def test_post_only_logout_flushes_current_session(self):
        client = self.login_human(self.viewer)
        self.assertEqual(client.get("/api/v1/auth/logout").status_code, 405)
        response = self.human_post(client, "/api/v1/auth/logout", {})
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertFalse(client.get("/api/v1/auth/session").json()["authenticated"])

    def test_password_requires_authentication_and_csrf(self):
        response = self.human_post(self.client, "/api/v1/auth/password", {"current_password": "x", "new_password": "synthetic-new-password"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": {"code": "unauthenticated"}})
        self.assertEqual(response["Cache-Control"], "no-store")
        client = self.login_human(self.viewer)
        self.assertEqual(client.post("/api/v1/auth/password", {}, content_type="application/json").status_code, 403)

    def test_json_contract_rejects_unknown_duplicate_nonobject_wrong_types_and_oversize(self):
        token = self.client.get("/api/v1/auth/session").json()["csrf_token"]
        bodies = ['{"username":"viewer","password":"x","next":"https://synthetic.invalid"}',
                  '{"username":"viewer","username":"owner","password":"x"}', '[]', 'null', '{',
                  '{"username":1,"password":"x"}', '{"username":"viewer","password":false}',
                  json.dumps({"username": "viewer", "password": "x" * 16384})]
        for body in bodies:
            with self.subTest(body=body[:80]):
                response = self.client.post("/api/v1/auth/login", body, content_type="application/json", HTTP_X_CSRFTOKEN=token)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json(), {"error": {"code": "invalid_request"}})
        response = self.client.post("/api/v1/auth/login", "username=viewer", content_type="text/plain", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 400)

    def test_legacy_active_user_without_view_can_use_session_password_logout(self):
        legacy = get_user_model().objects.create_user("synthetic-legacy", password="synthetic-test-password")
        client = self.login_human(legacy)
        response = client.get("/api/v1/auth/session")
        self.assertTrue(response.json()["authenticated"])
        self.assertEqual(response.json()["user"]["capabilities"], [])
        self.assertEqual(self.human_post(client, "/api/v1/auth/password", {"current_password": "synthetic-test-password", "new_password": "synthetic-new-password"}).status_code, 204)
        self.assertEqual(self.human_post(client, "/api/v1/auth/logout", {}).status_code, 204)

    def test_get_serializers_never_create_missing_security_or_audit(self):
        client = self.login_human(self.viewer)
        AccountSecurity.objects.filter(user=self.viewer).delete()
        response = client.get("/api/v1/auth/session")
        self.assertFalse(response.json()["authenticated"])
        self.assertFalse(AccountSecurity.objects.filter(user=self.viewer).exists())
        from accounts.contracts import user_dto
        dto = user_dto(self.viewer, self.admin)
        self.assertEqual(dto["display_name"], "")
        self.assertFalse(AccountSecurity.objects.filter(user=self.viewer).exists())
        self.assertFalse(AuthAudit.objects.exists())

    def test_locked_dto_retains_assigned_role_grants_and_external_inheritance(self):
        from accounts.contracts import user_dto
        self.viewer.is_active = False
        self.viewer.save()
        dto = user_dto(self.viewer, self.admin)
        self.assertEqual((dto["role"], dto["capabilities"]), ("viewer", ["view"]))
        external = Group.objects.create(name="Synthetic inherited locked grants")
        external.permissions.add(Permission.objects.get(content_type__app_label="accounts", codename="run_jobs"))
        self.viewer.groups.add(external)
        dto = user_dto(self.viewer, self.admin)
        self.assertEqual(dto["role"], "custom")
        self.assertEqual(dto["capabilities"], ["view", "run_jobs"])
        self.assertEqual(dto["inherited_capabilities"], ["run_jobs"])
        self.assertTrue(dto["editable"])
        self.assertFalse(dto["is_active"])
        self.assertFalse(user_dto(self.owner, self.admin)["editable"])

    def test_dto_reloads_cached_target_and_actor_authority(self):
        from accounts.contracts import user_dto
        self.viewer.get_all_permissions()
        self.admin.get_all_permissions()
        self.viewer.groups.set([Group.objects.get(name="AEGIS Operators")])
        self.admin.groups.clear()
        dto = user_dto(self.viewer, self.admin)
        self.assertEqual(dto["role"], "operator")
        self.assertFalse(dto["editable"])

    def test_shared_parser_rejects_duplicate_nested_keys_and_nonfinite_numbers(self):
        from accounts.contracts import parse_json
        from accounts.errors import AccountError
        for body in ('{"extra":{"x":1,"x":2}}', '{"extra":NaN}', '{"extra":Infinity}'):
            with self.assertRaises(AccountError):
                parse_json(RequestFactory().post("/", body, content_type="application/json"))
