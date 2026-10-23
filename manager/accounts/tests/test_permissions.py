from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Group, Permission
from django.core.exceptions import ValidationError

from accounts.errors import AccountError
from accounts.models import AccountSecurity, AuthAudit
from accounts.permissions import (
    CAPABILITIES, PRESETS, effective_product_permissions,
    external_group_capabilities, require_product_admin, require_product_permission,
)
from .helpers import AccountsCase


ALL = frozenset({"view", "run_jobs", "import_scenarios", "publish_scenarios", "manage_devices", "manage_connections", "export_evidence", "manage_users"})


class PermissionTests(AccountsCase):
    def test_seeded_presets_grant_exact_product_authority(self):
        self.assertEqual(frozenset(CAPABILITIES), ALL)
        self.assertEqual(PRESETS, {"admin": ALL, "operator": frozenset({"view", "run_jobs", "export_evidence"}), "viewer": frozenset({"view"})})
        self.assertEqual(set(Permission.objects.filter(content_type__app_label="accounts").values_list("codename", flat=True)), ALL)
        for user, expected in ((self.admin, ALL), (self.operator, frozenset({"view", "run_jobs", "export_evidence"})), (self.viewer, frozenset({"view"}))):
            self.assertEqual(effective_product_permissions(user), expected)
            self.assertFalse(user.is_staff)
            self.assertFalse(user.is_superuser)

    def test_viewer_cannot_run(self):
        with self.assertRaises(PermissionError):
            require_product_permission(self.viewer, "run_jobs")
        self.assertEqual(require_product_permission(self.viewer, "view").pk, self.viewer.pk)

    def test_active_technical_superuser_retains_authority(self):
        self.assertEqual(effective_product_permissions(self.owner), ALL)
        self.assertEqual(require_product_admin(self.owner).pk, self.owner.pk)
        with self.assertRaises(PermissionError):
            require_product_permission(self.owner, "not_a_capability")

    def test_anonymous_inactive_and_deleted_actors_are_denied(self):
        get_user_model().objects.filter(pk=self.admin.pk).update(is_active=False)
        removed = get_user_model().objects.get(pk=self.viewer.pk)
        get_user_model().objects.filter(pk=removed.pk).delete()
        for actor in (AnonymousUser(), self.admin, removed):
            self.assertEqual(effective_product_permissions(actor), frozenset())
            with self.assertRaises(PermissionError):
                require_product_permission(actor, "view")
        get_user_model().objects.filter(pk=self.owner.pk).update(is_active=False)
        with self.assertRaises(PermissionError):
            require_product_admin(self.owner)

    def test_cached_actor_observes_direct_and_group_grants_and_revocations(self):
        actor = get_user_model().objects.get(pk=self.viewer.pk)
        actor.get_all_permissions()
        permission = Permission.objects.get(content_type__app_label="accounts", codename="run_jobs")
        actor.user_permissions.add(permission)
        self.assertIn("run_jobs", effective_product_permissions(actor))
        actor.user_permissions.remove(permission)
        self.assertNotIn("run_jobs", effective_product_permissions(actor))
        group = Group.objects.create(name="Synthetic external operators")
        group.permissions.add(permission)
        actor.groups.add(group)
        self.assertEqual(external_group_capabilities(actor), frozenset({"run_jobs"}))
        self.assertIn("run_jobs", effective_product_permissions(actor))
        group.permissions.clear()
        self.assertEqual(external_group_capabilities(actor), frozenset())
        self.assertNotIn("run_jobs", effective_product_permissions(actor))

    def test_action_without_view_and_other_content_type_permission_are_denied(self):
        user = get_user_model().objects.create_user("no-view")
        user.user_permissions.add(Permission.objects.get(content_type__app_label="accounts", codename="run_jobs"))
        self.assertEqual(effective_product_permissions(user), frozenset())
        with self.assertRaises(PermissionError):
            require_product_permission(user, "run_jobs")
        self.viewer.user_permissions.add(Permission.objects.get(content_type__app_label="auth", codename="change_user"))
        with self.assertRaises(PermissionError):
            require_product_admin(self.viewer)

    def test_new_user_security_is_created_once(self):
        security = AccountSecurity.objects.get(user=self.viewer)
        self.assertEqual((security.generation, security.display_name), (1, ""))
        security.generation = 2
        security.save()
        self.viewer.save()
        security.refresh_from_db()
        self.assertEqual(security.generation, 2)


class AuditTests(AccountsCase):
    def create_audit(self):
        return AuthAudit.objects.create(actor_id=self.owner.pk, target_id=self.viewer.pk, actor_username="owner", target_username="viewer", action="user_updated", before={"is_active": True}, after={"is_active": False})

    def test_audit_rejects_instance_and_queryset_mutations(self):
        audit = self.create_audit()
        for operation in (lambda: audit.save(), lambda: audit.delete(), lambda: AuthAudit.objects.filter(pk=audit.pk).update(action="user_created"), lambda: AuthAudit.objects.filter(pk=audit.pk).delete()):
            with self.assertRaises(ValueError):
                operation()
        self.assertEqual(AuthAudit.objects.get(pk=audit.pk).action, "user_updated")

    def test_user_deletion_preserves_audit_identity_snapshots(self):
        audit = self.create_audit()
        actor_id, target_id = self.owner.pk, self.viewer.pk
        self.owner.delete()
        self.viewer.delete()
        audit.refresh_from_db()
        self.assertEqual((audit.actor_id, audit.target_id, audit.actor_username, audit.target_username), (actor_id, target_id, "owner", "viewer"))

    def test_audit_rejects_unknown_sensitive_and_unbounded_metadata(self):
        for values in ({"password": "synthetic-test-password"}, {"generation": True}, {"generation": 0}, {"display_name": "x" * 151}, {"capabilities": ["unknown"]}, {"has_usable_password": "encoded"}, {"is_staff": 1}, {"group_name": "x" * 151}):
            with self.subTest(values=tuple(values)):
                with self.assertRaises(ValidationError):
                    AuthAudit.objects.create(action="user_updated", before=values)
        with self.assertRaises(ValidationError):
            AuthAudit.objects.create(action="unknown")
        with self.assertRaises(ValidationError):
            AuthAudit.objects.bulk_create([AuthAudit(action="user_created", after={"password": "synthetic-test-password"})])

    def test_audit_accepts_agreed_bounded_metadata(self):
        for action in ("user_created", "user_updated", "password_reset", "password_changed", "group_created", "group_updated"):
            audit = AuthAudit.objects.create(action=action, after={"display_name": "Synthetic", "capabilities": ["view"], "is_active": True, "generation": 1, "is_staff": False, "is_superuser": False, "has_usable_password": True, "group_name": "Synthetic external group"})
            self.assertIsNotNone(audit.created_at)

    def test_account_errors_accept_only_fixed_code_status_pairs(self):
        error = AccountError("invalid_request", 400)
        self.assertEqual((error.code, error.status, str(error)), ("invalid_request", 400, "invalid_request"))
        for code, status in (("source-value", 400), ("invalid_request", 409)):
            with self.assertRaises(ValueError) as caught:
                AccountError(code, status)
            self.assertNotIn("source-value", str(caught.exception))
