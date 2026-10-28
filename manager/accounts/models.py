from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models

from .permissions import CAPABILITIES


class AccountSecurity(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="account_security")
    generation = models.PositiveIntegerField(default=1)
    display_name = models.CharField(max_length=150, blank=True)

    class Meta:
        default_permissions = ()
        permissions = [(key, key.replace("_", " ").capitalize()) for key in CAPABILITIES]


class AccountMutationLock(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1)

    class Meta:
        default_permissions = ()


AUDIT_ACTIONS = (
    "user_created", "user_updated", "password_reset", "password_changed",
    "group_created", "group_updated",
)


def _validate_metadata(metadata):
    if type(metadata) is not dict:
        raise ValidationError("invalid_audit_metadata")
    for key, value in metadata.items():
        if key in ("display_name", "group_name"):
            valid = type(value) is str and len(value) <= 150
        elif key in ("is_active", "is_staff", "is_superuser", "has_usable_password"):
            valid = type(value) is bool
        elif key == "generation":
            valid = type(value) is int and 1 <= value <= 2147483647
        elif key == "capabilities":
            valid = (type(value) is list and len(value) <= len(CAPABILITIES)
                     and all(type(item) is str and item in CAPABILITIES for item in value)
                     and len(set(value)) == len(value))
        else:
            valid = False
        if not valid:
            raise ValidationError("invalid_audit_metadata")


class AuthAuditQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("auth_audit_append_only")

    def delete(self):
        raise ValueError("auth_audit_append_only")

    def bulk_create(self, objs, **kwargs):
        if kwargs.get("update_conflicts"):
            raise ValueError("auth_audit_append_only")
        objs = list(objs)
        for obj in objs:
            obj.full_clean()
        return super().bulk_create(objs, **kwargs)


class AuthAudit(models.Model):
    objects = AuthAuditQuerySet.as_manager()
    actor_id = models.PositiveBigIntegerField(null=True, blank=True, validators=[MinValueValidator(1)])
    target_id = models.PositiveBigIntegerField(null=True, blank=True, validators=[MinValueValidator(1)])
    actor_username = models.CharField(max_length=150, blank=True)
    target_username = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=32, choices=[(action, action) for action in AUDIT_ACTIONS])
    before = models.JSONField(default=dict, blank=True)
    after = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        default_permissions = ()
        base_manager_name = "objects"

    def clean(self):
        super().clean()
        _validate_metadata(self.before)
        _validate_metadata(self.after)

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise ValueError("auth_audit_append_only")
        self.full_clean()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("auth_audit_append_only")
