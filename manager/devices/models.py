"""Pairing state stores digests; enrollment audit has a closed, secret-free schema."""
import uuid

from django.conf import settings
from django.db import models


class PairingCode(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code_sha256 = models.CharField(max_length=64, unique=True)
    environment_id = models.CharField(max_length=64)
    issued_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)
    consumed_at = models.DateTimeField(null=True)
    consumed_device = models.OneToOneField("control.Device", null=True, on_delete=models.PROTECT)

    class Meta:
        default_permissions = ()


class EnrollmentAuditQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("enrollment_audit_append_only")

    def delete(self):
        raise ValueError("enrollment_audit_append_only")

    def bulk_create(self, objs, **kwargs):
        if kwargs.get("update_conflicts"):
            raise ValueError("enrollment_audit_append_only")
        objs = list(objs)
        for obj in objs:
            obj.full_clean()
        return super().bulk_create(objs, **kwargs)


class EnrollmentAudit(models.Model):
    objects = EnrollmentAuditQuerySet.as_manager()
    created_at = models.DateTimeField(auto_now_add=True)
    actor_id = models.PositiveBigIntegerField(null=True, blank=True)
    action = models.CharField(max_length=32, choices=[(v, v) for v in
        ("pairing_code_created", "pairing_code_revoked", "device_enrolled", "device_revoked")])
    code_id = models.UUIDField(null=True, blank=True)
    device_id = models.UUIDField(null=True, blank=True)

    class Meta:
        default_permissions = ()
        base_manager_name = "objects"

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise ValueError("enrollment_audit_append_only")
        self.full_clean()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("enrollment_audit_append_only")
