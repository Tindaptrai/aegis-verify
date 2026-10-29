"""No credentials in database rows. Saved source history is append-only."""
import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone
from control.execution_models import ImmutableRecord


class ConnectionDraft(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    session_digest = models.CharField(max_length=64)
    generation = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    tested_at = models.DateTimeField(null=True)
    state = models.CharField(max_length=16, default='probing')
    summary = models.JSONField(default=dict)
    config_sha256 = models.CharField(max_length=64, default='')
    snapshot_hmac = models.CharField(max_length=64, default='')


class ManagedSource(ImmutableRecord):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source_id = models.UUIDField()
    version = models.PositiveIntegerField()
    draft = models.OneToOneField(ConnectionDraft, on_delete=models.PROTECT)
    registration = models.OneToOneField('control.RegisteredExecutionConnection', on_delete=models.PROTECT)
    idempotency_key = models.UUIDField(unique=True)
    summary = models.JSONField()
    tested_at = models.DateTimeField()
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=('source_id','version'), name='managed_source_version_unique')]


class CandidateSelection(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1)
    source = models.ForeignKey(ManagedSource, on_delete=models.PROTECT, null=True)


class ConnectionAudit(ImmutableRecord):
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    action = models.CharField(max_length=32)
    version = models.PositiveIntegerField()
    draft_id = models.UUIDField()
    fingerprint = models.CharField(max_length=64)
    result = models.CharField(max_length=32)
    created_at = models.DateTimeField(default=timezone.now)
