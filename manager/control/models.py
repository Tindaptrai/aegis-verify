import uuid
from django.db import models


class Device(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    environment_id = models.CharField(max_length=64)
    generation = models.PositiveIntegerField(default=1)
    certificate_sha256 = models.CharField(max_length=64, unique=True)
    revoked = models.BooleanField(default=False)
    wazuh_agent_id = models.CharField(max_length=64, null=True, blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    connection_kind = models.CharField(max_length=32, choices=[("legacy_v1", "legacy_v1"), ("paired_presence", "paired_presence")], default="legacy_v1")
    os = models.CharField(max_length=16, null=True, blank=True)
    architecture = models.CharField(max_length=16, null=True, blank=True)
    agent_version = models.CharField(max_length=32, null=True, blank=True)
    enrolled_at = models.DateTimeField(null=True, blank=True)
    certificate_not_before = models.DateTimeField(null=True, blank=True)
    certificate_expires_at = models.DateTimeField(null=True, blank=True)
    last_heartbeat_at = models.DateTimeField(null=True, blank=True)


class RunnerRelease(models.Model):
    name = models.CharField(max_length=100, default="SCN-001 reviewed release")
    scenario_path = models.TextField()
    profile_path = models.TextField()
    scenario_sha256 = models.CharField(max_length=64)
    profile_sha256 = models.CharField(max_length=64)
    runner_sha256 = models.CharField(max_length=64)
    kit_sha256 = models.CharField(max_length=64)
    payload_sha256 = models.CharField(max_length=64)
    timeout_seconds = models.PositiveIntegerField(default=300)
    rule_hashes = models.JSONField(default=dict)
    allow_rehearsal = models.BooleanField(default=False)
    evaluation_bindings = models.JSONField(default=list)


class Job(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.PROTECT)
    release = models.ForeignKey(RunnerRelease, on_delete=models.PROTECT)
    execution_state = models.CharField(max_length=32, default="draft")
    collection_state = models.CharField(max_length=32, default="pending")
    report = models.JSONField(null=True, blank=True)
    error_code = models.CharField(max_length=100, blank=True)
    payload_sha256 = models.CharField(max_length=64, blank=True)
    envelope = models.JSONField(null=True, blank=True)
    receipt = models.JSONField(null=True, blank=True)
    receipt_bytes = models.TextField(blank=True)
    parameters = models.JSONField(default=dict)
    evaluation_bindings = models.JSONField(default=list)
    approval_id = models.UUIDField(null=True, editable=False)
    approved_wazuh_agent_id = models.CharField(max_length=64, blank=True)
    approved_generation = models.PositiveIntegerField(null=True)
    not_before = models.DateTimeField()
    expires_at = models.DateTimeField()
    collection_start = models.DateTimeField()
    collection_end = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    started_authorized_at = models.DateTimeField(null=True)


class AuditQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("Audit is append-only")
    def delete(self):
        raise ValueError("Audit is append-only")


class AuditEntry(models.Model):
    objects = AuditQuerySet.as_manager()
    created_at = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=150)
    action = models.CharField(max_length=64)
    job = models.ForeignKey(Job, on_delete=models.PROTECT, null=True)
    def save(self, *args, **kwargs):
        if self.pk: raise ValueError("Audit is append-only")
        super().save(*args, **kwargs)
    def delete(self, *args, **kwargs):
        raise ValueError("Audit is append-only")


class DispatchLock(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1)
