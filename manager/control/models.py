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
    archived_at = models.DateTimeField(null=True, blank=True)
    archived_by_id = models.PositiveBigIntegerField(null=True, blank=True)
    reported_ips = models.JSONField(null=True, blank=True)
    ip_collection_status = models.CharField(max_length=16, choices=[(v, v) for v in ("unknown", "ok", "unavailable")], default="unknown")
    reported_ips_truncated = models.BooleanField(default=False)
    reported_ips_received_at = models.DateTimeField(null=True, blank=True)
    observed_ip = models.GenericIPAddressField(null=True, blank=True)
    observed_ip_received_at = models.DateTimeField(null=True, blank=True)
    reported_agent_version = models.CharField(max_length=32, null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=models.Q(archived_at__isnull=True) | models.Q(revoked=True),
                                   name="archived_device_is_revoked"),
        ]


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


EXECUTION_FROZEN_FIELDS = ('binding_id', 'approval_snapshot_id', 'preview_id', 'envelope_bytes', 'signed_payload_bytes',
    'job_sha256', 'start_request_id', 'start_request_bytes', 'start_request_sha256', 'start_ack_bytes',
    'terminal_receipt_id', 'terminal_receipt_bytes', 'receipt_ack_bytes')


class JobQuerySet(models.QuerySet):
    def bulk_create(self, objs, **kwargs):
        if kwargs.get('update_conflicts'):
            objs = list(objs)
            if (any(obj.protocol_family == 'windows_execution_v2' for obj in objs) or
                    self.filter(pk__in=[obj.pk for obj in objs], protocol_family='windows_execution_v2').exists()):
                raise ValueError('Execution job authority is immutable')
        return super().bulk_create(objs, **kwargs)

    def bulk_update(self, objs, fields, batch_size=None):
        if set(fields) & (set(EXECUTION_FROZEN_FIELDS) | {'protocol_family'}):
            if self.filter(pk__in=[obj.pk for obj in objs], protocol_family='windows_execution_v2').exists():
                raise ValueError('Execution job authority is immutable')
        return super().bulk_update(objs, fields, batch_size)

    def update(self, **kwargs):
        normalized = {self.model._meta.get_field(k).attname: v for k, v in kwargs.items()}
        guarded = set(normalized) & (set(EXECUTION_FROZEN_FIELDS) | {'protocol_family'})
        if guarded:
            for row in self.values('protocol_family', *EXECUTION_FROZEN_FIELDS):
                for name in guarded:
                    previous = row[name]
                    if (name == 'protocol_family' or row['protocol_family'] == 'windows_execution_v2' and previous is not None) and previous != normalized[name]:
                        raise ValueError('Execution job authority is immutable')
        return super().update(**kwargs)


class Job(models.Model):
    objects = JobQuerySet.as_manager()
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
    protocol_family = models.CharField(max_length=32, choices=[('legacy_v1', 'legacy_v1'), ('windows_execution_v2', 'windows_execution_v2')], default='legacy_v1')
    binding = models.ForeignKey('control.DeviceExecutionBinding', on_delete=models.PROTECT, null=True)
    approval_snapshot = models.OneToOneField('control.JobApprovalSnapshot', on_delete=models.PROTECT, null=True)
    preview = models.OneToOneField('control.ExecutionPreview', on_delete=models.PROTECT, null=True)
    envelope_bytes = models.BinaryField(null=True)
    signed_payload_bytes = models.BinaryField(null=True)
    job_sha256 = models.CharField(max_length=64, null=True)
    start_request_id = models.UUIDField(null=True)
    start_request_bytes = models.BinaryField(null=True)
    start_request_sha256 = models.CharField(max_length=64, null=True)
    start_ack_bytes = models.BinaryField(null=True)
    terminal_receipt_id = models.UUIDField(null=True, unique=True)
    terminal_receipt_bytes = models.BinaryField(null=True)
    receipt_ack_bytes = models.BinaryField(null=True)
    finished_at = models.DateTimeField(null=True)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            previous = type(self).objects.filter(pk=self.pk).values('protocol_family', *EXECUTION_FROZEN_FIELDS).get()
            for name in ('protocol_family', *EXECUTION_FROZEN_FIELDS):
                if (name == 'protocol_family' or previous['protocol_family'] == 'windows_execution_v2' and previous[name] is not None) and previous[name] != getattr(self, name):
                    raise ValueError('Execution job authority is immutable')
        return super().save(*args, **kwargs)


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


# Explicit registration keeps existing v1 models and their services intact.
from .execution_models import (DeviceExecutionBinding, RegisteredExecutionConnection,
    ExecutionTargetOwnership, ExecutionOwnershipAudit, BindingAdmissionAudit, ExecutionPreview,
    ExecutionIdempotency, JobApprovalSnapshot, LocalExecutionReadiness, CollectionWorkerLease)
