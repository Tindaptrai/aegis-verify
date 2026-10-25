"""Private execution authority records. Historical revisions are append-only."""
import hashlib
import uuid
from django.conf import settings
from django.db import models, transaction
from django.utils import timezone


class ImmutableQuerySet(models.QuerySet):
    def update(self, **kwargs): raise ValueError('Execution authority is immutable')
    def delete(self): raise ValueError('Execution authority is immutable')
    def bulk_update(self, objs, fields, batch_size=None): raise ValueError('Execution authority is immutable')
    def bulk_create(self, objs, **kwargs):
        if kwargs.get('update_conflicts') or kwargs.get('ignore_conflicts'): raise ValueError('Execution authority is immutable')
        for obj in objs: obj.validate_authority()
        return super().bulk_create(objs, **kwargs)


class ImmutableRecord(models.Model):
    objects = ImmutableQuerySet.as_manager()
    class Meta: abstract = True
    def validate_authority(self): pass
    def save(self, *args, **kwargs):
        if not self._state.adding: raise ValueError('Execution authority is immutable')
        if type(self).objects.filter(pk=self.pk).exists(): raise ValueError('Execution authority is immutable')
        self.validate_authority()
        return super().save(*args, **kwargs)
    def delete(self, *args, **kwargs): raise ValueError('Execution authority is immutable')


class JobApprovalSnapshot(ImmutableRecord):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    schema_version = models.PositiveSmallIntegerField(default=1)
    snapshot_bytes = models.BinaryField()
    snapshot_sha256 = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    def validate_authority(self):
        from .execution_contracts import decode_contract, snapshot_bytes
        raw = bytes(self.snapshot_bytes)
        if self.schema_version != 1 or hashlib.sha256(raw).hexdigest() != self.snapshot_sha256:
            raise ValueError('Invalid execution snapshot')
        if snapshot_bytes(decode_contract('JobApprovalSnapshotData', raw)) != raw:
            raise ValueError('Invalid execution snapshot')


class RegisteredExecutionConnection(ImmutableRecord):
    id = models.BigAutoField(primary_key=True)
    connection_id = models.UUIDField(default=uuid.uuid4)
    revision = models.PositiveIntegerField()
    config_path = models.TextField()
    config_sha256 = models.CharField(max_length=64)
    output_root_fingerprint = models.CharField(max_length=64)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    reviewed_at = models.DateTimeField(default=timezone.now)
    class Meta:
        constraints = [models.UniqueConstraint(fields=('connection_id', 'revision'), name='execution_connection_revision_unique')]
    def validate_authority(self):
        from .execution_contracts import _field
        for name in ('connection_id', 'revision', 'config_sha256', 'output_root_fingerprint'):
            value = getattr(self, name)
            _field(name, str(value) if name == 'connection_id' else value)
        previous = type(self).objects.filter(connection_id=self.connection_id).aggregate(models.Max('revision'))['revision__max']
        if previous is not None and self.revision <= previous: raise ValueError('Connection revision must increase')
        if not self.config_path: raise ValueError('Invalid private connection path')


class BindingQuerySet(ImmutableQuerySet):
    def update(self, **kwargs):
        if set(kwargs) != {'is_current'} or type(kwargs['is_current']) is not bool: raise ValueError('Binding revision is immutable')
        return models.QuerySet.update(self, **kwargs)


class DeviceExecutionBinding(ImmutableRecord):
    objects = BindingQuerySet.as_manager()
    id = models.BigAutoField(primary_key=True)
    binding_id = models.UUIDField(default=uuid.uuid4)
    revision = models.PositiveIntegerField()
    is_current = models.BooleanField(default=True)
    enabled = models.BooleanField(default=True)
    device = models.ForeignKey('control.Device', on_delete=models.PROTECT)
    approved_device_id = models.UUIDField()
    approved_generation = models.PositiveIntegerField()
    approved_certificate_sha256 = models.CharField(max_length=64)
    approved_environment_id = models.CharField(max_length=64)
    provider_id = models.CharField(max_length=64, default='reviewed-scn001-windows/1')
    release = models.ForeignKey('control.RunnerRelease', on_delete=models.PROTECT)
    release_bytes = models.BinaryField()
    release_sha256 = models.CharField(max_length=64)
    installation_profile_sha256 = models.CharField(max_length=64)
    artifact_set_sha256 = models.CharField(max_length=64)
    connection_id = models.UUIDField()
    connection_revision = models.PositiveIntegerField()
    wazuh_agent_id = models.CharField(max_length=64)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    reviewed_at = models.DateTimeField(default=timezone.now)
    class Meta:
        constraints = [models.UniqueConstraint(fields=('binding_id', 'revision'), name='execution_binding_revision_unique'),
                       models.UniqueConstraint(fields=('device',), condition=models.Q(is_current=True), name='execution_one_current_binding')]
    def validate_authority(self):
        from .execution_contracts import canonical_bytes, decode_contract, _field
        for name, value in (('binding_id', str(self.binding_id)), ('revision', self.revision),
                            ('device_id', str(self.approved_device_id)), ('generation', self.approved_generation),
                            ('certificate_sha256', self.approved_certificate_sha256), ('environment_id', self.approved_environment_id),
                            ('provider_id', self.provider_id), ('installation_profile_sha256', self.installation_profile_sha256),
                            ('artifact_set_sha256', self.artifact_set_sha256), ('connection_id', str(self.connection_id)),
                            ('revision', self.connection_revision), ('wazuh_agent_id', self.wazuh_agent_id)):
            _field(name, value)
        previous = type(self).objects.filter(binding_id=self.binding_id).aggregate(models.Max('revision'))['revision__max']
        if previous is not None and self.revision <= previous: raise ValueError('Binding revision must increase')
        raw = bytes(self.release_bytes)
        if hashlib.sha256(raw).hexdigest() != self.release_sha256 or canonical_bytes(decode_contract('ReleaseDefinition', raw)) != raw:
            raise ValueError('Invalid frozen release')
    @transaction.atomic
    def set_enabled(self, enabled, actor):
        if type(enabled) is not bool or not actor.pk: raise ValueError('Invalid binding admission')
        current = type(self).objects.select_for_update().get(pk=self.pk)
        if current.enabled != enabled:
            BindingAdmissionAudit.objects.create(binding=current, actor=actor, enabled=enabled)
            models.QuerySet.update(type(self).objects.filter(pk=self.pk), enabled=enabled)
        self.enabled = enabled


class BindingAdmissionAudit(ImmutableRecord):
    binding = models.ForeignKey(DeviceExecutionBinding, on_delete=models.PROTECT)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    enabled = models.BooleanField()
    created_at = models.DateTimeField(auto_now_add=True)


class ExecutionTargetOwnership(models.Model):
    objects = ImmutableQuerySet.as_manager()
    connection_id = models.UUIDField()
    environment_id = models.CharField(max_length=64)
    wazuh_agent_id = models.CharField(max_length=64)
    reviewed_legacy_device_id = models.UUIDField(null=True)
    reviewed_paired_device_id = models.UUIDField()
    active_executor_id = models.UUIDField()
    revision = models.PositiveIntegerField(default=1)
    class Meta:
        constraints = [models.UniqueConstraint(fields=('connection_id', 'environment_id', 'wazuh_agent_id'), name='execution_target_resource_unique')]
    def save(self, *args, **kwargs):
        if not self._state.adding: raise ValueError('Ownership changes require audited transfer')
        if self.pk is not None and type(self).objects.filter(pk=self.pk).exists():
            raise ValueError('Ownership changes require audited transfer')
        self.validate_authority()
        # A concurrent insertion of this PK must fail, never become an UPDATE.
        kwargs['force_insert'] = True
        return super().save(*args, **kwargs)
    def validate_authority(self):
        if type(self.revision) is not int or not 1 <= self.revision <= 2147483647: raise ValueError('Invalid ownership revision')
        allowed = {str(self.reviewed_paired_device_id)}
        if self.reviewed_legacy_device_id is not None: allowed.add(str(self.reviewed_legacy_device_id))
        if str(self.active_executor_id) not in allowed: raise ValueError('Executor must be reviewed')
    def delete(self, *args, **kwargs): raise ValueError('Ownership history is retained')
    @transaction.atomic
    def record_transfer(self, *, actor, expected_revision, reviewed_legacy_device_id, reviewed_paired_device_id, active_executor_id):
        """Persistence primitive; caller must first hold dispatch and idle/permission fences."""
        current = type(self).objects.select_for_update().get(pk=self.pk)
        if not actor.pk or type(expected_revision) is not int or current.revision != expected_revision:
            raise ValueError('Ownership revision conflict')
        current.revision += 1
        current.reviewed_legacy_device_id = reviewed_legacy_device_id
        current.reviewed_paired_device_id = reviewed_paired_device_id
        current.active_executor_id = active_executor_id
        current.validate_authority()
        names = ('revision', 'reviewed_legacy_device_id', 'reviewed_paired_device_id', 'active_executor_id')
        models.Model.save(current, update_fields=names)
        ExecutionOwnershipAudit.objects.create(ownership=current, actor=actor,
            **{name: getattr(current, name) for name in names})
        for name in names: setattr(self, name, getattr(current, name))


class ExecutionOwnershipAudit(ImmutableRecord):
    ownership = models.ForeignKey(ExecutionTargetOwnership, on_delete=models.PROTECT)
    revision = models.PositiveIntegerField()
    active_executor_id = models.UUIDField()
    reviewed_legacy_device_id = models.UUIDField(null=True)
    reviewed_paired_device_id = models.UUIDField()
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        constraints = [models.UniqueConstraint(fields=('ownership', 'revision'), name='execution_ownership_audit_revision')]


class ExecutionPreview(ImmutableRecord):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    snapshot = models.OneToOneField(JobApprovalSnapshot, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()


class ExecutionIdempotency(ImmutableRecord):
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    operation = models.CharField(max_length=32)
    key = models.UUIDField()
    request_sha256 = models.CharField(max_length=64)
    job = models.ForeignKey('control.Job', on_delete=models.PROTECT)
    class Meta:
        constraints = [models.UniqueConstraint(fields=('actor', 'operation', 'key'), name='execution_idempotency_actor_operation_key')]


class LocalExecutionReadiness(models.Model):
    device = models.OneToOneField('control.Device', on_delete=models.PROTECT)
    generation = models.PositiveIntegerField()
    binding_id = models.UUIDField()
    binding_revision = models.PositiveIntegerField()
    installation_profile_sha256 = models.CharField(max_length=64)
    artifact_set_sha256 = models.CharField(max_length=64)
    ready = models.BooleanField()
    blocking_codes = models.JSONField(default=list)
    report_bytes = models.BinaryField()
    received_at = models.DateTimeField(default=timezone.now)


class CollectionWorkerLease(models.Model):
    instance_id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    connection_id = models.UUIDField()
    connection_revision = models.PositiveIntegerField()
    config_sha256 = models.CharField(max_length=64)
    output_root_fingerprint = models.CharField(max_length=64)
    started_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    health_code = models.CharField(max_length=32)
    source_probe_status = models.CharField(max_length=32, default='unknown')
    source_probe_succeeded_at = models.DateTimeField(null=True)


class ExecutionOwnerDecision(ImmutableRecord):
    """Owner-reviewed operational references; never detection evidence claims."""
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    action = models.CharField(max_length=32)
    ownership = models.ForeignKey(ExecutionTargetOwnership, on_delete=models.PROTECT, null=True)
    ownership_revision = models.PositiveIntegerField(null=True)
    job = models.ForeignKey('control.Job', on_delete=models.PROTECT, null=True)
    reason = models.CharField(max_length=500)
    evidence_refs = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    def validate_authority(self):
        import unicodedata
        def bounded(value, limit):
            return (type(value) is str and 1 <= len(value) <= limit and value.strip()
                    and not any(unicodedata.category(char).startswith('C') for char in value))
        if not bounded(self.reason, 500) or type(self.evidence_refs) is not list or not 1 <= len(self.evidence_refs) <= 32:
            raise ValueError('Invalid owner decision')
        if not all(bounded(ref, 256) for ref in self.evidence_refs):
            raise ValueError('Invalid owner decision')
        if self.action == 'reconciliation':
            if self.job_id is None or self.ownership_id is not None or self.ownership_revision is not None:
                raise ValueError('Invalid owner decision')
        elif self.action in ('initial_ownership', 'ownership_transfer'):
            if self.job_id is not None or self.ownership_id is None or type(self.ownership_revision) is not int or not 1 <= self.ownership_revision <= 2147483647:
                raise ValueError('Invalid owner decision')
        else:
            raise ValueError('Invalid owner decision')
