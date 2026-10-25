"""Shared dispatch fences. Call guards inside the documented dispatch transaction."""
from django.db import transaction
from django.db.models import Q
from accounts.models import AccountMutationLock
from accounts.permissions import require_product_admin
from .execution_contracts import ExecutionError, _field
from .execution_models import ExecutionTargetOwnership, ExecutionOwnershipAudit, ExecutionOwnerDecision, RegisteredExecutionConnection
from .models import Device, Job, AuditEntry, DispatchLock


def lock_human_authority():
    AccountMutationLock.objects.select_for_update().get(pk=1)


def lock_dispatch():
    DispatchLock.objects.select_for_update().get(pk=1)


def execution_job_blocks(job):
    if job.collection_state == 'collecting':
        return True
    if job.collection_state == 'reconciled':
        return False
    if job.execution_state == 'draft':
        return False
    if job.execution_state == 'succeeded' and job.collection_state in ('evaluated', 'empty'):
        return False
    if job.execution_state in ('cancelled', 'expired') and job.collection_state == 'pending':
        return AuditEntry.objects.filter(job=job, action='leased').exists() or job.start_ack_bytes is not None
    return True


def require_idle(*, device_ids=None, active_job_id=None):
    jobs = Job.objects.all()
    if device_ids is not None:
        jobs = jobs.filter(device_id__in=device_ids)
    if active_job_id is not None:
        jobs = jobs.exclude(pk=active_job_id)
    if any(execution_job_blocks(job) for job in jobs.order_by('pk')):
        raise ExecutionError('job_conflict')


def lock_device_ownership(device_id):
    """Lock known fences before Device rows, including both sides of a handoff."""
    return list(ExecutionTargetOwnership.objects.select_for_update().filter(
        Q(reviewed_paired_device_id=device_id) | Q(reviewed_legacy_device_id=device_id)).order_by('pk'))


def guard_execution_owner(device, binding=None):
    rows = lock_device_ownership(device.pk)
    if binding is None and device.connection_kind == 'legacy_v1':
        if any(row.active_executor_id != device.pk or row.environment_id != device.environment_id
                or row.wazuh_agent_id != device.wazuh_agent_id for row in rows):
            raise PermissionError('identity_denied')
        return rows[0] if rows else None
    if binding is None:
        raise ExecutionError('binding_conflict')
    rows = [row for row in rows if (str(row.connection_id), row.environment_id, row.wazuh_agent_id) ==
            (str(binding.connection_id), device.environment_id, binding.wazuh_agent_id)]
    if len(rows) != 1 or rows[0].active_executor_id != device.pk or rows[0].reviewed_paired_device_id != device.pk:
        raise ExecutionError('binding_conflict')
    return rows[0]


@transaction.atomic
def transfer_execution_ownership(actor, resource, expected_revision, executor_id, reviewed_device_ids, reason, *, evidence_refs):
    lock_human_authority()
    actor = require_product_admin(actor)
    lock_dispatch()
    if type(resource) is not dict or set(resource) != {'connection_id','environment_id','wazuh_agent_id'}:
        raise ExecutionError('invalid_request')
    if type(reviewed_device_ids) is not dict or set(reviewed_device_ids) != {'paired_device_id','legacy_device_id'}:
        raise ExecutionError('invalid_request')
    for name, value in resource.items():
        if type(value) is not str: raise ExecutionError('invalid_request')
        _field(name, value)
    paired, legacy = reviewed_device_ids['paired_device_id'], reviewed_device_ids['legacy_device_id']
    for value in (paired, executor_id):
        if type(value) is not str: raise ExecutionError('invalid_request')
        _field('device_id', value)
    if legacy is not None:
        if type(legacy) is not str: raise ExecutionError('invalid_request')
        _field('device_id', legacy)
    if paired == legacy or executor_id not in (paired, legacy):
        raise ExecutionError('binding_conflict')
    if not RegisteredExecutionConnection.objects.filter(connection_id=resource['connection_id']).exists():
        raise ExecutionError('binding_conflict')
    current = ExecutionTargetOwnership.objects.select_for_update().filter(**resource).first()
    if current is None and expected_revision is not None or current is not None and (type(expected_revision) is not int or current.revision != expected_revision):
        raise ExecutionError('binding_conflict')
    ids = {paired, legacy} - {None}
    if current:
        ids.update(str(value) for value in (current.reviewed_paired_device_id, current.reviewed_legacy_device_id) if value)
    # One reviewed executor identity must not silently participate in two resources.
    if ExecutionTargetOwnership.objects.filter(Q(reviewed_paired_device_id__in=ids) | Q(reviewed_legacy_device_id__in=ids)).exclude(pk=current.pk if current else None).exists():
        raise ExecutionError('binding_conflict')
    devices = {str(row.pk): row for row in Device.objects.select_for_update().filter(pk__in=ids).order_by('pk')}
    if set(devices) != ids:
        raise ExecutionError('binding_conflict')
    if devices[paired].connection_kind != 'paired_presence' or (legacy and devices[legacy].connection_kind != 'legacy_v1'):
        raise ExecutionError('binding_conflict')
    for value in (paired, legacy):
        if value is not None and (devices[value].environment_id != resource['environment_id'] or
                devices[value].revoked or devices[value].archived_at is not None):
            raise ExecutionError('binding_conflict')
    if legacy and devices[legacy].wazuh_agent_id != resource['wazuh_agent_id']:
        raise ExecutionError('binding_conflict')
    require_idle(device_ids=ids)
    values = dict(reviewed_paired_device_id=paired, reviewed_legacy_device_id=legacy, active_executor_id=executor_id)
    initial = current is None
    if initial:
        current = ExecutionTargetOwnership.objects.create(**resource, **values)
        ExecutionOwnershipAudit.objects.create(ownership=current, actor=actor, revision=1, **values)
    else:
        current.record_transfer(actor=actor, expected_revision=expected_revision, **values)
    ExecutionOwnerDecision.objects.create(actor=actor, action='initial_ownership' if initial else 'ownership_transfer',
        ownership=current, ownership_revision=current.revision, reason=reason, evidence_refs=evidence_refs)
    return current
