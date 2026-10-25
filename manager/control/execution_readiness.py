"""Server-owned readiness conjunction, never evidence or collection assurance."""
from datetime import timedelta, timezone
from django.db import transaction
from . import execution_contracts as wire
from .execution_models import DeviceExecutionBinding, LocalExecutionReadiness, CollectionWorkerLease, RegisteredExecutionConnection
from .execution_connections import resolve_execution_connection
from .execution_ownership import (lock_dispatch, lock_device_ownership, guard_execution_owner,
    require_idle, execution_job_blocks)
from .execution_services import authenticate_execution_identity
from .models import Device, Job
from .worker_health import current_scope_sha256


def stamp(now):
    return now.astimezone(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')


def fresh(value, now, seconds):
    return value is not None and timedelta(0) <= now-value <= timedelta(seconds=seconds)


@transaction.atomic
def record_local_readiness(identity, request, *, received_at):
    request = wire.decode_contract('ReadinessRequest', wire.canonical_bytes(request))
    lock_dispatch()
    lock_device_ownership(identity.device_id)
    device = authenticate_execution_identity(identity, now=received_at, lock=True)
    if (request.device_id, request.generation) != (str(device.pk),device.generation):
        raise PermissionError('identity_denied')
    binding = DeviceExecutionBinding.objects.filter(device=device, is_current=True).first()
    if binding is None or (request.binding_id,request.binding_revision) != (str(binding.binding_id),binding.revision):
        raise wire.ExecutionError('identity_denied')
    LocalExecutionReadiness.objects.update_or_create(device=device, defaults=dict(generation=request.generation,
        binding_id=request.binding_id,binding_revision=request.binding_revision,
        installation_profile_sha256=request.installation_profile_sha256,artifact_set_sha256=request.artifact_set_sha256,
        ready=request.ready,blocking_codes=list(request.blocking_codes),report_bytes=wire.canonical_bytes(request),received_at=received_at))
    return wire.ReadinessAck(wire.PROTOCOL,stamp(received_at),True)


@transaction.atomic
def execution_readiness(device_id, *, now, active_job_id=None):
    # Same lock order as the machine service; read checks cannot race publication.
    lock_dispatch()
    lock_device_ownership(device_id)
    device = Device.objects.filter(pk=device_id).first()
    binding = DeviceExecutionBinding.objects.filter(device_id=device_id,is_current=True).first()
    codes, deadlines = [], []
    def block(code):
        if code not in codes: codes.append(code)
    capability = 'upgrade_required'
    if device is None:
        block('identity_unavailable')
    else:
        if device.os != 'windows' or device.architecture != 'x64':
            capability='unsupported'; block('unsupported_platform')
        elif (device.reported_agent_version or device.agent_version) != '0.3.0': block('upgrade_required')
        else: capability='installed_supported'
        if (device.connection_kind != 'paired_presence' or device.revoked or device.archived_at is not None
                or device.certificate_not_before is None or device.certificate_expires_at is None
                or not device.certificate_not_before <= now < device.certificate_expires_at): block('identity_unavailable')
        else: deadlines.append(device.certificate_expires_at)
        try: wire._field('environment_id',device.environment_id)
        except (ValueError,TypeError): block('environment_invalid')
        if not fresh(device.last_heartbeat_at,now,30): block('local_stale')
        else: deadlines.append(device.last_heartbeat_at+timedelta(seconds=30))
    if binding is None: block('binding_missing')
    elif device:
        if not binding.enabled: block('binding_disabled')
        if (binding.approved_device_id,binding.approved_generation,binding.approved_certificate_sha256,binding.approved_environment_id) != (
                device.pk,device.generation,device.certificate_sha256,device.environment_id): block('identity_unavailable')
        if not binding.wazuh_agent_id or binding.wazuh_agent_id != device.wazuh_agent_id: block('mapping_missing')
        try: guard_execution_owner(device,binding)
        except Exception: block('ownership_conflict')
        report = LocalExecutionReadiness.objects.filter(device=device).first()
        if report is None or not fresh(report.received_at,now,30): block('local_stale')
        if report:
            if report.generation != device.generation: block('identity_unavailable')
            if (str(report.binding_id),report.binding_revision,report.installation_profile_sha256) != (
                    str(binding.binding_id),binding.revision,binding.installation_profile_sha256): block('profile_mismatch')
            if report.artifact_set_sha256 != binding.artifact_set_sha256: block('artifact_mismatch')
            if not report.ready:
                for code in report.blocking_codes: block(code if code in wire.LOCAL_CODES else 'local_not_ready')
                if not report.blocking_codes: block('local_not_ready')
            deadlines.append(report.received_at+timedelta(seconds=30))
        connection = RegisteredExecutionConnection.objects.filter(connection_id=binding.connection_id).order_by('-revision').first()
        try:
            if connection is None or connection.revision != binding.connection_revision: raise ValueError
            resolve_execution_connection(binding.connection_id,binding.connection_revision)
        except Exception: block('source_unavailable')
        leases = CollectionWorkerLease.objects.filter(connection_id=binding.connection_id,connection_revision=binding.connection_revision)
        workers = [row for row in leases if connection is not None and row.config_sha256 == connection.config_sha256
            and row.output_root_fingerprint == connection.output_root_fingerprint and row.health_code == 'healthy'
            and fresh(row.last_seen_at,now,30)]
        if len(workers) != 1: block('worker_unavailable'); block('source_unavailable')
        else:
            worker = workers[0]; deadlines.append(worker.last_seen_at+timedelta(seconds=30))
            if (worker.source_probe_status != 'healthy' or not fresh(worker.source_probe_succeeded_at,now,60)
                    or not worker.source_probe_scope_sha256 or worker.source_probe_scope_sha256 != current_scope_sha256(connection)):
                block('source_unavailable')
            else: deadlines.append(worker.source_probe_succeeded_at+timedelta(seconds=60))
    exclude = None
    if active_job_id is not None:
        same = Job.objects.filter(pk=active_job_id,device_id=device_id,protocol_family='windows_execution_v2',
            execution_state__in=('queued','leased','started'),collection_state='pending',approval_snapshot__isnull=False).first()
        if same is not None and binding is not None and same.binding_id == binding.pk: exclude=same.pk
    try: require_idle(active_job_id=exclude)
    except wire.ExecutionError:
        blockers = [job for job in Job.objects.exclude(pk=exclude) if execution_job_blocks(job)]
        unresolved = any(job.collection_state in ('failed','collecting') or job.execution_state in ('execution_unknown','failed','cancelled','expired') for job in blockers)
        block('reconciliation_required' if unresolved else 'busy')
    return wire.ExecutionDeviceDTO(str(device_id),binding.provider_id if binding else None,
        str(binding.binding_id) if binding else None,binding.revision if binding else None,capability,not codes,tuple(codes[:8]),
        stamp(now),stamp(min(deadlines)) if deadlines and not codes else None,binding.release_id if binding else None,
        binding.release_sha256 if binding else None,str(binding.connection_id) if binding else None,binding.wazuh_agent_id if binding else None)
