"""Transactional paired execution authority; no process launch or evidence synthesis."""
import hashlib
import importlib
import uuid
from dataclasses import asdict, dataclass
from datetime import timedelta, timezone as utc_timezone
from pathlib import Path

from django.db import transaction
from django.utils import timezone
from accounts.permissions import require_product_permission, require_product_admin
from aegis_verify.intake.io import read_local
from . import execution_contracts as wire
from .execution_models import (DeviceExecutionBinding, RegisteredExecutionConnection, JobApprovalSnapshot,
    ExecutionPreview, ExecutionIdempotency, ExecutionOwnerDecision)
from .execution_ownership import (lock_human_authority, lock_dispatch, lock_device_ownership,
    guard_execution_owner, require_idle, execution_job_blocks)
from .execution_signing import sign_execution_payload
from .jobs import audit, release_pins
from .models import Device, RunnerRelease, Job, AuditEntry

FAMILY = 'windows_execution_v2'


@dataclass(frozen=True)
class ExecutionIdentity:
    device_id: str
    generation: int
    certificate_sha256: str


def stamp(value):
    return value.astimezone(utc_timezone.utc).replace(microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')


def checked(kind, value):
    return wire.decode_contract(kind, wire.canonical_bytes(value))


def execution_readiness(device_id, *, now, active_job_id=None):
    """Temporary fail-closed bridge, replaced by Task3's actual conjunction."""
    try:
        module = importlib.import_module('control.execution_readiness')
    except ModuleNotFoundError as error:
        if error.name != 'control.execution_readiness': raise
        binding = DeviceExecutionBinding.objects.filter(device_id=device_id, is_current=True).first()
        return wire.ExecutionDeviceDTO(str(device_id), binding.provider_id if binding else None,
            str(binding.binding_id) if binding else None, binding.revision if binding else None,
            'upgrade_required', False, ('worker_unavailable',), None, None,
            binding.release_id if binding else None, binding.release_sha256 if binding else None,
            str(binding.connection_id) if binding else None, binding.wazuh_agent_id if binding else None)
    return module.execution_readiness(device_id, now=now, active_job_id=active_job_id)


def _ready(device_id, *, now, active_job_id=None):
    dto = checked('ExecutionDeviceDTO', execution_readiness(str(device_id), now=now, active_job_id=active_job_id))
    if not dto.ready or dto.device_id != str(device_id):
        raise wire.ExecutionError('execution_unavailable')


def _device_valid(device, now):
    return (device.connection_kind == 'paired_presence' and not device.revoked and device.archived_at is None
        and device.certificate_not_before is not None and device.certificate_expires_at is not None
        and device.certificate_not_before <= now < device.certificate_expires_at)


def authenticate_execution_identity(identity, *, now, lock=False):
    """Identity is constructed only from verified proxy certificate + closed request."""
    if type(identity) is not ExecutionIdentity:
        raise PermissionError('identity_denied')
    rows = Device.objects.select_for_update() if lock else Device.objects
    try:
        device = rows.get(pk=identity.device_id, generation=identity.generation,
            certificate_sha256=identity.certificate_sha256)
    except (Device.DoesNotExist, ValueError):
        raise PermissionError('identity_denied') from None
    if not _device_valid(device, now):
        raise PermissionError('identity_denied')
    return device


def _human_device(device_id, *, now):
    lock_device_ownership(device_id)
    try: device = Device.objects.select_for_update().get(pk=device_id)
    except Device.DoesNotExist: raise wire.ExecutionError('binding_conflict') from None
    if not _device_valid(device, now): raise wire.ExecutionError('binding_conflict')
    return device


def _current_binding(device):
    binding = DeviceExecutionBinding.objects.select_for_update().filter(device=device, is_current=True).first()
    if binding is None: raise wire.ExecutionError('binding_conflict')
    return binding


def _definition(release):
    release_pins(release)
    return checked('ReleaseDefinition', dict(release_id=release.pk, scenario_id='SCN-001', runner_id='scn001-safe-demo',
        runner_version='0.3.0', artifact_pins={name+'_sha256': getattr(release,name+'_sha256')
            for name in ('scenario','profile','runner','kit','payload')}, rule_pins=release.rule_hashes,
        allow_rehearsal=release.allow_rehearsal, timeout_seconds=release.timeout_seconds,
        evaluation_bindings=release.evaluation_bindings, scenario_path=release.scenario_path, profile_path=release.profile_path))


def _connection(connection_id, revision):
    connection = RegisteredExecutionConnection.objects.filter(connection_id=connection_id).order_by('-revision').first()
    if connection is None or connection.revision != revision:
        raise wire.ExecutionError('binding_conflict')
    path = Path(connection.config_path)
    if not path.is_absolute() or hashlib.sha256(read_local(path, limit=1024*1024, stage='inputs')).hexdigest() != connection.config_sha256:
        raise wire.ExecutionError('binding_conflict')
    return connection


def _binding_valid(device, binding, *, enabled=True):
    if enabled and not binding.enabled:
        raise wire.ExecutionError('binding_conflict')
    if (binding.approved_device_id, binding.approved_generation, binding.approved_certificate_sha256, binding.approved_environment_id) != (
            device.pk, device.generation, device.certificate_sha256, device.environment_id):
        raise wire.ExecutionError('binding_conflict')
    if device.wazuh_agent_id != binding.wazuh_agent_id:
        raise wire.ExecutionError('binding_conflict')
    return guard_execution_owner(device, binding)


@transaction.atomic
def set_execution_binding(actor, device_id, input):
    lock_human_authority()
    actor = require_product_permission(actor, 'manage_devices')
    input = checked('BindingInput', input)
    lock_dispatch()
    device = _human_device(device_id, now=timezone.now())
    current = DeviceExecutionBinding.objects.select_for_update().filter(device=device, is_current=True).first()
    if input.expected_revision != (current.revision if current else None):
        raise wire.ExecutionError('binding_conflict')
    values = dict(provider_id=input.provider_id, release_id=input.runner_release_id,
        installation_profile_sha256=input.installation_profile_sha256, connection_id=input.wazuh_connection_id,
        connection_revision=input.wazuh_connection_revision, wazuh_agent_id=input.wazuh_agent_id)
    same = current is not None and all(str(getattr(current, key)) == str(value) for key, value in values.items())
    if same:
        # Disabling may always block future admissions, including during ambiguity.
        if input.enabled:
            _binding_valid(device, current, enabled=False)
        current.set_enabled(input.enabled, actor)
        return execution_readiness(device.pk, now=timezone.now())
    require_idle(device_ids=[device.pk])
    _connection(input.wazuh_connection_id, input.wazuh_connection_revision)
    try: release = RunnerRelease.objects.get(pk=input.runner_release_id)
    except RunnerRelease.DoesNotExist: raise wire.ExecutionError('binding_conflict') from None
    definition = _definition(release)
    raw = wire.release_definition_bytes(definition)
    binding = DeviceExecutionBinding(device=device, **values, enabled=input.enabled,
        revision=current.revision+1 if current else 1,
        binding_id=current.binding_id if current else uuid.uuid4(), approved_device_id=device.pk,
        approved_generation=device.generation, approved_certificate_sha256=device.certificate_sha256,
        approved_environment_id=device.environment_id, release_bytes=raw, release_sha256=hashlib.sha256(raw).hexdigest(),
        artifact_set_sha256=hashlib.sha256(wire.canonical_bytes(dict(artifact_pins=asdict(definition.artifact_pins),
            rule_pins=asdict(definition.rule_pins)))).hexdigest(), reviewed_by=actor)
    guard_execution_owner(device, binding)
    if current: DeviceExecutionBinding.objects.filter(pk=current.pk).update(is_current=False)
    binding.save()
    device.wazuh_agent_id=binding.wazuh_agent_id
    device.save(update_fields=['wazuh_agent_id'])
    return execution_readiness(device.pk, now=timezone.now())


def _snapshot(device, binding, parameters, windows):
    owner = _binding_valid(device, binding)
    release = _definition(RunnerRelease.objects.get(pk=binding.release_id))
    if wire.release_definition_bytes(release) != bytes(binding.release_bytes):
        raise wire.ExecutionError('preview_conflict')
    connection = _connection(binding.connection_id, binding.connection_revision)
    return checked('JobApprovalSnapshotData', dict(schema_version=1,
        identity=dict(device_id=str(device.pk), generation=device.generation, certificate_sha256=device.certificate_sha256,
            environment_id=device.environment_id),
        binding=dict(binding_id=str(binding.binding_id), binding_revision=binding.revision, provider_id=binding.provider_id,
            installation_profile_sha256=binding.installation_profile_sha256, artifact_set_sha256=binding.artifact_set_sha256,
            ownership_revision=owner.revision), release=asdict(wire.freeze_release(release, parameters)), windows=asdict(windows),
        connection=dict(connection_id=str(connection.connection_id), revision=connection.revision, config_path=connection.config_path,
            config_sha256=connection.config_sha256, output_root_fingerprint=connection.output_root_fingerprint,
            wazuh_agent_id=binding.wazuh_agent_id)))


@transaction.atomic
def preview_execution(actor, input, *, now):
    lock_human_authority()
    actor = require_product_permission(actor, 'run_jobs')
    input = checked('PreviewInput', input)
    lock_dispatch()
    device = _human_device(input.device_id, now=now)
    binding = _current_binding(device)
    if binding.revision != input.binding_revision or binding.provider_id != input.provider_id:
        raise wire.ExecutionError('preview_conflict')
    require_idle()
    _ready(device.pk, now=now)
    t0 = now.astimezone(utc_timezone.utc).replace(microsecond=0)
    release = wire.decode_contract('ReleaseDefinition', bytes(binding.release_bytes))
    parameters = wire.Parameters(input.run_label, input.rule_revision, getattr(release.rule_pins, input.rule_revision))
    windows = wire.ExecutionWindows(stamp(t0), stamp(t0+timedelta(seconds=120)), stamp(t0-timedelta(seconds=30)),
        stamp(t0+timedelta(seconds=120+release.timeout_seconds)))
    snapshot = _snapshot(device, binding, parameters, windows)
    raw = wire.snapshot_bytes(snapshot)
    record = JobApprovalSnapshot.objects.create(snapshot_bytes=raw, snapshot_sha256=hashlib.sha256(raw).hexdigest())
    preview = ExecutionPreview.objects.create(actor=actor, snapshot=record, expires_at=t0+timedelta(seconds=120))
    return wire.PreviewDTO(str(preview.pk), record.snapshot_sha256, stamp(preview.expires_at), wire.public_summary(snapshot))


def job_dto(job):
    snapshot = wire.decode_contract('JobApprovalSnapshotData', bytes(job.approval_snapshot.snapshot_bytes))
    return checked('JobDTO', dict(job_id=str(job.pk), admission_blocked=execution_job_blocks(job), summary=asdict(wire.public_summary(snapshot)),
        execution_state=job.execution_state, collection_state=job.collection_state,
        evaluation_state='evaluated' if job.report is not None else 'not_evaluated', created_at=stamp(job.created_at),
        started_authorized_at=stamp(job.started_authorized_at) if job.started_authorized_at else None,
        finished_at=stamp(job.finished_at) if job.finished_at else None, error_code=job.error_code or None, report=job.report))


@transaction.atomic
def _approve_execution(actor, input, *, now):
    lock_human_authority()
    actor = require_product_permission(actor, 'run_jobs')
    input = checked('ApproveInput', input)
    digest = hashlib.sha256(wire.canonical_bytes(input)).hexdigest()
    lock_dispatch()
    replay = ExecutionIdempotency.objects.filter(actor=actor, operation='approve', key=input.idempotency_key).first()
    if replay:
        if replay.request_sha256 != digest: raise wire.ExecutionError('preview_conflict')
        return job_dto(replay.job), False
    try: preview = ExecutionPreview.objects.select_related('snapshot').get(pk=input.preview_id, actor=actor)
    except ExecutionPreview.DoesNotExist: raise wire.ExecutionError('preview_conflict') from None
    if preview.snapshot.snapshot_sha256 != input.preview_sha256 or (preview.expires_at-now).total_seconds() < 30:
        raise wire.ExecutionError('preview_conflict')
    snapshot = wire.decode_contract('JobApprovalSnapshotData', bytes(preview.snapshot.snapshot_bytes))
    device = _human_device(snapshot.identity.device_id, now=now)
    binding = _current_binding(device)
    if Job.objects.filter(preview=preview).exists(): raise wire.ExecutionError('preview_conflict')
    if wire.snapshot_bytes(_snapshot(device, binding, snapshot.release.parameters, snapshot.windows)) != bytes(preview.snapshot.snapshot_bytes):
        raise wire.ExecutionError('preview_conflict')
    require_idle()
    _ready(device.pk, now=now)
    job_id, approval_id = uuid.uuid4(), uuid.uuid4()
    payload = checked('SignedJob', dict(protocol=wire.PROTOCOL, job_id=str(job_id), run_id=str(job_id), approval_id=str(approval_id),
        **asdict(snapshot.identity), binding_id=snapshot.binding.binding_id, binding_revision=snapshot.binding.binding_revision,
        release_id=snapshot.release.release_id, approval_snapshot_sha256=preview.snapshot.snapshot_sha256,
        scenario_id=snapshot.release.scenario_id, runner_id=snapshot.release.runner_id, runner_version=snapshot.release.runner_version,
        **asdict(snapshot.release.artifact_pins), **asdict(snapshot.windows), timeout_seconds=snapshot.release.timeout_seconds,
        parameters=asdict(snapshot.release.parameters)))
    try: envelope, digest_job = sign_execution_payload(payload)
    except (ValueError,OSError): raise wire.ExecutionError('execution_unavailable') from None
    job = Job.objects.create(id=job_id, device=device, release_id=binding.release_id, protocol_family=FAMILY,
        binding=binding, approval_snapshot=preview.snapshot, preview=preview, envelope_bytes=envelope,
        signed_payload_bytes=wire.canonical_bytes(payload), job_sha256=digest_job, approval_id=approval_id,
        approved_generation=device.generation, approved_wazuh_agent_id=binding.wazuh_agent_id,
        parameters=asdict(snapshot.release.parameters), evaluation_bindings=[asdict(item) for item in snapshot.release.evaluation_bindings],
        **{name:wire.timestamp(value) for name,value in asdict(snapshot.windows).items()}, execution_state='queued')
    ExecutionIdempotency.objects.create(actor=actor, operation='approve', key=input.idempotency_key, request_sha256=digest, job=job)
    audit(job, 'approved', actor.pk)
    return job_dto(job), True


def approve_execution(actor, input, *, now):
    return _approve_execution(actor, input, now=now)[0]


def _machine_device(identity, request, *, now, current=True):
    if identity.device_id != request.device_id or identity.generation != request.generation:
        raise PermissionError('identity_denied')
    lock_device_ownership(identity.device_id)
    device = authenticate_execution_identity(identity, now=now, lock=True)
    binding = None
    if current:
        binding = _current_binding(device)
        _binding_valid(device, binding)
        if (str(binding.binding_id), binding.revision) != (request.binding_id, request.binding_revision):
            raise wire.ExecutionError('binding_conflict')
    return device, binding


@transaction.atomic
def poll_execution(identity, request, *, now):
    request = checked('PollRequest', request)
    lock_dispatch()
    device, binding = _machine_device(identity, request, now=now)
    job = Job.objects.select_for_update().filter(device=device, protocol_family=FAMILY,
        binding=binding, execution_state__in=('queued','leased')).order_by('created_at').first()
    if job is None: return None
    if not job.not_before <= now <= job.expires_at: return None
    require_idle(active_job_id=job.pk)
    _ready(device.pk, now=now, active_job_id=job.pk)
    if job.execution_state == 'queued':
        job.execution_state='leased'; job.save(update_fields=['execution_state'])
        audit(job, 'leased', device.pk)
    return bytes(job.envelope_bytes)


def _machine_job(device, job_id, request):
    try: job = Job.objects.select_for_update().get(pk=job_id, device=device, protocol_family=FAMILY)
    except Job.DoesNotExist: raise wire.ExecutionError('job_not_found') from None
    snapshot = wire.decode_contract('JobApprovalSnapshotData', bytes(job.approval_snapshot.snapshot_bytes))
    if (snapshot.identity.device_id, snapshot.identity.generation, snapshot.identity.certificate_sha256,
            snapshot.binding.binding_id, snapshot.binding.binding_revision, job.job_sha256) != (
            str(device.pk), device.generation, device.certificate_sha256, request.binding_id, request.binding_revision, request.job_sha256):
        raise wire.ExecutionError('start_conflict' if isinstance(request,wire.StartRequest) else 'receipt_conflict')
    return job, snapshot


@transaction.atomic
def authorize_execution_start(identity, job_id, raw_request, *, now):
    request = wire.parse_execution_request('start', raw_request)
    lock_dispatch()
    device, binding = _machine_device(identity, request, now=now)
    job, snapshot = _machine_job(device, job_id, request)
    if job.binding_id != binding.pk or not job.not_before <= now <= job.expires_at:
        raise wire.ExecutionError('start_conflict')
    require_idle(active_job_id=job.pk)
    _ready(device.pk, now=now, active_job_id=job.pk)
    if job.start_ack_bytes is not None:
        if job.execution_state != 'started' or job.collection_state == 'reconciled' or bytes(job.start_request_bytes) != raw_request:
            raise wire.ExecutionError('start_conflict')
        return bytes(job.start_ack_bytes)
    if job.execution_state != 'leased': raise wire.ExecutionError('start_conflict')
    ack = wire.canonical_bytes(wire.StartAck(wire.PROTOCOL, str(job.pk), request.start_request_id, job.job_sha256, True))
    job.start_request_id=request.start_request_id; job.start_request_bytes=raw_request
    job.start_request_sha256=hashlib.sha256(raw_request).hexdigest(); job.start_ack_bytes=ack
    job.execution_state='started'; job.started_authorized_at=now
    job.save(update_fields=['start_request_id','start_request_bytes','start_request_sha256','start_ack_bytes','execution_state','started_authorized_at'])
    audit(job, 'start_authorized', device.pk)
    return ack


@transaction.atomic
def accept_execution_receipt(identity, raw_request, *, now):
    request = wire.parse_execution_request('receipt', raw_request)
    lock_dispatch()
    device, _ = _machine_device(identity, request, now=now, current=False)
    job, snapshot = _machine_job(device, request.job_id, request)
    if job.terminal_receipt_bytes is not None:
        if bytes(job.terminal_receipt_bytes) != raw_request: raise wire.ExecutionError('receipt_conflict')
        return bytes(job.receipt_ack_bytes)
    if Job.objects.filter(terminal_receipt_id=request.receipt_id).exists(): raise wire.ExecutionError('receipt_conflict')
    end = wire.timestamp(request.finished_at)
    start = wire.timestamp(request.started_at) if request.started_at else None
    if not job.not_before <= end <= now+timedelta(seconds=5): raise wire.ExecutionError('receipt_conflict')
    if start is not None and not job.not_before <= start <= job.expires_at: raise wire.ExecutionError('receipt_conflict')
    late_unknown = request.state == 'execution_unknown' and job.execution_state in ('leased','execution_unknown','cancelled','expired')
    if late_unknown:
        if not AuditEntry.objects.filter(job=job, action='leased').exists(): raise wire.ExecutionError('receipt_conflict')
    elif job.execution_state != 'started': raise wire.ExecutionError('receipt_conflict')
    if request.state != 'execution_unknown' and (start is None or end > start+timedelta(seconds=snapshot.release.timeout_seconds)
            or not job.collection_start <= start <= end <= job.collection_end):
        raise wire.ExecutionError('receipt_conflict')
    ack = wire.canonical_bytes(wire.ReceiptAck(wire.PROTOCOL, str(job.pk), request.receipt_id, job.job_sha256, True))
    job.terminal_receipt_id=request.receipt_id; job.terminal_receipt_bytes=raw_request; job.receipt_ack_bytes=ack
    job.finished_at=end
    if job.execution_state in ('leased','started'): job.execution_state=request.state
    job.save(update_fields=['terminal_receipt_id','terminal_receipt_bytes','receipt_ack_bytes','finished_at','execution_state'])
    audit(job, 'receipt_accepted', device.pk)
    return ack


def _human_job(job_id):
    # First read only discovers the device; lock the mutable rows in global order.
    try: device_id=Job.objects.values_list('device_id',flat=True).get(pk=job_id, protocol_family=FAMILY)
    except Job.DoesNotExist: raise wire.ExecutionError('job_not_found') from None
    lock_device_ownership(device_id)
    Device.objects.select_for_update().get(pk=device_id)
    list(DeviceExecutionBinding.objects.select_for_update().filter(device_id=device_id).order_by('pk'))
    return Job.objects.select_for_update().get(pk=job_id, protocol_family=FAMILY)


@transaction.atomic
def cancel_execution(actor, job_id):
    lock_human_authority(); actor=require_product_permission(actor,'run_jobs'); lock_dispatch()
    job=_human_job(job_id)
    if job.execution_state not in ('queued','leased'): raise wire.ExecutionError('job_conflict')
    job.execution_state='cancelled'; job.save(update_fields=['execution_state'])
    audit(job,'cancelled',actor.pk)
    return job_dto(job)


@transaction.atomic
def reconcile_execution(actor, job_id, *, reason, evidence_refs):
    lock_human_authority(); actor=require_product_admin(actor); lock_dispatch()
    job=_human_job(job_id)
    if job.execution_state == 'draft' or job.collection_state in ('collecting','reconciled'):
        raise wire.ExecutionError('job_conflict')
    ExecutionOwnerDecision.objects.create(actor=actor, action='reconciliation', job=job, reason=reason, evidence_refs=evidence_refs)
    job.collection_state='reconciled'
    if job.execution_state in ('queued','leased','started'): job.execution_state='execution_unknown'
    job.save(update_fields=['collection_state','execution_state']); audit(job,'owner_reconciled',actor.pk)
    return job_dto(job)


@transaction.atomic
def current_execution_job(actor):
    lock_human_authority()
    actor = require_product_permission(actor, 'view')
    lock_dispatch()
    latest = ExecutionIdempotency.objects.filter(actor=actor, operation='approve', job__protocol_family=FAMILY).select_related('job').order_by('-job__created_at', '-pk').first()
    return checked('CurrentJobDTO', dict(job=asdict(job_dto(latest.job)) if latest else None))


def get_execution_job(actor, job_id):
    require_product_permission(actor,'view')
    try: job=Job.objects.get(pk=job_id, protocol_family=FAMILY)
    except Job.DoesNotExist: raise wire.ExecutionError('job_not_found') from None
    return job_dto(job)


def get_execution_device(actor, device_id, *, now):
    require_product_permission(actor,'view')
    if not Device.objects.filter(pk=device_id, archived_at__isnull=True).exists(): raise wire.ExecutionError('job_not_found')
    return execution_readiness(device_id, now=now)


def execution_providers(actor):
    require_product_permission(actor,'view')
    providers=[]
    for release in RunnerRelease.objects.order_by('pk'):
        try: definition=_definition(release)
        except (ValueError, OSError): continue
        providers.append(wire.ProviderDTO(wire.PROVIDER_ID, definition.scenario_id, definition.runner_id,
            definition.runner_version, definition.release_id, hashlib.sha256(wire.release_definition_bytes(definition)).hexdigest(),
            definition.allow_rehearsal, definition.timeout_seconds))
    return wire.ProviderList(tuple(providers))
