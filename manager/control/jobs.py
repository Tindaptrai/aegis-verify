import hashlib
import re
import uuid
from pathlib import Path
from django.db import transaction
from django.utils import timezone
from accounts.permissions import require_product_admin, require_product_permission
from .models import Job, Device, DispatchLock, AuditEntry
from .signing import sign_payload
from aegis_verify.intake.io import read_local
from aegis_verify.intake.errors import IntakeError
from .execution_ownership import lock_human_authority, lock_device_ownership, guard_execution_owner, require_idle

TERMINAL_COLLECTION = ("evaluated", "empty", "reconciled")
HEX = re.compile(r"[0-9a-f]{64}\Z")


def audit(job, action, actor):
    AuditEntry.objects.create(job=job, action=action, actor=str(actor))


def lock_dispatch():
    DispatchLock.objects.select_for_update().get(pk=1)


def release_pins(release):
    for name in ("scenario", "profile"):
        path = Path(getattr(release, name + "_path"))
        if not path.is_absolute() or hashlib.sha256(read_local(path, limit=4 * 1024 * 1024, stage="inputs")).hexdigest() != getattr(release, name + "_sha256"):
            raise ValueError("Release pin mismatch")
    for name in ("scenario", "profile", "runner", "kit", "payload"):
        if not HEX.fullmatch(getattr(release, name + "_sha256")):
            raise ValueError("Invalid release digest")
    if type(release.timeout_seconds) is not int or not 180 <= release.timeout_seconds <= 300:
        raise ValueError("Invalid timeout")


def stamp(value):
    if value.microsecond: raise ValueError("Times require second precision")
    return value.astimezone(timezone.get_default_timezone()).strftime("%Y-%m-%dT%H:%M:%SZ")


@transaction.atomic
def approve_job(job_id, actor):
    lock_human_authority()
    actor = require_product_permission(actor, "run_jobs")
    lock_dispatch()
    device_id = Job.objects.values_list('device_id', flat=True).get(pk=job_id)
    lock_device_ownership(device_id)
    device = Device.objects.select_for_update().get(pk=device_id)
    if device.connection_kind != 'legacy_v1': raise ValueError('Device unavailable')
    guard_execution_owner(device)
    job = Job.objects.select_for_update().select_related("device", "release").get(pk=job_id)
    if job.protocol_family != 'legacy_v1': raise ValueError('Use execution approval')
    if job.execution_state != "draft": raise ValueError("Job already approved")
    require_idle(active_job_id=job.pk)
    release = job.release
    release_pins(release)
    if device.connection_kind != "legacy_v1" or device.revoked or device.archived_at is not None or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", device.environment_id) or not 1 <= device.generation <= 2147483647:
        raise ValueError("Device unavailable")
    p = job.parameters
    if not isinstance(p, dict) or set(p) != {"run_label", "rule_revision", "rule_sha256"}: raise ValueError("Invalid parameters")
    if p["run_label"] not in ("A", "B", "C", "Rehearsal") or p["rule_revision"] not in ("baseline", "behavioral"): raise ValueError("Invalid parameters")
    if p["run_label"] in ("A", "B") and p["rule_revision"] != "baseline" or p["run_label"] == "C" and p["rule_revision"] != "behavioral": raise ValueError("Invalid revision")
    if p["run_label"] == "Rehearsal" and not release.allow_rehearsal: raise ValueError("Rehearsal disabled")
    if not isinstance(p["rule_sha256"], str) or not HEX.fullmatch(p["rule_sha256"]) or p["rule_sha256"] != release.rule_hashes.get(p["rule_revision"]): raise ValueError("Invalid rule pin")
    ttl = (job.expires_at-job.not_before).total_seconds()
    if not 0 < ttl <= 300 or job.expires_at <= timezone.now() or job.collection_start > job.not_before or job.collection_end < job.expires_at + timezone.timedelta(seconds=release.timeout_seconds) or (job.collection_end-job.collection_start).total_seconds() > 900:
        raise ValueError("Invalid approval bounds")
    job.approval_id = uuid.uuid4()
    payload = {"protocol":"0.1.0", "job_id":str(job.id), "run_id":str(job.id), "agent_id":str(device.id), "approval_id":str(job.approval_id), "environment_id":device.environment_id, "generation":device.generation, "scenario_id":"SCN-001", "runner_id":"scn001-safe-demo", "runner_version":"0.3.0", "timeout_seconds":release.timeout_seconds, "parameters":p}
    payload.update({name+"_sha256":getattr(release,name+"_sha256") for name in ("scenario", "profile", "runner", "kit", "payload")})
    payload.update({name:stamp(getattr(job,name)) for name in ("not_before", "expires_at", "collection_start", "collection_end")})
    job.envelope, job.payload_sha256 = sign_payload(payload)
    job.approved_wazuh_agent_id = device.wazuh_agent_id
    job.approved_generation = device.generation
    job.evaluation_bindings = release.evaluation_bindings
    job.execution_state = "queued"
    job.save()
    audit(job,"approved",actor.pk)
    return job


@transaction.atomic
def claim_job(device):
    lock_dispatch()
    lock_device_ownership(device.pk)
    device = Device.objects.select_for_update().get(pk=device.pk)
    if device.archived_at is not None or device.revoked or device.connection_kind != "legacy_v1": raise PermissionError()
    guard_execution_owner(device)
    job = Job.objects.select_for_update().filter(device=device, protocol_family='legacy_v1', approved_generation=device.generation, execution_state__in=("queued", "leased")).order_by("created_at").first()
    if job is None: return None
    now = timezone.now()
    if now > job.expires_at or now < job.not_before: return None
    if job.execution_state == "queued":
        job.execution_state = "leased"; job.save(update_fields=["execution_state"])
        audit(job,"leased",device.pk)
    return job


@transaction.atomic
def reconcile_job(job_id, actor):
    lock_human_authority()
    actor = require_product_admin(actor)
    lock_dispatch()
    job = Job.objects.select_for_update().get(pk=job_id)
    if job.protocol_family != 'legacy_v1': raise ValueError('Explicit owner reason and evidence required')
    if job.execution_state == "draft" or job.collection_state == "collecting": raise ValueError("Cannot reconcile draft or active collection")
    job.collection_state = "reconciled"
    if job.execution_state in ("queued", "leased", "started"):
        job.execution_state = "execution_unknown"
    job.save(update_fields=["collection_state", "execution_state"])
    audit(job,"owner_reconciled",actor.pk)
    return job


@transaction.atomic
def cancel_job(job_id, actor):
    lock_human_authority()
    actor = require_product_permission(actor, "run_jobs")
    lock_dispatch()
    job = Job.objects.select_for_update().get(pk=job_id)
    if job.protocol_family != 'legacy_v1': raise ValueError('Use execution cancellation')
    if job.execution_state not in ("draft", "queued", "leased"):
        raise ValueError("Only unstarted jobs can be cancelled")
    job.execution_state = "cancelled"
    job.save(update_fields=["execution_state"])
    audit(job,"cancelled",actor.pk)
    return job
