"""Archive identity atomically, preserving all linked records and immutable audit."""
from django.db import transaction
from django.utils import timezone

from accounts.permissions import require_product_permission
from control.jobs import lock_dispatch
from control.models import Device
from .contracts import DeviceError
from .models import EnrollmentAudit
from .services import _lock_authority
from control.execution_ownership import lock_device_ownership, execution_job_blocks


def archive_block_reason(device, jobs=None):
    if device.archived_at is not None:
        return "already_archived"
    if device.connection_kind != "paired_presence":
        return "legacy_device"
    if jobs is None:
        jobs = device.job_set.all()
    for job in jobs:
        if job.protocol_family == 'windows_execution_v2':
            if execution_job_blocks(job): return 'device_busy'
            continue
        allowed = {"evaluated", "empty", "reconciled"}
        if job.execution_state in {"draft", "cancelled", "expired"}:
            allowed.add("pending")
        elif job.execution_state not in {"succeeded", "failed", "execution_unknown"}:
            return "device_busy"
        if job.collection_state not in allowed:
            return "device_busy"
    return None


@transaction.atomic
def archive_device(*, actor, device_id):
    _lock_authority()
    actor = require_product_permission(actor, "manage_devices")
    lock_dispatch()
    lock_device_ownership(device_id)
    try:
        device = Device.objects.select_for_update().get(pk=device_id)
    except Device.DoesNotExist:
        raise DeviceError("device_not_found") from None
    jobs = list(device.job_set.select_for_update().order_by("pk"))
    reason = archive_block_reason(device, jobs)
    if reason == "already_archived":
        return
    if reason is not None:
        raise DeviceError("device_conflict" if reason == "legacy_device" else reason)
    if not device.revoked:
        EnrollmentAudit.objects.create(actor_id=actor.pk, action="device_revoked", device_id=device.pk)
    device.revoked = True
    device.archived_at, device.archived_by_id = timezone.now(), actor.pk
    device.save(update_fields=["revoked", "archived_at", "archived_by_id"])
    EnrollmentAudit.objects.create(actor_id=actor.pk, action="device_archived", device_id=device.pk)
