"""Versioned inventory presentation; old closed DTO remains unchanged."""
import ipaddress

from django.db.models import Q

from control.models import Device
from .archive import archive_block_reason
from .contracts import DeviceError, canonical_uuid, device_dto, devices_query, stamp
from .models import EnrollmentAudit, PairingCode


def device_v2_dto(device):
    result = device_dto(device)
    result.update({name: getattr(device, name) for name in (
        "reported_ips", "ip_collection_status", "reported_ips_truncated", "observed_ip",
        "reported_agent_version", "archived_by_id")})
    result.update({name: stamp(getattr(device, name)) for name in (
        "reported_ips_received_at", "observed_ip_received_at", "archived_at")})
    reason = archive_block_reason(device)
    result.update(can_archive=reason is None, archive_block_reason=reason)
    if device.archived_at is not None:
        result["status"] = "archived"
    return result


def get_device(device_id):
    key = canonical_uuid(str(device_id))
    try:
        return Device.objects.prefetch_related("job_set").get(pk=key)
    except Device.DoesNotExist:
        raise DeviceError("device_not_found") from None


def inventory_query(request):
    page, search = devices_query(request, allowed={"scope", "page", "search"})
    scope = request.GET.get("scope", "managed")
    if scope not in {"managed", "archived"}:
        raise DeviceError("invalid_request")
    rows = Device.objects.filter(archived_at__isnull=scope == "managed")
    if search:
        match = Q(hostname__icontains=search) | Q(environment_id__icontains=search) | Q(wazuh_agent_id__icontains=search)
        try:
            address = ipaddress.ip_address(search)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            address = str(address)
        except ValueError:
            pass
        else:
            match |= Q(observed_ip=address)
            # Bounded canonical snapshots have at most 32 addresses. Explicit
            # JSON indices support both PostgreSQL and the SQLite fixture path.
            for index in range(32):
                match |= Q(**{f"reported_ips__{index}": address})
        rows = rows.filter(match)
    return page, rows.prefetch_related("job_set").order_by("pk")


def history_query(device):
    codes = PairingCode.objects.filter(consumed_device=device).values("pk")
    audit_codes = EnrollmentAudit.objects.filter(device_id=device.pk, code_id__isnull=False).values("code_id")
    return EnrollmentAudit.objects.filter(
        Q(device_id=device.pk) | Q(code_id__in=codes) | Q(code_id__in=audit_codes)
    ).order_by("-created_at", "-pk")


def history_dto(row):
    return {"action": row.action, "created_at": stamp(row.created_at), "actor_id": row.actor_id,
            "code_id": str(row.code_id) if row.code_id is not None else None,
            "device_id": str(row.device_id) if row.device_id is not None else None}
