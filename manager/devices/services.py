"""Authority → code → device lock ordering for pairing and revocation."""
import hashlib
import secrets
import uuid
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django.db import transaction
from django.utils import timezone

from accounts.models import AccountMutationLock
from accounts.permissions import require_product_permission
from control.models import Device
from . import issuer
from .contracts import DeviceError, enrollment_input, environment, heartbeat_input, stamp
from .identity import certificate_fingerprint, observed_peer_ip
from .network import network_heartbeat_input
from .models import PairingCode, EnrollmentAudit


def _lock_authority():
    AccountMutationLock.objects.select_for_update().get(pk=1)


@transaction.atomic
def create_pairing_code(*, actor, environment_id):
    _lock_authority()
    actor = require_product_permission(actor, "manage_devices")
    environment_id = environment(environment_id)
    code, now = secrets.token_hex(32), timezone.now()
    row = PairingCode.objects.create(code_sha256=hashlib.sha256(code.encode("ascii")).hexdigest(),
        environment_id=environment_id, issued_by=actor, created_at=now, expires_at=now + timedelta(seconds=600))
    EnrollmentAudit.objects.create(actor_id=actor.pk, action="pairing_code_created", code_id=row.pk)
    return {"id": str(row.pk), "code": code, "environment_id": row.environment_id, "expires_at": stamp(row.expires_at)}


@transaction.atomic
def revoke_pairing_code(*, actor, code_id):
    _lock_authority()
    actor = require_product_permission(actor, "manage_devices")
    try:
        code = PairingCode.objects.select_for_update().get(pk=code_id)
    except (PairingCode.DoesNotExist, ValueError):
        raise DeviceError("invalid_request") from None
    if not code.revoked:
        code.revoked = True
        code.save(update_fields=["revoked"])
        EnrollmentAudit.objects.create(actor_id=actor.pk, action="pairing_code_revoked", code_id=code.pk)


@transaction.atomic
def revoke_device(*, actor, device_id):
    _lock_authority()
    actor = require_product_permission(actor, "manage_devices")
    try:
        device = Device.objects.select_for_update().get(pk=device_id)
    except (Device.DoesNotExist, ValueError):
        raise DeviceError("invalid_request") from None
    if device.connection_kind != "paired_presence":
        raise DeviceError("device_conflict")
    if not device.revoked:
        device.revoked = True
        device.save(update_fields=["revoked"])
        EnrollmentAudit.objects.create(actor_id=actor.pk, action="device_revoked", device_id=device.pk)


@transaction.atomic
def enroll_device(data):
    data = enrollment_input(data)
    try:
        issuer.validate_csr(data["csr_pem"])
    except ValueError:
        raise DeviceError("invalid_request") from None
    _lock_authority()
    try:
        code = PairingCode.objects.select_for_update().get(code_sha256=hashlib.sha256(data["pairing_code"].encode("ascii")).hexdigest())
    except PairingCode.DoesNotExist:
        raise DeviceError("pairing_denied") from None
    now = timezone.now()
    if code.revoked or code.consumed_at is not None or code.expires_at <= now:
        raise DeviceError("pairing_denied")
    try:
        actor = require_product_permission(code.issued_by, "manage_devices")
    except PermissionError:
        raise DeviceError("pairing_denied") from None
    device_id = uuid.uuid4()
    try:
        certificate_pem, issuer_pem = issuer.issue_certificate(csr_pem=data["csr_pem"], device_id=device_id)
    except issuer.IssuerUnavailable:
        raise DeviceError("issuer_unavailable") from None
    cert = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    device = Device.objects.create(id=device_id, environment_id=code.environment_id, generation=1,
        certificate_sha256=cert.fingerprint(hashes.SHA256()).hex(), connection_kind="paired_presence", wazuh_agent_id=None,
        hostname=data["hostname"], os=data["os"], architecture=data["architecture"], agent_version=data["agent_version"],
        enrolled_at=now, certificate_not_before=cert.not_valid_before_utc, certificate_expires_at=cert.not_valid_after_utc)
    code.consumed_device, code.consumed_at = device, now
    code.save(update_fields=["consumed_device", "consumed_at"])
    EnrollmentAudit.objects.create(actor_id=actor.pk, action="device_enrolled", code_id=code.pk, device_id=device.pk)
    return {"protocol": "2.0", "device_id": str(device.pk), "environment_id": device.environment_id, "generation": 1,
            "certificate_pem": certificate_pem, "issuer_pem": issuer_pem, "expires_at": stamp(device.certificate_expires_at),
            "heartbeat_seconds": 15, "offline_after_seconds": 60}


@transaction.atomic
def receive_heartbeat(*, request, data, network=False):
    data = network_heartbeat_input(data) if network else heartbeat_input(data)
    fingerprint = certificate_fingerprint(request)
    try:
        device = Device.objects.select_for_update().get(pk=data["device_id"], certificate_sha256=fingerprint,
            connection_kind="paired_presence", generation=data["generation"])
    except Device.DoesNotExist:
        raise DeviceError("identity_denied") from None
    now = timezone.now()
    if (device.archived_at is not None or device.revoked or device.certificate_not_before is None or device.certificate_expires_at is None
            or not device.certificate_not_before <= now < device.certificate_expires_at):
        raise DeviceError("identity_denied")
    peer = observed_peer_ip(request)
    report = data["network"] if network else None
    values = {"last_heartbeat_at": now, "observed_ip": peer, "observed_ip_received_at": now if peer is not None else None,
              "reported_ips": report["reported_ips"] if report else None,
              "ip_collection_status": report["collection_status"] if report else "unknown",
              "reported_ips_truncated": report["truncated"] if report else False,
              "reported_ips_received_at": now if report else None,
              "reported_agent_version": report["agent_version"] if report else None}
    for name, value in values.items():
        setattr(device, name, value)
    device.save(update_fields=list(values))
    return {"protocol": "2.1" if network else "2.0", "server_time": stamp(now), "heartbeat_seconds": 15, "offline_after_seconds": 60}
