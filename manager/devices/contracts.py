"""Closed v2 wire contracts and bounded presentation of presence state."""
import json
import re
import unicodedata
import uuid

from django.core.exceptions import RequestDataTooBig
from django.utils import timezone

from accounts.contracts import _unique_object, _invalid_constant

ERRORS = {"invalid_request": 400, "pairing_denied": 403, "issuer_unavailable": 503,
          "identity_denied": 403, "temporarily_unavailable": 503, "device_conflict": 409,
          "device_busy": 409, "device_not_found": 404}


class DeviceError(ValueError):
    def __init__(self, code):
        self.code, self.status = code, ERRORS[code]
        super().__init__(code)


def parse_json(request):
    try:
        if request.content_type != "application/json":
            raise ValueError
        # Never trust Content-Length, including under ASGI/chunked adapters.
        # A finite read also prevents allocating an unbounded request.body.
        raw = request.read(16385)
        if len(raw) > 16384:
            raise ValueError
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if type(data) is not dict:
            raise ValueError
        return data
    except (ValueError, UnicodeError, RecursionError, RequestDataTooBig, OSError):
        raise DeviceError("invalid_request") from None


def environment(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value):
        raise DeviceError("invalid_request")
    return value


def canonical_uuid(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        raise DeviceError("invalid_request") from None


def enrollment_input(data):
    if (type(data) is not dict or set(data) != {"protocol", "pairing_code", "csr_pem", "hostname", "os", "architecture", "agent_version"}
            or any(type(v) is not str for v in data.values())):
        raise DeviceError("invalid_request")
    if (data["protocol"] != "2.0" or data["os"] not in ("windows", "linux") or data["architecture"] != "x64"
            or data["agent_version"] != "0.1.0" or not re.fullmatch(r"[0-9a-f]{64}", data["pairing_code"])
            or not 1 <= len(data["hostname"]) <= 255
            or any(unicodedata.category(c).startswith("C") or not c.isprintable() for c in data["hostname"])
            or not data["csr_pem"].isascii() or len(data["csr_pem"]) > 8192):
        raise DeviceError("invalid_request")
    return data


def heartbeat_input(data):
    if (type(data) is not dict or set(data) != {"protocol", "device_id", "generation"} or data["protocol"] != "2.0"
            or type(data["generation"]) is not int or not 1 <= data["generation"] <= 2147483647):
        raise DeviceError("invalid_request")
    canonical_uuid(data["device_id"])
    return data


def stamp(value):
    return value.isoformat().replace("+00:00", "Z") if value is not None else None


def device_status(device, *, now=None):
    now = now or timezone.now()
    if device.revoked:
        return "revoked"
    if device.certificate_expires_at is not None and now >= device.certificate_expires_at:
        return "expired"
    if device.connection_kind == "legacy_v1":
        return "unknown"
    if (device.certificate_not_before is None or device.certificate_expires_at is None
            or now < device.certificate_not_before or device.last_heartbeat_at is None):
        return "offline"
    return "online" if 0 <= (now - device.last_heartbeat_at).total_seconds() < 60 else "offline"


def device_dto(device, *, now=None):
    return {"id": str(device.pk), "hostname": device.hostname or None, "environment_id": device.environment_id,
            "wazuh_agent_id": device.wazuh_agent_id or None, "connection_kind": device.connection_kind,
            "os": device.os, "architecture": device.architecture, "agent_version": device.agent_version,
            "generation": device.generation, "status": device_status(device, now=now),
            "last_heartbeat_at": stamp(device.last_heartbeat_at), "certificate_expires_at": stamp(device.certificate_expires_at),
            "execution_supported": False}


def devices_query(request, *, allowed=None):
    query = request.GET
    if set(query) - (allowed if allowed is not None else {"page", "search"}) or any(len(query.getlist(k)) != 1 for k in query):
        raise DeviceError("invalid_request")
    raw, search = query.get("page", "1"), query.get("search", "")
    if not raw.isascii() or not raw.isdecimal() or len(raw) > 9 or int(raw) < 1 or len(search) > 100:
        raise DeviceError("invalid_request")
    return int(raw), search
