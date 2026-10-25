import ipaddress
from urllib.parse import unquote
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django.utils import timezone
from .models import Device


def authenticate_device(request):
    try:
        if not ipaddress.ip_address(request.META.get("REMOTE_ADDR", "")).is_loopback:
            raise ValueError()
        if request.META.get("HTTP_X_FORWARDED_PROTO") != "https" or request.META.get("HTTP_X_AEGIS_CLIENT_VERIFY") != "SUCCESS":
            raise ValueError()
        pem = unquote(request.META.get("HTTP_X_AEGIS_CLIENT_CERT", ""), errors="strict").encode("ascii")
        cert = x509.load_pem_x509_certificate(pem)
        now = timezone.now()
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise ValueError()
        return Device.objects.get(certificate_sha256=cert.fingerprint(hashes.SHA256()).hex(), revoked=False, archived_at__isnull=True, connection_kind="legacy_v1")
    except (ValueError, UnicodeError, Device.DoesNotExist):
        raise PermissionError("Machine identity denied") from None
