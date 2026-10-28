"""Trust only the local TLS proxy; identity headers never establish trust alone."""
import ipaddress
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django.utils import timezone

from .contracts import DeviceError


def require_https(request, *, error="pairing_denied"):
    try:
        if (not ipaddress.ip_address(request.META.get("REMOTE_ADDR", "")).is_loopback
                or not (request.is_secure() or request.META.get("HTTP_X_FORWARDED_PROTO") == "https")):
            raise ValueError
    except ValueError:
        raise DeviceError(error) from None


def certificate_fingerprint(request):
    require_https(request, error="identity_denied")
    try:
        if (request.META.get("HTTP_X_FORWARDED_PROTO") != "https"
                or request.META.get("HTTP_X_AEGIS_CLIENT_VERIFY") != "SUCCESS"):
            raise ValueError
        header = request.META.get("HTTP_X_AEGIS_CLIENT_CERT", "")
        if len(header) > 16384:
            raise ValueError
        cert = x509.load_pem_x509_certificate(unquote(header, errors="strict").encode("ascii"))
        now = timezone.now()
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise ValueError
        return cert.fingerprint(hashes.SHA256()).hex()
    except (ValueError, TypeError, UnicodeError):
        raise DeviceError("identity_denied") from None
