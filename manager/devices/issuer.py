"""Explicit private issuer initialization; loading is lazy and never repairs state."""
import os
import stat
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.conf import settings
from django.utils import timezone


class IssuerUnavailable(Exception):
    pass


def _safe_path(path, root, *, regular=False):
    if (not path.is_absolute() or ".." in path.parts or not path.is_relative_to(root)
            or not path.resolve().is_relative_to(root)):
        raise IssuerUnavailable()
    for part in [path, *path.parents]:
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise IssuerUnavailable()
        if part.is_dir() and os.name != "nt" and (part.stat().st_mode & 0o077 or part.stat().st_uid != os.geteuid()):
            raise IssuerUnavailable()
        if part == root:
            break
    if not path.parent.is_dir():
        raise IssuerUnavailable()
    if regular:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 32768 or info.st_nlink != 1:
            raise IssuerUnavailable()
        if os.name != "nt" and (info.st_mode & 0o077 or info.st_uid != os.geteuid()):
            raise IssuerUnavailable()


def _paths():
    try:
        root = Path(settings.PRIVATE_ROOT)
        key, cert = Path(settings.ENROLLMENT_CA_KEY), Path(settings.ENROLLMENT_CA_CERT)
        if not root.is_absolute() or not root.is_dir() or root.resolve() != root:
            raise IssuerUnavailable()
        if os.name != "nt" and (root.stat().st_mode & 0o077 or root.stat().st_uid != os.geteuid()):
            raise IssuerUnavailable()
        for path in (key, cert):
            _safe_path(path, root)
        if key == cert or key.resolve() == Path(getattr(settings, "MANAGER_SIGNING_KEY", "")).resolve():
            raise IssuerUnavailable()
        return root, key, cert
    except (AttributeError, TypeError, ValueError, OSError):
        raise IssuerUnavailable() from None


def load_issuer():
    try:
        root, key_path, cert_path = _paths()
        for path in (key_path, cert_path):
            _safe_path(path, root, regular=True)
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        if (not isinstance(key, rsa.RSAPrivateKey) or not 3072 <= key.key_size <= 4096
                or key.public_key().public_numbers() != cert.public_key().public_numbers()
                or cert.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AEGIS Enrollment CA")])
                or cert.subject != cert.issuer or not cert.not_valid_before_utc <= timezone.now() < cert.not_valid_after_utc
                or cert.signature_hash_algorithm.name != "sha256"
                or not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length != 0
                or not cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
                or not cert.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign):
            raise IssuerUnavailable()
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
        signing = getattr(settings, "MANAGER_SIGNING_KEY", None)
        if signing:
            other = serialization.load_pem_private_key(Path(signing).read_bytes(), password=None)
            if other.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
                raise IssuerUnavailable()
        return key, cert
    except (OSError, ValueError, TypeError, AttributeError, x509.ExtensionNotFound, x509.DuplicateExtension,
            InvalidSignature, UnsupportedAlgorithm):
        raise IssuerUnavailable() from None


def initialize_issuer():
    root, key_path, cert_path = _paths()
    if key_path.exists() or cert_path.exists():
        load_issuer()
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = timezone.now().replace(microsecond=0)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AEGIS Enrollment CA")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    try:
        # O_EXCL never replaces a competing initializer's state. A failed write
        # leaves explicit partial state for the operator to inspect, not repair.
        for path, data in ((key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption())),
                           (cert_path, cert.public_bytes(serialization.Encoding.PEM))):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
    except OSError:
        raise IssuerUnavailable() from None
    load_issuer()


def validate_csr(csr_pem):
    try:
        request = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        key = request.public_key()
        if (not isinstance(key, rsa.RSAPublicKey) or not 3072 <= key.key_size <= 4096
                or request.signature_hash_algorithm.name != "sha256" or not request.is_signature_valid):
            raise ValueError()
        return request
    except (ValueError, TypeError, AttributeError, UnicodeError, UnsupportedAlgorithm):
        raise ValueError("invalid_csr") from None


def issue_certificate(*, csr_pem, device_id):
    request = validate_csr(csr_pem)
    key, issuer = load_issuer()
    now = timezone.now().replace(microsecond=0)
    if issuer.not_valid_after_utc < now + timedelta(days=30):
        raise IssuerUnavailable()
    try:
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AEGIS-Agent-" + str(device_id))]))
                .issuer_name(issuer.subject).public_key(request.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier("urn:aegis:agent:" + str(device_id))]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(request.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
                .sign(key, hashes.SHA256()))
        return (cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                issuer.public_bytes(serialization.Encoding.PEM).decode("ascii"))
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise IssuerUnavailable() from None
