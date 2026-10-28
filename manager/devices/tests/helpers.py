"""Synthetic issuer and endpoint inputs; no private deployment state."""
import importlib
import importlib.util
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from django.test import override_settings

from accounts.tests.helpers import AccountsCase


def component(case, name):
    case.assertIsNotNone(importlib.util.find_spec("devices." + name), "pairing component is missing")
    return importlib.import_module("devices." + name)


def csr(key=None, algorithm=None, extensions=False):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=3072)
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "untrusted requested identity")]))
    if extensions:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier("urn:foreign:requested")]), critical=False)
    request = builder.sign(key, algorithm or hashes.SHA256())
    return key, request.public_bytes(serialization.Encoding.PEM).decode("ascii")


def duplicate_extension_certificate(key, certificate):
    """Build real malformed DER; the public certificate builder forbids duplicates.

    Keep the original key, identity, dates and signature algorithm, duplicate a
    real extension, and sign the changed TBS so signature corruption cannot mask
    the extension parser failure. Only synthetic test certificates enter here.
    """
    def encode(tag, value):
        size = len(value)
        length = bytes([size]) if size < 128 else size.to_bytes((size.bit_length() + 7) // 8, "big")
        if size >= 128:
            length = bytes([0x80 | len(length)]) + length
        return bytes([tag]) + length + value

    def parts(value):
        while value:
            tag, size, offset = value[0], value[1], 2
            if size & 0x80:
                count = size & 0x7f
                size, offset = int.from_bytes(value[2:2 + count], "big"), 2 + count
            yield tag, value[offset:offset + size]
            value = value[offset + size:]

    _, outer = next(parts(certificate.public_bytes(serialization.Encoding.DER)))
    certificate_parts = list(parts(outer))
    fields = list(parts(certificate_parts[0][1]))
    assert fields[-1][0] == 0xa3, "Synthetic issuer must have explicit extensions"
    _, extensions = next(parts(fields[-1][1]))
    first = next(parts(extensions))
    fields[-1] = (0xa3, encode(0x30, extensions + encode(*first)))
    tbs = encode(0x30, b"".join(encode(*field) for field in fields))
    signature = key.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
    der = encode(0x30, tbs + encode(*certificate_parts[1]) + encode(0x03, b"\x00" + signature))
    return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)


class PairingCase(AccountsCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aegis-synthetic-enrollment-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.settings_override = override_settings(
            PRIVATE_ROOT=self.root, ENROLLMENT_CA_KEY=str(self.root / "issuer-key.pem"),
            ENROLLMENT_CA_CERT=str(self.root / "issuer.pem"))
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)

    def initialize(self):
        component(self, "issuer").initialize_issuer()

    def install_duplicate_extension_issuer(self):
        self.initialize()
        key, certificate = component(self, "issuer").load_issuer()
        pem = duplicate_extension_certificate(key, certificate)
        # Confirm the malformed input exercises the real DuplicateExtension path.
        with self.assertRaises(x509.DuplicateExtension):
            x509.load_pem_x509_certificate(pem).extensions
        (self.root / "issuer.pem").write_bytes(pem)
        return {path.name: path.read_bytes() for path in self.root.iterdir()}

    def mint(self):
        return component(self, "services").create_pairing_code(actor=self.admin, environment_id="synthetic.env")

    def enrollment(self, code=None, pem=None):
        if code is None:
            code = self.mint()["code"]
        if pem is None:
            _, pem = csr()
        return {"protocol": "2.0", "pairing_code": code, "csr_pem": pem, "hostname": "synthetic-host",
                "os": "linux", "architecture": "x64", "agent_version": "0.1.0"}
