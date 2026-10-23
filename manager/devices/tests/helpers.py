"""Synthetic issuer and endpoint inputs; no private deployment state."""
import importlib
import importlib.util
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
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

    def mint(self):
        return component(self, "services").create_pairing_code(actor=self.admin, environment_id="synthetic.env")

    def enrollment(self, code=None, pem=None):
        if code is None:
            code = self.mint()["code"]
        if pem is None:
            _, pem = csr()
        return {"protocol": "2.0", "pairing_code": code, "csr_pem": pem, "hostname": "synthetic-host",
                "os": "linux", "architecture": "x64", "agent_version": "0.1.0"}
