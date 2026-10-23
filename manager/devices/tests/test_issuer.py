import io
import os
import uuid
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings
from django.utils import timezone

from .helpers import PairingCase, component, csr


class IssuerTests(PairingCase):
    def test_duplicate_extensions_are_normalized_as_issuer_unavailable(self):
        self.install_duplicate_extension_issuer()
        issuer = component(self, "issuer")
        with self.assertRaises(issuer.IssuerUnavailable):
            issuer.load_issuer()

    def test_init_command_refuses_duplicate_extensions_with_fixed_diagnostic(self):
        before = self.install_duplicate_extension_issuer()
        output = io.StringIO()
        with self.assertRaises(CommandError) as failure:
            call_command("init_enrollment_ca", stdout=output)
        self.assertEqual(str(failure.exception), "Enrollment issuer unavailable; inspect configured paths and permissions.")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.root.iterdir()})

    def test_configured_parent_traversal_cannot_escape_private_root(self):
        issuer = component(self, "issuer")
        private = self.root / "private"
        private.mkdir(mode=0o700)
        with override_settings(PRIVATE_ROOT=private, ENROLLMENT_CA_KEY=str(private / ".." / "escaped-key.pem"),
                               ENROLLMENT_CA_CERT=str(private / "issuer.pem")):
            with self.assertRaises(issuer.IssuerUnavailable):
                issuer.initialize_issuer()
        self.assertFalse((self.root / "escaped-key.pem").exists())

    def test_job_signing_key_is_never_reused_as_issuer(self):
        self.initialize()
        issuer = component(self, "issuer")
        job = self.root / "job-key.pem"
        job.write_bytes((self.root / "issuer-key.pem").read_bytes())
        with override_settings(MANAGER_SIGNING_KEY=str(job)):
            with self.assertRaises(issuer.IssuerUnavailable):
                issuer.load_issuer()

    def test_foreign_ca_identity_is_never_adopted_as_enrollment_issuer(self):
        self.initialize()
        issuer = component(self, "issuer")
        key, current = issuer.load_issuer()
        foreign = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic legacy pilot issuer")])
        builder = (x509.CertificateBuilder().subject_name(foreign).issuer_name(foreign).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(current.not_valid_before_utc)
                   .not_valid_after(current.not_valid_after_utc))
        for extension in current.extensions:
            builder = builder.add_extension(extension.value, extension.critical)
        (self.root / "issuer.pem").write_bytes(builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
        with self.assertRaises(issuer.IssuerUnavailable):
            issuer.initialize_issuer()

    def test_initialization_is_idempotent_and_command_has_no_secret_output(self):
        self.initialize()
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        output = io.StringIO()
        call_command("init_enrollment_ca", stdout=output)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})
        self.assertNotIn("BEGIN", output.getvalue())

    def test_partial_state_is_never_replaced(self):
        path = self.root / "issuer.pem"
        path.write_text("synthetic incomplete state")
        issuer = component(self, "issuer")
        with self.assertRaises(issuer.IssuerUnavailable):
            issuer.initialize_issuer()
        self.assertEqual(path.read_text(), "synthetic incomplete state")
        self.assertFalse((self.root / "issuer-key.pem").exists())

    def test_existing_invalid_or_mismatched_issuer_is_rejected(self):
        self.initialize()
        issuer = component(self, "issuer")
        path = self.root / "issuer-key.pem"
        other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        path.write_bytes(other.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
        with self.assertRaises(issuer.IssuerUnavailable):
            issuer.initialize_issuer()

    def test_expired_future_non_ca_or_missing_signing_usage_is_refused(self):
        self.initialize()
        issuer = component(self, "issuer")
        key, original = issuer.load_issuer()
        now = timezone.now().replace(microsecond=0)
        for state in ("expired", "future", "non_ca", "no_signing"):
            before = now + timedelta(days=1) if state == "future" else now - timedelta(days=2)
            after = now - timedelta(days=1) if state == "expired" else now + timedelta(days=3650)
            ca = state != "non_ca"
            cert = (x509.CertificateBuilder().subject_name(original.subject).issuer_name(original.subject)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(before).not_valid_after(after)
                    .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
                    .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                        data_encipherment=False, key_agreement=False, key_cert_sign=state != "no_signing", crl_sign=True,
                        encipher_only=False, decipher_only=False), critical=True).sign(key, hashes.SHA256()))
            (self.root / "issuer.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            with self.subTest(state=state), self.assertRaises(issuer.IssuerUnavailable):
                issuer.initialize_issuer()

    def test_symlink_or_insecure_posix_state_is_rejected(self):
        issuer = component(self, "issuer")
        if os.name == "nt":
            self.skipTest("POSIX mode/symlink gate runs on Linux; Windows symlink privilege unavailable")
        target = self.root / "target"
        target.write_text("preserve")
        (self.root / "issuer-key.pem").symlink_to(target)
        with self.assertRaises(issuer.IssuerUnavailable):
            issuer.initialize_issuer()
        (self.root / "issuer-key.pem").unlink()
        self.initialize()
        (self.root / "issuer-key.pem").chmod(0o644)
        with self.assertRaises(issuer.IssuerUnavailable):
            issuer.load_issuer()

    def test_leaf_ignores_requested_authority_and_binds_uuid_public_key_and_issuer(self):
        self.initialize()
        key, pem = csr(extensions=True)
        identity = uuid.uuid4()
        before = timezone.now().replace(microsecond=0)
        leaf, ca = component(self, "issuer").issue_certificate(csr_pem=pem, device_id=identity)
        cert, issuer = x509.load_pem_x509_certificate(leaf.encode()), x509.load_pem_x509_certificate(ca.encode())
        self.assertEqual(cert.public_key().public_numbers(), key.public_key().public_numbers())
        self.assertEqual(cert.issuer, issuer.subject)
        self.assertEqual(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "AEGIS-Agent-" + str(identity))
        issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
                         x509.SubjectAlternativeName([x509.UniformResourceIdentifier("urn:aegis:agent:" + str(identity))]))
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual(list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value),
                         [ExtendedKeyUsageOID.CLIENT_AUTH])
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(usage.digital_signature)
        self.assertFalse(usage.key_cert_sign or usage.crl_sign or usage.key_encipherment)
        self.assertEqual(cert.not_valid_after_utc - cert.not_valid_before_utc, timedelta(days=30))
        self.assertGreaterEqual(cert.not_valid_before_utc, before)

    def test_unsupported_csr_key_signature_or_invalid_signature_is_rejected(self):
        self.initialize()
        issuer = component(self, "issuer")
        for key, algorithm in ((rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256()),
                               (rsa.generate_private_key(public_exponent=65537, key_size=3072), hashes.SHA384()),
                               (ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())):
            with self.subTest(bits=key.key_size, hash=algorithm.name):
                _, pem = csr(key, algorithm)
                with self.assertRaises(ValueError):
                    issuer.issue_certificate(csr_pem=pem, device_id=uuid.uuid4())
        _, pem = csr()
        raw = bytearray(x509.load_pem_x509_csr(pem.encode()).public_bytes(serialization.Encoding.DER))
        raw[-1] ^= 1
        invalid = x509.load_der_x509_csr(bytes(raw)).public_bytes(serialization.Encoding.PEM).decode()
        with self.assertRaises(ValueError):
            issuer.issue_certificate(csr_pem=invalid, device_id=uuid.uuid4())
