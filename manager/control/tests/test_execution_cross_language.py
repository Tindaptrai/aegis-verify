"""Generated-key Manager -> production paired verifier. No payload is executed."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.test import SimpleTestCase, override_settings
from .test_execution_contracts import UUID, DIGEST, PINS, RULES, job_data, raw

VECTOR_EXE = Path(os.environ['AEGIS_EXECUTION_VECTOR_TEST_EXE']) if os.environ.get('AEGIS_EXECUTION_VECTOR_TEST_EXE') else None


class ExecutionCrossLanguageTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def setUp(self):
        from control.execution_contracts import canonical_bytes, decode_contract
        from control.execution_signing import sign_execution_payload
        self.assertTrue(VECTOR_EXE is not None and VECTOR_EXE.is_absolute() and VECTOR_EXE.is_file(),
                        'Set AEGIS_EXECUTION_VECTOR_TEST_EXE to the explicit Release test harness; cross-language vectors must execute')
        self.space = tempfile.TemporaryDirectory(prefix='aegis-execution-vector-')
        self.addCleanup(self.space.cleanup)
        self.root = Path(self.space.name)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic execution vector')])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1)).sign(self.key, hashes.SHA256()))
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        self.profile = dict(schema_version=1, provider_id='reviewed-scn001-windows/1', environment_id='synthetic-env',
            expected_computer_name='SYNTHETIC', scenario_path='synthetic/scenario', profile_path='synthetic/profile',
            runner_path='synthetic/runner', kit_directory='synthetic/kit', run_directory='synthetic/runs',
            study_path='synthetic/study', study_sha256=DIGEST, artifact_pins=PINS, rule_pins=RULES,
            allow_rehearsal=False, timeout_seconds=180)
        self.installed = dict(schema_version=1, device_id=UUID, generation=1, certificate_sha256=fingerprint,
            binding_id=UUID, binding_revision=1, installation_profile_sha256=hashlib.sha256(canonical_bytes(self.profile)).hexdigest(),
            artifact_set_sha256=hashlib.sha256(canonical_bytes(dict(artifact_pins=PINS, rule_pins=RULES))).hexdigest())
        self.payload = job_data() | dict(certificate_sha256=fingerprint,
            not_before=(now - timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            expires_at=(now + timedelta(seconds=119)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            collection_start=(now - timedelta(seconds=30)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            collection_end=(now + timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        (self.root / 'profile.json').write_bytes(raw(self.profile))
        (self.root / 'installed.json').write_bytes(raw(self.installed))
        (self.root / 'certificate.pem').write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (self.root / 'public.pem').write_bytes(self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        private = self.root / 'ephemeral.pem'
        private.write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with override_settings(MANAGER_EXECUTION_SIGNING_KEY=str(private)):
            self.envelope, self.digest = sign_execution_payload(decode_contract('SignedJob', raw(self.payload)))

    def validate(self, envelope=None):
        (self.root / 'envelope.json').write_bytes(self.envelope if envelope is None else envelope)
        command = ['dotnet', str(VECTOR_EXE)] if VECTOR_EXE.suffix == '.dll' else [str(VECTOR_EXE)]
        return subprocess.run(command + ['--execution-vector', str(self.root)], capture_output=True,
                              timeout=30, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)

    def signed_raw(self, payload):
        envelope = json.loads(self.envelope)
        envelope['payload'] = base64.b64encode(payload).decode()
        envelope['signature'] = base64.b64encode(self.key.sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())).decode()
        return raw(envelope)

    def test_original_python_signed_bytes_accepted_and_retained(self):
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout.strip(), self.digest.encode())
        original = raw(self.payload) + b' \n'
        result = self.validate(self.signed_raw(original))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout.strip(), hashlib.sha256(original).hexdigest().encode())

    def test_exact_rsa3072_rejects_valid_2048_and_4096_signatures(self):
        for size in (2048, 3072, 4096):
            with self.subTest(size=size):
                self.key = rsa.generate_private_key(public_exponent=65537, key_size=size)
                (self.root / 'public.pem').write_bytes(self.key.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
                result = self.validate(self.signed_raw(raw(self.payload)))
                self.assertEqual(result.returncode, 0 if size == 3072 else 2, result.stderr.decode())

    def test_tampered_signed_byte_and_noncanonical_envelope_rejected(self):
        value = json.loads(self.envelope)
        payload = base64.b64decode(value['payload']).replace(b'SCN-001', b'SCN-002')
        for change in ({'payload': base64.b64encode(payload).decode()}, {'protocol': '0.1.0'},
                       {'key_id': 'manager-v1'}, {'payload': value['payload'] + '\n'}, {'unknown': None}):
            with self.subTest(change=change): self.assertEqual(self.validate(raw(value | change)).returncode, 2)

    def test_valid_signature_cannot_bypass_pins_identity_or_closed_schema(self):
        for changes in ({'generation': 2}, {'device_id': 'b1111111-1111-4111-8111-111111111111'},
                        {'binding_revision': 2}, {'runner_sha256': 'd' * 64}, {'protocol': '0.1.0'},
                        {'parameters': self.payload['parameters'] | {'run_label': 'C'}},
                        {'parameters': self.payload['parameters'] | {'run_label': 'Rehearsal'}},
                        {'unknown': None}, {'generation': True}, {'release_id': 2**63}):
            with self.subTest(changes=changes): self.assertEqual(self.validate(self.signed_raw(raw(self.payload | changes))).returncode, 2)
        duplicate = raw(self.payload).replace(b'"generation":1', b'"generation":1,"generation":1')
        self.assertEqual(self.validate(self.signed_raw(duplicate)).returncode, 2)
        for key in self.payload:
            with self.subTest(missing=key):
                self.assertEqual(self.validate(self.signed_raw(raw({k: v for k, v in self.payload.items() if k != key}))).returncode, 2)
        oversized = raw(self.payload) + b' ' * 65536
        self.assertEqual(self.validate(self.signed_raw(oversized)).returncode, 2)

    def test_v2_envelope_cannot_enter_legacy_collection(self):
        from control.models import Job
        from control.worker import _approved_payload
        with self.assertRaises(ValueError): _approved_payload(Job(envelope=json.loads(self.envelope)))

    def test_installed_profile_and_artifact_hashes_are_enforced(self):
        for field in ('installation_profile_sha256', 'artifact_set_sha256'):
            (self.root / 'installed.json').write_bytes(raw(self.installed | {field: 'f' * 64}))
            with self.subTest(field=field): self.assertEqual(self.validate().returncode, 2)

    def test_canonical_profile_hash_preserves_valid_ascii_path_characters(self):
        from control.execution_contracts import canonical_bytes
        self.profile['scenario_path'] = "C:/synthetic/a'+&/scenario.yaml"
        self.profile['profile_path'] = "C:/synthetic/space name/profile.json"
        (self.root / 'profile.json').write_bytes(raw(self.profile))
        self.installed['installation_profile_sha256'] = hashlib.sha256(canonical_bytes(self.profile)).hexdigest()
        (self.root / 'installed.json').write_bytes(raw(self.installed))
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
