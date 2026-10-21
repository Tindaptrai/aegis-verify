import tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase, override_settings
from control.signing import sign_payload


class SigningTests(SimpleTestCase):
    def test_undersized_rsa_key_cannot_sign_job(self):
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.pem"
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            with override_settings(MANAGER_SIGNING_KEY=str(path)):
                with self.assertRaises(ValueError): sign_payload({"protocol":"0.1.0"})
