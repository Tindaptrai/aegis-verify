import base64
import hashlib
import json
from aegis_verify.intake.io import read_local
from django.conf import settings
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def sign_payload(payload):
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    key = serialization.load_pem_private_key(read_local(settings.MANAGER_SIGNING_KEY, limit=65536, stage="inputs"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
        raise ValueError("Signing key must be RSA 3072 or stronger")
    signature = key.sign(raw, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    return {"protocol":"0.1.0", "key_id":"manager-v1", "payload":base64.b64encode(raw).decode("ascii"), "signature":base64.b64encode(signature).decode("ascii")}, hashlib.sha256(raw).hexdigest()
