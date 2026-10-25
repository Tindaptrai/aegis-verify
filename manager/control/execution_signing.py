"""Separate execution signing authority; signatures cover original payload bytes."""
import base64
import hashlib
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.conf import settings
from aegis_verify.intake.io import read_local
from .execution_contracts import (PROTOCOL, KEY_ID, SignedJob, canonical_bytes, canonical_base64, decode_contract)


def sign_execution_payload(payload: SignedJob) -> tuple[bytes, str]:
    if type(payload) is not SignedJob: raise ValueError('invalid_request')
    raw = canonical_bytes(payload)
    decode_contract('SignedJob', raw)
    configured = settings.MANAGER_EXECUTION_SIGNING_KEY
    if not configured: raise ValueError('execution_unavailable')
    execution_path = Path(configured)
    if hasattr(settings, 'PRIVATE_ROOT') and not execution_path.resolve().is_relative_to(Path(settings.PRIVATE_ROOT).resolve()):
        raise ValueError('invalid_request')
    key = serialization.load_pem_private_key(read_local(execution_path, limit=65536, stage='inputs'), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072: raise ValueError('invalid_request')
    for name in ('MANAGER_SIGNING_KEY', 'ENROLLMENT_CA_KEY'):
        reference = getattr(settings, name, None)
        if not reference: continue
        path = Path(reference)
        if path.resolve() == execution_path.resolve(): raise ValueError('invalid_request')
        if path.is_file():
            old = serialization.load_pem_private_key(read_local(path, limit=65536, stage='inputs'), password=None)
            if isinstance(old, rsa.RSAPrivateKey) and old.public_key().public_numbers() == key.public_key().public_numbers():
                raise ValueError('invalid_request')
    signature = key.sign(raw, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    return canonical_bytes(dict(protocol=PROTOCOL, key_id=KEY_ID, payload=base64.b64encode(raw).decode('ascii'),
                                signature=base64.b64encode(signature).decode('ascii'))), hashlib.sha256(raw).hexdigest()


def verify_execution_envelope(raw: bytes, public_key) -> SignedJob:
    envelope = decode_contract('Envelope', raw)
    payload = canonical_base64(envelope.payload)
    signature = canonical_base64(envelope.signature)
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 3072: raise ValueError('invalid_request')
    try: public_key.verify(signature, payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    except (InvalidSignature, ValueError): raise ValueError('invalid_request') from None
    return decode_contract('SignedJob', payload)
