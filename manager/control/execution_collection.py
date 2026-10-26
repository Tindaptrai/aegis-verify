"""Immutable v2 collection authority, independent of mutable release/device views."""
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings

from aegis_verify.intake.io import read_local
from .collection import CollectionSpec, validate_collection_spec
from .execution_contracts import (PROTOCOL, SignedJob, canonical_base64, decode_contract,
    release_definition_bytes, snapshot_bytes)
from .execution_models import RegisteredExecutionConnection
from .execution_signing import verify_execution_envelope

FAMILY = 'windows_execution_v2'


def _public_key():
    configured = getattr(settings, 'MANAGER_EXECUTION_SIGNING_KEY', None)
    if not configured: raise ValueError
    path = Path(configured)
    if not path.is_absolute(): raise ValueError
    if hasattr(settings, 'PRIVATE_ROOT') and not path.resolve().is_relative_to(Path(settings.PRIVATE_ROOT).resolve()):
        raise ValueError
    key = serialization.load_pem_private_key(read_local(path, limit=65536, stage='inputs'), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 3072: raise ValueError
    public = key.public_key()
    for name in ('MANAGER_SIGNING_KEY', 'ENROLLMENT_CA_KEY'):
        reference = getattr(settings, name, None)
        if not reference: continue
        other_path = Path(reference)
        if other_path.resolve() == path.resolve(): raise ValueError
        if other_path.is_file():
            other = serialization.load_pem_private_key(read_local(other_path, limit=65536, stage='inputs'), password=None)
            if isinstance(other, rsa.RSAPrivateKey) and other.public_key().public_numbers() == public.public_numbers():
                raise ValueError
    return public


def approved_execution_collection(job):
    """Verify local authority/pins before claim; never contact the evidence source."""
    try:
        if job.protocol_family != FAMILY: raise ValueError
        envelope_raw = bytes(job.envelope_bytes)
        payload = verify_execution_envelope(envelope_raw, _public_key())
        raw = canonical_base64(decode_contract('Envelope', envelope_raw).payload)
        if raw != bytes(job.signed_payload_bytes) or sha256(raw).hexdigest() != job.job_sha256:
            raise ValueError
        record = job.approval_snapshot
        frozen_raw = bytes(record.snapshot_bytes)
        snapshot = decode_contract('JobApprovalSnapshotData', frozen_raw)
        if (record.schema_version != 1 or snapshot_bytes(snapshot) != frozen_raw
                or sha256(frozen_raw).hexdigest() != record.snapshot_sha256):
            raise ValueError
        identity, binding, release, windows, source = (snapshot.identity, snapshot.binding,
            snapshot.release, snapshot.windows, snapshot.connection)
        expected = SignedJob(protocol=PROTOCOL, **asdict(identity), job_id=str(job.pk), run_id=str(job.pk),
            approval_id=str(job.approval_id), binding_id=binding.binding_id, binding_revision=binding.binding_revision,
            release_id=release.release_id, approval_snapshot_sha256=record.snapshot_sha256,
            scenario_id=release.scenario_id, runner_id=release.runner_id, runner_version=release.runner_version,
            **asdict(release.artifact_pins), **asdict(windows), timeout_seconds=release.timeout_seconds,
            parameters=release.parameters)
        if payload != expected or str(job.device_id) != identity.device_id: raise ValueError
        row = job.binding
        # Admission/current flags can change after execution; historical authority cannot.
        if (str(row.binding_id), row.revision, row.provider_id, row.installation_profile_sha256,
                row.artifact_set_sha256, str(row.approved_device_id), row.approved_generation,
                row.approved_certificate_sha256, row.approved_environment_id, str(row.connection_id),
                row.connection_revision, row.wazuh_agent_id, row.release_sha256) != (
                binding.binding_id, binding.binding_revision, binding.provider_id, binding.installation_profile_sha256,
                binding.artifact_set_sha256, identity.device_id, identity.generation, identity.certificate_sha256,
                identity.environment_id, source.connection_id, source.revision, source.wazuh_agent_id, release.release_sha256):
            raise ValueError
        definition = decode_contract('ReleaseDefinition', bytes(row.release_bytes))
        if (sha256(bytes(row.release_bytes)).hexdigest() != row.release_sha256
                or release_definition_bytes(definition) != bytes(row.release_bytes)
                or asdict(definition) != {name:value for name,value in asdict(release).items()
                    if name not in ('parameters','release_sha256')}):
            raise ValueError
        connection = RegisteredExecutionConnection.objects.get(connection_id=source.connection_id, revision=source.revision)
        if (connection.config_path, connection.config_sha256, connection.output_root_fingerprint) != (
                source.config_path, source.config_sha256, source.output_root_fingerprint):
            raise ValueError
        # Lazy import avoids the worker -> adapter -> resolver -> worker import cycle.
        from .execution_connections import resolve_execution_connection
        resolve_execution_connection(source.connection_id, source.revision)
        spec = CollectionSpec(job_id=str(job.pk), environment_id=identity.environment_id,
            wazuh_agent_id=source.wazuh_agent_id, start=windows.collection_start, end=windows.collection_end,
            bindings=tuple(asdict(item) for item in release.evaluation_bindings),
            scenario_path=Path(release.scenario_path), profile_path=Path(release.profile_path),
            scenario_sha256=release.artifact_pins.scenario_sha256, profile_sha256=release.artifact_pins.profile_sha256)
        validate_collection_spec(spec)
        return spec, connection
    except Exception:
        raise ValueError('invalid_approved_job') from None


def validate_execution_worker(approved, running, connection, root):
    """Require the exact running registration and actual reader/root identity."""
    try:
        if type(running) is not RegisteredExecutionConnection: raise ValueError
        names = ('pk','connection_id','revision','config_path','config_sha256','output_root_path','output_root_fingerprint')
        if any(getattr(approved,name) != getattr(running,name) for name in names): raise ValueError
        from .execution_connections import resolve_execution_connection
        actual, output = resolve_execution_connection(approved.connection_id, approved.revision)
        if actual != connection or output != root: raise ValueError
    except Exception:
        raise ValueError('invalid_approved_job') from None
