"""Private worker liveness. Source I/O never runs on the keepalive thread."""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
import os
import threading
import time
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.db import close_old_connections, transaction
from django.db.models import Max
from django.utils import timezone
from aegis_verify.connectors.wazuh.live import Config, ProbeResult, probe
from aegis_verify.intake.io import read_local
from aegis_verify.dashboard.operations_config import read_windows_acl, validate_windows_acl
from .execution_connections import resolve_execution_connection
from .execution_contracts import canonical_bytes, decode_contract
from .execution_models import CollectionWorkerLease, DeviceExecutionBinding, RegisteredExecutionConnection, BindingAdmissionAudit
from .execution_ownership import lock_dispatch
from .jobs import release_pins


@dataclass(frozen=True)
class ScopedProbeResult:
    """Private round proof, distinct from the connector's two-field result."""
    result: ProbeResult
    scope_sha256: str = ''

    @property
    def healthy(self): return self.result.healthy

    @property
    def code(self): return self.result.code


@transaction.atomic
def refresh_worker_health(instance_id, connection_revision, *, now, probe_result):
    """Refresh an existing private lease; never advances source freshness on keepalive."""
    if probe_result is not None: lock_dispatch()
    row = CollectionWorkerLease.objects.select_for_update().get(pk=instance_id)
    connection = connection_revision
    if type(connection) is not RegisteredExecutionConnection or (
            row.connection_id,row.connection_revision,row.config_sha256,row.output_root_fingerprint) != (
            connection.connection_id,connection.revision,connection.config_sha256,connection.output_root_fingerprint):
        raise ValueError('worker_revision_mismatch')
    values = dict(last_seen_at=now)
    if probe_result is not None:
        if type(probe_result) is ProbeResult:
            if probe_result.healthy: raise ValueError('unscoped_probe_result')
        elif type(probe_result) is not ScopedProbeResult:
            raise ValueError('invalid_probe_result')
        matched = (probe_result.healthy and bool(probe_result.scope_sha256)
            and probe_result.scope_sha256 == current_scope_sha256(connection))
        values['source_probe_status'] = 'healthy' if matched else 'source_unavailable'
        if matched:
            values['source_probe_succeeded_at'] = now
            values['source_probe_scope_sha256'] = probe_result.scope_sha256
    CollectionWorkerLease.objects.filter(pk=instance_id).update(**values)


def _scopes(connection):
    return list(DeviceExecutionBinding.objects.select_related('device','release').filter(
        is_current=True,enabled=True,connection_id=connection.connection_id,connection_revision=connection.revision).order_by('pk'))


def _scope_sha256(connection, scopes):
    if not scopes: return ''
    reviewed=[]
    for binding in scopes:
        # Append-only admission audit PK is an epoch, including disable/re-enable
        # of the same immutable binding. Keepalive never advances this proof.
        epoch=BindingAdmissionAudit.objects.filter(binding_id=binding.pk).aggregate(value=Max('pk'))['value'] or 0
        reviewed.append(dict(binding_id=str(binding.binding_id),revision=binding.revision,
            device_id=str(binding.approved_device_id),generation=binding.approved_generation,
            certificate_sha256=binding.approved_certificate_sha256,environment_id=binding.approved_environment_id,
            provider_id=binding.provider_id,wazuh_agent_id=binding.wazuh_agent_id,
            installation_profile_sha256=binding.installation_profile_sha256,
            artifact_set_sha256=binding.artifact_set_sha256,release_id=binding.release_id,
            release_sha256=binding.release_sha256,admission_epoch=epoch))
    return sha256(canonical_bytes(dict(connection_id=str(connection.connection_id),revision=connection.revision,
        config_sha256=connection.config_sha256,output_root_fingerprint=connection.output_root_fingerprint,scopes=reviewed))).hexdigest()


def current_scope_sha256(connection):
    """Caller holds DispatchLock for coherent admission and publication checks."""
    return _scope_sha256(connection,_scopes(connection))


@transaction.atomic
def _scope_snapshot(connection):
    lock_dispatch()
    scopes=_scopes(connection)
    return scopes,_scope_sha256(connection,scopes)


def _authority(connection):
    """Validate private reader, signing separation and pinned collection artifacts."""
    resolved, root = resolve_execution_connection(connection.connection_id,connection.revision)
    latest = RegisteredExecutionConnection.objects.filter(connection_id=connection.connection_id).order_by('-revision').first()
    if latest is None or latest.revision != connection.revision: raise ValueError
    configured = getattr(settings,'MANAGER_EXECUTION_SIGNING_KEY',None)
    if not configured: raise ValueError
    path = Path(configured)
    if not path.is_absolute(): raise ValueError
    if hasattr(settings,'PRIVATE_ROOT') and not path.resolve().is_relative_to(Path(settings.PRIVATE_ROOT).resolve()): raise ValueError
    if os.name=='nt': validate_windows_acl(read_windows_acl(path),directory=False)
    elif path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077: raise ValueError
    # Signing is local only; reject reused authority exactly as the signer does.
    key = serialization.load_pem_private_key(read_local(path,limit=65536,stage='inputs'),password=None)
    if not isinstance(key,rsa.RSAPrivateKey) or key.key_size != 3072: raise ValueError
    for name in ('MANAGER_SIGNING_KEY','ENROLLMENT_CA_KEY'):
        ref = getattr(settings,name,None)
        if ref and Path(ref).exists():
            other = serialization.load_pem_private_key(read_local(ref,limit=65536,stage='inputs'),password=None)
            if isinstance(other,rsa.RSAPrivateKey) and other.public_key().public_numbers() == key.public_key().public_numbers(): raise ValueError
    scopes = _scopes(connection)
    if not scopes: raise ValueError
    for binding in scopes:
        release_pins(binding.release)
        frozen = decode_contract('ReleaseDefinition',bytes(binding.release_bytes))
        if sha256(bytes(binding.release_bytes)).hexdigest() != binding.release_sha256: raise ValueError
        if frozen.scenario_path != binding.release.scenario_path or frozen.profile_path != binding.release.profile_path: raise ValueError
        for name in ('scenario','profile','runner','kit','payload'):
            if getattr(frozen.artifact_pins,name+'_sha256') != getattr(binding.release,name+'_sha256'): raise ValueError
    return resolved,root,scopes


def probe_connection(connection, *, now=None, transport=None, clock=time.monotonic):
    """All current reviewed scopes must complete within one bounded round."""
    started = clock()
    failed=ScopedProbeResult(ProbeResult(False,'source_unavailable'))
    try:
        resolved,_,checked_scopes = _authority(connection)
        scopes,scope_sha256 = _scope_snapshot(connection)
        if not scope_sha256 or [b.pk for b in scopes] != [b.pk for b in checked_scopes]: return failed
        now = (now or timezone.now()).replace(microsecond=0)
        stamp = lambda dt: dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        for binding in scopes:
            if clock()-started >= 50: return failed
            cfg = Config(endpoint=resolved.endpoint,username=resolved.username,password=resolved.password,
                ca_file=resolved.ca_file,index=resolved.index,collection_mode=resolved.collection_mode,
                agent_id=binding.wazuh_agent_id,environment_id=binding.approved_environment_id,
                start=stamp(now-timedelta(seconds=60)),end=stamp(now))
            if not probe(cfg,transport=transport).healthy: return failed
        # Recheck scope set/revision after I/O; no success for a retired round.
        if clock()-started > 50 or _scope_snapshot(connection)[1] != scope_sha256:
            return failed
        return ScopedProbeResult(ProbeResult(True,'healthy'),scope_sha256)
    except Exception:
        return failed


class WorkerHealth:
    """Started only while caller holds the OS worker lock. No durable claim recovery."""
    def __init__(self, connection, *, keepalive_interval=5):
        if not 0 < keepalive_interval <= 10: raise ValueError('invalid_keepalive_interval')
        self.connection = connection
        self.keepalive_interval = keepalive_interval
        self.instance_id = uuid.uuid4()
        self.stop = threading.Event()
        self.threads = []

    def start(self):
        _authority(self.connection)
        now = timezone.now()
        CollectionWorkerLease.objects.create(instance_id=self.instance_id,connection_id=self.connection.connection_id,
            connection_revision=self.connection.revision,config_sha256=self.connection.config_sha256,
            output_root_fingerprint=self.connection.output_root_fingerprint,started_at=now,last_seen_at=now,
            health_code='healthy')
        for action in (self._keepalive,self._source):
            thread = threading.Thread(target=action,daemon=True); self.threads.append(thread); thread.start()

    def _keepalive(self):
        try:
            while not self.stop.wait(self.keepalive_interval):
                close_old_connections()
                refresh_worker_health(self.instance_id,self.connection,now=timezone.now(),probe_result=None)
        except Exception:
            self.stop.set()
        finally: close_old_connections()

    def _source(self):
        try:
            while not self.stop.is_set():
                close_old_connections()
                result = probe_connection(self.connection)
                if self.stop.is_set(): break
                refresh_worker_health(self.instance_id,self.connection,now=timezone.now(),probe_result=result)
                if self.stop.wait(15): break
        except Exception:
            self.stop.set()
        finally: close_old_connections()

    def close(self):
        self.stop.set()
        # Never wait on potentially blocking network I/O while stopping the lease.
        CollectionWorkerLease.objects.filter(pk=self.instance_id).update(health_code='stopped')


@contextmanager
def execution_worker_health(connection):
    worker = WorkerHealth(connection)
    try:
        worker.start(); yield worker
    finally: worker.close()
