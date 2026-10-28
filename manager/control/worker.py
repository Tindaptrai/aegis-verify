"""Durable, single-flight collection. Uncertain collections need owner review."""
import base64
from contextlib import contextmanager
from datetime import timedelta
from hashlib import sha256
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from aegis_verify.dashboard.operations_config import read_windows_acl, validate_windows_acl
from aegis_verify.intake.io import local_path, read_local, decode_config
from .collection import CollectionSpec, collect_and_evaluate, _stamp
from .jobs import lock_dispatch, release_pins, audit
from .models import Job, AuditEntry


def validate_output_root(value):
    """Require an existing private directory outside every source checkout."""
    try:
        root = Path(value)
        if not root.is_absolute() or '..' in root.parts:
            raise ValueError
        root = local_path(root, directory=True, stage='inputs')
        for parent in (root, *root.parents):
            if (parent / '.git').exists():
                raise ValueError
        if os.name == 'nt':
            validate_windows_acl(read_windows_acl(root))
        else:
            info = root.stat()
            if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
                raise ValueError
        return root
    except Exception:
        raise ValueError('invalid_private_output_root') from None


@contextmanager
def worker_lock(output_root):
    """Hold an OS lock for the process lifetime; never delete the lock inode."""
    root = validate_output_root(output_root)
    path = root / '.worker.lock'
    if path.exists() or path.is_symlink():
        local_path(path,stage='inputs')
    descriptor = os.open(path,os.O_RDWR | os.O_CREAT | getattr(os,'O_NOFOLLOW',0),0o600)
    stream = os.fdopen(descriptor,'r+b',buffering=0)
    acquired = False
    try:
        if os.fstat(stream.fileno()).st_size == 0:
            stream.write(b'0')
            os.fsync(stream.fileno())
        stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(),fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError:
            raise ValueError('worker_already_running') from None
        yield
    finally:
        if acquired:
            stream.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(),fcntl.LOCK_UN)
        stream.close()


def _root_actor(root):
    return 'worker:' + sha256(os.path.normcase(str(root)).encode()).hexdigest()


def recover_interrupted(output_root):
    """Explicit operator action; blocked failures still require owner review."""
    root = validate_output_root(output_root)
    with worker_lock(root), transaction.atomic():
        lock_dispatch()
        jobs = list(Job.objects.select_for_update().filter(collection_state='collecting'))
        for job in jobs:
            if not AuditEntry.objects.filter(job=job,action='collection_started',
                    actor=_root_actor(root)).exists():
                raise ValueError('collection_output_root_mismatch')
            job.collection_state,job.error_code = 'failed','worker_interrupted'
            job.save(update_fields=['collection_state','error_code'])
            audit(job,'collection_interrupted','worker-recovery')
        return len(jobs)


def _approved_payload(job):
    envelope = job.envelope
    if (type(envelope) is not dict or set(envelope) != {'protocol','key_id','payload','signature'}
            or envelope['protocol'] != '0.1.0' or envelope['key_id'] != 'manager-v1'):
        raise ValueError
    raw = base64.b64decode(envelope['payload'], validate=True)
    signature = base64.b64decode(envelope['signature'], validate=True)
    if len(raw) > 65536 or sha256(raw).hexdigest() != job.payload_sha256:
        raise ValueError
    key = serialization.load_pem_private_key(read_local(settings.MANAGER_SIGNING_KEY,
        limit=65536, stage='inputs'), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
        raise ValueError
    key.public_key().verify(signature, raw,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    payload = decode_config(raw, stage='inputs')
    if (payload['job_id'] != str(job.id) or payload['run_id'] != str(job.id)
            or payload['agent_id'] != str(job.device_id)
            or payload['generation'] != job.approved_generation
            or payload['scenario_id'] != 'SCN-001'
            or payload['runner_id'] != 'scn001-safe-demo' or payload['runner_version'] != '0.3.0'
            or payload['timeout_seconds'] != job.release.timeout_seconds):
        raise ValueError
    for name in ('scenario','profile','runner','kit','payload'):
        if payload[name+'_sha256'] != getattr(job.release,name+'_sha256'):
            raise ValueError
    return payload


def process_one(connection, output_root, *, now=None, settle_seconds=30, transport=None):
    """Handle at most one approved collection; never reclaim a durable claim."""
    if type(settle_seconds) is not int or not 0 <= settle_seconds <= 300:
        raise ValueError('invalid_settle_seconds')
    root = validate_output_root(output_root)
    now = now or timezone.now()
    invalid = False
    with transaction.atomic():
        lock_dispatch()
        if Job.objects.filter(collection_state__in=('collecting','failed')).exists():
            return False
        job = None
        for candidate in Job.objects.select_for_update().select_related('release').filter(
                execution_state='succeeded',collection_state='pending').order_by('created_at'):
            try:
                payload = _approved_payload(candidate)
                ready = _stamp(payload['collection_end']) + timedelta(seconds=settle_seconds) <= now
            except Exception:
                job, invalid = candidate, True
                break
            if ready:
                job = candidate
                break
        if job is None:
            return False
        job.collection_state = 'collecting'
        job.save(update_fields=['collection_state'])
        audit(job,'collection_started',_root_actor(root))
    # Claim is committed before any source I/O. A process crash leaves collecting.
    try:
        if invalid:
            raise ValueError
        release_pins(job.release)
        spec = CollectionSpec(job_id=str(job.id),environment_id=payload['environment_id'],
            wazuh_agent_id=job.approved_wazuh_agent_id,start=payload['collection_start'],
            end=payload['collection_end'],bindings=tuple(job.evaluation_bindings),
            scenario_path=Path(job.release.scenario_path),profile_path=Path(job.release.profile_path),
            scenario_sha256=payload['scenario_sha256'],profile_sha256=payload['profile_sha256'])
    except Exception:
        state, report, error = 'failed', None, 'invalid_approved_job'
    else:
        try:
            result = collect_and_evaluate(spec,connection,root / str(job.id),transport=transport)
            if result.state not in ('evaluated','empty','failed'):
                raise ValueError
            state,report,error = result.state,result.report,result.error_code or ''
        except Exception:
            state,report,error = 'failed',None,'collection_worker_failed'
    with transaction.atomic():
        lock_dispatch()
        current = Job.objects.select_for_update().get(pk=job.pk)
        if current.collection_state != 'collecting':
            raise ValueError('collection_claim_changed')
        current.collection_state,current.report,current.error_code = state,report,error
        current.save(update_fields=['collection_state','report','error_code'])
        audit(current,'collection_'+state,'worker')
    return True
