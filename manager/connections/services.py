"""Private test/save lifecycle. No transaction spans network I/O, no activation."""
from datetime import timedelta
import hashlib
import hmac
import json
import uuid
from django.conf import settings
from django.contrib.sessions.models import Session
from django.db import transaction
from django.utils import timezone
from accounts.models import AccountSecurity
from accounts.permissions import require_product_permission
from control.execution_models import RegisteredExecutionConnection, DeviceExecutionBinding
from control.execution_connections import root_fingerprint
from control.execution_ownership import lock_human_authority
from aegis_verify.connectors.wazuh.onboarding import probe as run_probe
from . import storage
from .contracts import fail, test_input, uuid_value
from .models import ConnectionDraft, ManagedSource, CandidateSelection, ConnectionAudit
from .policy import load_target


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(',',':'), ensure_ascii=True, allow_nan=False).encode()


def _mac(value):
    return hmac.new(settings.SECRET_KEY.encode(), b'connections-v1\0'+value, hashlib.sha256).hexdigest()


def _stamp(value):
    return value.isoformat().replace('+00:00','Z')


def _authority(request):
    actor = require_product_permission(request.user, 'manage_connections')
    generation = request.session.get('aegis_generation')
    session_key = request.session.session_key
    stored = Session.objects.select_for_update().filter(session_key=session_key, expire_date__gt=timezone.now()).first()
    session = stored.get_decoded() if stored is not None else {}
    if (type(generation) is not int or not session_key
            or session.get('_auth_user_id') != str(actor.pk)
            or session.get('aegis_generation') != generation
            or session.get('aegis_deadline', 0) <= timezone.now().timestamp()
            or not hmac.compare_digest(session.get('_auth_user_hash',''), actor.get_session_auth_hash())
            or not AccountSecurity.objects.filter(user=actor, generation=generation).exists()):
        fail('permission_denied',403)
    return actor, _mac(session_key.encode()), generation


def _version(source_id, expected):
    if source_id is None:
        return
    latest = ManagedSource.objects.filter(source_id=source_id).order_by('-version').first()
    if latest is None or latest.version != expected:
        fail('source_conflict',409)


def _snapshot(draft):
    return _mac(_encode(dict(id=str(draft.pk), actor=draft.actor_id, session=draft.session_digest,
        generation=draft.generation, expires_at=_stamp(draft.expires_at), tested_at=_stamp(draft.tested_at),
        summary=draft.summary, config_sha256=draft.config_sha256)))


def _audit(actor, action, draft):
    ConnectionAudit.objects.create(actor=actor, action=action, draft_id=draft.pk,
                                   version=draft.summary['version'], fingerprint=draft.snapshot_hmac, result='passed')


def test_connection(request, data):
    ca_sha256 = test_input(data)
    with transaction.atomic():
        lock_human_authority()
        actor, session_digest, generation = _authority(request)
        _version(data['source_id'], data['expected_version'])
        now = timezone.now()
        pending = ConnectionDraft.objects.filter(expires_at__gt=now, state__in=('probing','tested'))
        if pending.filter(actor=actor).count() >= 4 or pending.count() >= 32:
            fail('rate_limited',429)
        draft = ConnectionDraft.objects.create(actor=actor, session_digest=session_digest, generation=generation,
                                               expires_at=now+timedelta(minutes=5))
    try:
        run_probe(endpoint=data['endpoint'], index=data['index'], username=data['username'], password=data['password'],
                  ca_pem=data['ca_pem'], policy_provider=load_target)
        with transaction.atomic():
            lock_human_authority()
            fresh_actor, fresh_session, fresh_generation = _authority(request)
            if (actor.pk, session_digest, generation) != (fresh_actor.pk, fresh_session, fresh_generation):
                fail('permission_denied',403)
            _version(data['source_id'], data['expected_version'])
            if draft.expires_at <= timezone.now():
                fail('draft_expired',409)
            config_path, ca_path, _ = storage.paths(draft.pk)
            config = _encode(dict(endpoint=data['endpoint'], username=data['username'], password=data['password'],
                                  ca_file=str(ca_path), index=data['index'], collection_mode='unknown'))
            storage.create(draft.pk, config, data['ca_pem'].encode('ascii'))
            draft.summary = {key:data[key] for key in ('name','environment_id','endpoint','index','source_id')}
            draft.summary.update(ca_sha256=ca_sha256, version=(data['expected_version'] or 0)+1)
            draft.tested_at = timezone.now()
            draft.config_sha256 = hashlib.sha256(config).hexdigest()
            draft.snapshot_hmac = _snapshot(draft)
            draft.state = 'tested'
            draft.save()
            _audit(actor, 'tested', draft)
        return dict(draft_id=str(draft.pk), expires_at=_stamp(draft.expires_at), tested_at=_stamp(draft.tested_at),
                    checks=dict(policy='passed',tls='passed',authentication='passed',query='passed'), summary=draft.summary)
    except Exception:
        ConnectionDraft.objects.filter(pk=draft.pk, state='probing').update(state='failed')
        raise


def _draft(request, draft_id):
    actor, session_digest, generation = _authority(request)
    draft = ConnectionDraft.objects.select_for_update().filter(pk=draft_id).first()
    if (draft is None or draft.actor_id != actor.pk or draft.session_digest != session_digest
            or draft.generation != generation or draft.state not in ('tested','saved')):
        fail('draft_conflict',409)
    return actor, draft


def _verify(draft, *, expiry=True):
    if expiry and draft.expires_at <= timezone.now():
        fail('draft_expired',409)
    if not hmac.compare_digest(draft.snapshot_hmac, _snapshot(draft)):
        fail('draft_conflict',409)
    config, ca = storage.read(draft.pk)
    if (hashlib.sha256(config).hexdigest() != draft.config_sha256
            or hashlib.sha256(ca).hexdigest() != draft.summary['ca_sha256']):
        fail('draft_conflict',409)


@transaction.atomic
def save_connection(request, draft_id, idempotency_key):
    uuid_value(draft_id)
    uuid_value(idempotency_key)
    lock_human_authority()
    actor, draft = _draft(request, draft_id)
    previous = ManagedSource.objects.filter(draft=draft).first()
    if previous is not None:
        if str(previous.idempotency_key) != idempotency_key:
            fail('draft_conflict',409)
        _verify(draft, expiry=False)
        return source_dto(previous), False
    if ManagedSource.objects.filter(idempotency_key=idempotency_key).exists():
        fail('draft_conflict',409)
    _verify(draft)
    summary = draft.summary.copy()
    _version(summary['source_id'], summary['version']-1)
    source_id = summary['source_id'] or str(uuid.uuid4())
    summary['source_id'] = source_id
    config_path, _, output_root = storage.paths(draft.pk)
    registration = RegisteredExecutionConnection.objects.create(connection_id=uuid.uuid4(), revision=1,
        config_path=str(config_path), config_sha256=draft.config_sha256, output_root_path=str(output_root),
        output_root_fingerprint=root_fingerprint(output_root), reviewed_by=actor)
    source = ManagedSource.objects.create(source_id=source_id, version=summary['version'], draft=draft,
        registration=registration, idempotency_key=idempotency_key, summary=summary, tested_at=draft.tested_at)
    draft.state = 'saved'
    draft.save(update_fields=('state',))
    _audit(actor, 'saved', draft)
    return source_dto(source), True


def candidate_id():
    value = CandidateSelection.objects.filter(pk=1).values_list('source_id',flat=True).first()
    return str(value) if value else None


_UNSELECTED = object()


def source_dto(source, selected=_UNSELECTED):
    if selected is _UNSELECTED:
        selected = candidate_id()
    return dict(id=str(source.pk), source_id=str(source.source_id), version=source.version,
        **{key:source.summary[key] for key in ('name','environment_id','endpoint','index','ca_sha256')},
        kind='managed', product='wazuh', product_version='4.14.4',
        status='candidate' if str(source.pk) == selected else 'saved', worker_state='waiting_configuration',
        tested_at=_stamp(source.tested_at), created_at=_stamp(source.created_at))


@transaction.atomic
def prepare_connection(request, source_id, expected_candidate_id):
    uuid_value(expected_candidate_id, nullable=True)
    lock_human_authority()
    _authority(request)
    source = ManagedSource.objects.select_related('draft').filter(pk=source_id).first()
    if source is None:
        fail('source_conflict',409)
    actor, draft = _draft(request, source.draft_id)
    _verify(draft)
    selection, _ = CandidateSelection.objects.get_or_create(pk=1)
    if (str(selection.source_id) if selection.source_id else None) != expected_candidate_id:
        fail('candidate_conflict',409)
    selection.source = source
    selection.save(update_fields=('source',))
    _audit(actor, 'prepared', draft)
    return dict(source=source_dto(source), candidate_id=str(source.pk))


def managed_candidate():
    selection = CandidateSelection.objects.select_related('source__registration').filter(pk=1).first()
    if selection is None or selection.source_id is None:
        return None
    source = selection.source
    return dict(candidate_id=str(source.pk), source_id=str(source.source_id), version=source.version,
                status='waiting_configuration', connection_id=str(source.registration.connection_id),
                connection_revision=source.registration.revision)


def is_managed_registration(connection_id):
    return ManagedSource.objects.filter(registration__connection_id=connection_id).exists()


def list_sources(page):
    selected = candidate_id()
    results = [source_dto(source, selected) for source in ManagedSource.objects.order_by('-created_at','id')]
    # Read only registration/binding metadata; never open legacy configs.
    seen = set()
    managed_ids = ManagedSource.objects.values_list('registration__connection_id',flat=True)
    for row in RegisteredExecutionConnection.objects.exclude(connection_id__in=managed_ids).order_by('connection_id','-revision'):
        if row.connection_id in seen:
            continue
        seen.add(row.connection_id)
        environments = set(DeviceExecutionBinding.objects.filter(connection_id=row.connection_id)
                           .values_list('approved_environment_id',flat=True))
        results.append(dict(id=str(row.connection_id), source_id=str(row.connection_id), version=row.revision,
            name='Legacy Wazuh connection', kind='legacy', product='wazuh', product_version=None,
            environment_id=next(iter(environments)) if len(environments)==1 else None,
            endpoint=None, index=None, ca_sha256=None, status='legacy', worker_state='legacy',
            tested_at=None, created_at=_stamp(row.reviewed_at)))
    offset = (page-1)*50
    return dict(results=results[offset:offset+50], count=len(results), page=page, page_size=50, candidate_id=selected)


@transaction.atomic
def cleanup_expired():
    """Optional maintenance, serialized against publication; retains all history."""
    lock_human_authority()
    now = timezone.now()
    referenced = set(str(value) for value in ManagedSource.objects.values_list('draft_id',flat=True))
    referenced.update(str(value) for value in ConnectionDraft.objects.filter(expires_at__gt=now).values_list('id',flat=True))
    # Protect technical registrations too, even if a crash left metadata incomplete.
    for path in RegisteredExecutionConnection.objects.values_list('config_path',flat=True):
        from pathlib import Path
        referenced.add(Path(path).parent.name)
    storage.cleanup(referenced, now-timedelta(minutes=5))
    ConnectionDraft.objects.filter(expires_at__lte=now, managedsource__isnull=True).delete()
