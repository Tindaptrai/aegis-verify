"""Bounded Wazuh collection into the unchanged canonical engine.

Execution receipts never enter this module as detection evidence. No collection
completeness declaration or scenario ground truth is created here.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from uuid import UUID

from pydantic import ValidationError

from aegis_verify.cli.service import evaluate_bundle
from aegis_verify.connectors.wazuh.live import Config, LiveError, collect
from aegis_verify.dashboard.operations_config import (
    OperationsError, read_windows_acl, validate_windows_acl,
)
from aegis_verify.intake import IntakeError
from aegis_verify.intake.io import decode_config, local_path, read_local, MAX_CONFIG_BYTES
from aegis_verify.validation import EvaluationContext, EvaluationProfile


@dataclass(frozen=True)
class CollectionSpec:
    job_id: str
    environment_id: str
    wazuh_agent_id: str
    start: str
    end: str
    bindings: tuple
    scenario_path: Path = field(repr=False)
    profile_path: Path = field(repr=False)
    scenario_sha256: str
    profile_sha256: str


@dataclass(frozen=True)
class WazuhConnection:
    endpoint: str = field(repr=False)
    username: str = field(repr=False)
    password: str = field(repr=False)
    ca_file: str | None = field(repr=False)
    index: str
    collection_mode: str = 'unknown'


@dataclass(frozen=True)
class CollectionResult:
    state: str
    report: dict | None = field(default=None, repr=False)
    summary: dict = field(default_factory=dict)
    error_code: str | None = None


def _stamp(value):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value):
        raise ValueError
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def _scope(spec):
    if (not isinstance(spec, CollectionSpec) or str(UUID(spec.job_id)) != spec.job_id
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', spec.environment_id)
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', spec.wazuh_agent_id)):
        raise ValueError
    if not 0 < (_stamp(spec.end) - _stamp(spec.start)).total_seconds() <= 900:
        raise ValueError
    if not isinstance(spec.bindings, (tuple, list)) or any(
        type(row) is not dict or set(row) != {'name', 'value'} for row in spec.bindings
    ):
        raise ValueError
    return EvaluationContext.model_validate(dict(run_id=spec.job_id,
        environment_id=spec.environment_id, start=spec.start, end=spec.end,
        bindings=list(spec.bindings), declarations=[]))


def _pinned(path, digest):
    if type(digest) is not str or not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError
    selected = Path(path)
    if not selected.is_absolute():
        raise ValueError
    raw = read_local(selected, limit=MAX_CONFIG_BYTES, stage='inputs')
    if sha256(raw).hexdigest() != digest:
        raise ValueError
    return raw


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf-8')


def _exclusive(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def load_connection(path):
    """Load a private, local reader config; never accept it over the agent API."""
    try:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise ValueError
        selected = local_path(candidate, stage='inputs')
        info = selected.stat()
        if os.name == 'nt':
            validate_windows_acl(read_windows_acl(selected), directory=False)
        elif info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError
        value = decode_config(read_local(selected, limit=16384, stage='inputs'), stage='inputs')
        if set(value) != {'endpoint', 'username', 'password', 'ca_file', 'index', 'collection_mode'}:
            raise ValueError
        if any(type(value[name]) is not str or not value[name] for name in value):
            raise ValueError
        ca = local_path(Path(value['ca_file']), stage='inputs')
        if not ca.is_absolute():
            raise ValueError
        connection = WazuhConnection(**value)
        # Reuse the reader's validation before any source request. Times and IDs
        # are syntax checks only; a real job supplies its own approved scope.
        Config(**value, agent_id='config-check', start='2000-01-01T00:00:00Z',
               end='2000-01-01T00:00:01Z', environment_id='config-check')
        return connection
    except (IntakeError, OperationsError, OSError, TypeError, ValueError, LiveError):
        raise ValueError('invalid_private_wazuh_config') from None


def collect_and_evaluate(spec, connection, output, *, transport=None):
    """Create a new immutable snapshot; return safe status, never a guessed verdict."""
    try:
        context = _scope(spec)
    except (ValueError, TypeError, AttributeError, ValidationError):
        return CollectionResult('failed', error_code='invalid_collection_scope')
    try:
        scenario_raw = _pinned(spec.scenario_path, spec.scenario_sha256)
        profile_raw = _pinned(spec.profile_path, spec.profile_sha256)
        profile = EvaluationProfile.model_validate(decode_config(profile_raw, stage='profile'))
        if profile.scenario_id != 'SCN-001':
            raise ValueError
    except (IntakeError, OSError, ValueError, TypeError, ValidationError):
        return CollectionResult('failed', error_code='release_pin_mismatch')
    try:
        target = Path(output)
        if not target.is_absolute() or target.exists() or target.is_symlink():
            raise ValueError
        parent = local_path(target.parent, directory=True, stage='inputs')
        target = parent / target.name
    except (IntakeError, OSError, ValueError, TypeError):
        return CollectionResult('failed', error_code='output_unavailable')
    try:
        cfg = Config(endpoint=connection.endpoint, username=connection.username,
            password=connection.password, ca_file=connection.ca_file, index=connection.index,
            collection_mode=connection.collection_mode, agent_id=spec.wazuh_agent_id,
            start=spec.start, end=spec.end, environment_id=spec.environment_id)
        summary = collect(cfg, target, transport=transport)
        if summary.get('query_complete') is not True or summary.get('collection_assurance') != 'unknown':
            return CollectionResult('failed', error_code='collection_incomplete')
        if summary.get('cleanup_failed') is not False:
            return CollectionResult('failed', error_code='collection_cleanup_failed')
        if summary['record_count'] == 0:
            return CollectionResult('empty', summary=summary)
        _exclusive(target / 'scenario.yaml', scenario_raw)
        _exclusive(target / 'profile.json', profile_raw)
        _exclusive(target / 'context.json', _json_bytes(context.model_dump(mode='json')))
        report = evaluate_bundle(target / 'scenario.yaml', target)
        report['manager_metadata'] = dict(job_id=spec.job_id, run_binding='unknown',
            execution_receipt_is_detection_evidence=False, collection_assurance='unknown',
            query_time_basis='wazuh.timestamp_[start,end)',
            evaluation_time_basis='canonical_source_event_time_closed_window',
            limitation='No independent event-to-job binding or complete SCN-001 study acceptance.')
        _exclusive(target / 'report.json', _json_bytes(report))
        return CollectionResult('evaluated', report=report, summary=summary)
    except LiveError:
        return CollectionResult('failed', error_code='collection_failed')
    except (IntakeError, OSError, ValueError, TypeError, ValidationError):
        return CollectionResult('failed', error_code='evaluation_failed')
