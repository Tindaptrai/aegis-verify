"""Fixture-only Windows 4688 mapping. No network, clock or command execution."""

from datetime import datetime
import json
from pathlib import Path
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp
from ._json import MAX_BYTES, decode_document
from .errors import WazuhParseError


class WazuhProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)
    mapping_version: Literal['wazuh-win4688-v2'] = 'wazuh-win4688-v2'
    timestamp_basis: Literal['windows.systemTime'] = 'windows.systemTime'
    timestamp_policy: Literal['lossless-nanosecond-v2'] = 'lossless-nanosecond-v2'
    source_fraction_digits: int
    source_ref: str
    record_index: Literal[1] = 1
    event_id: str
    raw_event_hash: str
    collection_mode: Literal['direct', 'forwarded', 'unknown']
    collector_agent_id: str | None
    collector_agent_name: str | None
    collector_manager_name: str | None


class WazuhParseResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)
    event: CanonicalEventV2
    provenance: WazuhProvenance


def _object(parent, key, path, *, optional=False):
    value = parent.get(key)
    if value is None and optional:
        return {}
    if type(value) is not dict:
        raise WazuhParseError('invalid_field', path) from None
    return value


def _string(parent, key, path):
    value = parent.get(key)
    if value is not None and type(value) is not str:
        raise WazuhParseError('invalid_field', path) from None
    return value


def _integer(parent, key, path):
    value = parent.get(key)
    if value is not None and (type(value) is not int or value < 0):
        raise WazuhParseError('invalid_field', path) from None
    return value


def _context(source_ref, environment_id, ingested_at, collection_mode):
    if type(source_ref) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', source_ref) is None:
        raise WazuhParseError('invalid_context', 'source_ref') from None
    if type(environment_id) is not str or not environment_id.strip():
        raise WazuhParseError('invalid_context', 'environment_id') from None
    try:
        environment_id.encode('utf-8')
    except UnicodeEncodeError:
        raise WazuhParseError('invalid_context', 'environment_id') from None
    if type(collection_mode) is not str or collection_mode not in ('direct', 'forwarded', 'unknown'):
        raise WazuhParseError('invalid_context', 'collection_mode') from None
    try:
        return PreciseTimestamp.parse(ingested_at)
    except (ValueError, TypeError):
        raise WazuhParseError('invalid_context', 'ingested_at') from None


def parse_wazuh_document(
    raw: bytes, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp, collection_mode: str,
) -> WazuhParseResult:
    """Map one complete JSON search-hit document, hashing its exact input bytes."""
    ingestion = _context(source_ref, environment_id, ingested_at, collection_mode)
    document = decode_document(raw)
    if document.get('_source') is None:
        raise WazuhParseError('missing_source', '_source') from None
    source = _object(document, '_source', '_source')
    data = _object(source, 'data', '_source.data')
    win = _object(data, 'win', '_source.data.win')
    system = _object(win, 'system', '_source.data.win.system')
    for key, expected in (
        ('providerName', 'Microsoft-Windows-Security-Auditing'),
        ('channel', 'Security'), ('eventID', '4688'),
    ):
        path = '_source.data.win.system.' + key
        if type(system.get(key)) is not str:
            raise WazuhParseError('invalid_field', path) from None
        if system[key] != expected:
            raise WazuhParseError('unsupported_profile', path) from None
    time_path = '_source.data.win.system.systemTime'
    if system.get('systemTime') is None:
        raise WazuhParseError('missing_event_time', time_path) from None
    try:
        timestamp = PreciseTimestamp.parse(system['systemTime'])
    except (ValueError, TypeError):
        raise WazuhParseError('invalid_event_time', time_path) from None

    agent = _object(source, 'agent', '_source.agent', optional=True)
    manager = _object(source, 'manager', '_source.manager', optional=True)
    rule = _object(source, 'rule', '_source.rule', optional=True)
    eventdata = _object(win, 'eventdata', '_source.data.win.eventdata', optional=True)
    agent_id = _string(agent, 'id', '_source.agent.id')
    agent_name = _string(agent, 'name', '_source.agent.name')
    manager_name = _string(manager, 'name', '_source.manager.name')
    pid_path = '_source.data.win.eventdata.newProcessId'
    pid = _string(eventdata, 'newProcessId', pid_path)
    if pid is not None:
        if re.fullmatch(r'0[xX][0-9a-fA-F]{1,126}', pid) is None:
            raise WazuhParseError('invalid_field', pid_path) from None
        pid = int(pid, 16)
    rule_id = rule.get('id')
    if type(rule_id) is int and rule_id >= 0:
        rule_id = str(rule_id)
    elif rule_id is not None and type(rule_id) is not str:
        raise WazuhParseError('invalid_field', '_source.rule.id') from None

    raw_hash = hash_raw_event(raw)
    identity = ['wazuh-evidence-v1', environment_id, source_ref, 1, raw_hash]
    identity_bytes = json.dumps(identity, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    event_id = 'wazuh:evidence-v1:' + hash_raw_event(identity_bytes)
    mapped = dict(
        event_id=event_id, timestamp=timestamp, source_type='wazuh',
        environment_id=environment_id, ingested_at=ingestion,
        raw_event_ref=source_ref + '#record=1', raw_event_hash=raw_hash,
        source_record_id=_string(source, 'id', '_source.id'),
        event_provider=system['providerName'],
        hostname=_string(system, 'computer', '_source.data.win.system.computer'),
        asset_id=agent_id if collection_mode == 'direct' else None,
        process_id=pid, rule_id=rule_id,
        severity=_integer(rule, 'level', '_source.rule.level'),
    )
    for canonical, source_key in (
        ('username', 'subjectUserName'), ('process_name', 'newProcessName'),
        ('parent_process_name', 'parentProcessName'), ('command_line', 'commandLine'),
    ):
        mapped[canonical] = _string(eventdata, source_key, '_source.data.win.eventdata.' + source_key)
    try:
        event = CanonicalEventV2.model_validate(mapped)
    except ValidationError as error:
        location = error.errors(include_input=False, include_context=False, include_url=False)[0]['loc']
        field = 'canonical.' + str(location[0]) if location else None
        raise WazuhParseError('canonical_validation', field) from None
    provenance = WazuhProvenance(
        source_fraction_digits=timestamp.fractional_digits, source_ref=source_ref,
        event_id=event_id, raw_event_hash=raw_hash, collection_mode=collection_mode,
        collector_agent_id=agent_id, collector_agent_name=agent_name,
        collector_manager_name=manager_name,
    )
    return WazuhParseResult(event=event, provenance=provenance)


def load_wazuh_document(
    path: str | Path, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp, collection_mode: str,
) -> WazuhParseResult:
    """Read at most the byte limit plus one; never write or expose the path."""
    try:
        with open(path, 'rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
    except (OSError, ValueError, TypeError):
        raise WazuhParseError('io_error') from None
    return parse_wazuh_document(
        raw, source_ref=source_ref, environment_id=environment_id,
        ingested_at=ingested_at, collection_mode=collection_mode,
    )
