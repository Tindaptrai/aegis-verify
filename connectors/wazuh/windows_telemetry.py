"""Two explicit offline profiles; never execute scripts or assemble fragments.

Use the existing Wazuh byte decoder, context validation and evidence identity
convention. The 4688 entry point remains unchanged and does not auto-dispatch.
"""

import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp
from ._json import MAX_NUMERIC_CHARS, decode_document
from .errors import WazuhParseError
from .parser import _context, _integer, _object, _string


SYSTEM = '_source.data.win.system.'
DATA = '_source.data.win.eventdata.'


class WindowsTelemetryProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)

    mapping_version: Literal['wazuh-sysmon1-v1', 'wazuh-powershell4104-v1']
    timestamp_basis: Literal['windows.systemTime'] = 'windows.systemTime'
    timestamp_policy: Literal['lossless-nanosecond-v2'] = 'lossless-nanosecond-v2'
    source_fraction_digits: int
    source_ref: str
    record_index: Literal[1] = 1
    raw_event_ref: str
    raw_event_hash: str
    event_id: str
    line_start: Literal[1] = 1
    line_end: int
    collection_mode: Literal['direct', 'forwarded', 'unknown']
    collector_agent_id: str | None
    collector_agent_name: str | None
    collector_manager_name: str | None
    windows_event_id: Literal['1', '4104']
    windows_record_id: str | None
    process_guid: str | None = None
    parent_process_guid: str | None = None
    parent_process_id: int | None = None
    script_block_id: str | None = None
    message_number: Literal[1] | None = None
    message_total: Literal[1] | None = None


class WindowsTelemetryResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)
    event: CanonicalEventV2
    provenance: WindowsTelemetryProvenance


def _decimal_pid(parent, key, path):
    """Wazuh Windows PIDs are decimal strings, unlike Security 4688 hex PIDs."""
    value = _string(parent, key, path)
    if value is None:
        return None
    if re.fullmatch(r'[0-9]{1,' + str(MAX_NUMERIC_CHARS) + r'}', value) is None:
        raise WazuhParseError('invalid_field', path) from None
    return int(value, 10)


def _single_part(eventdata):
    # Missing counters cannot establish completeness. Never assume 1/1.
    for key in ('messageNumber', 'messageTotal'):
        value = _string(eventdata, key, DATA + key)
        if value is None:
            raise WazuhParseError('incomplete_script', DATA + key) from None
        if re.fullmatch(r'[1-9][0-9]{0,127}', value) is None:
            raise WazuhParseError('invalid_field', DATA + key) from None
        if value != '1':
            raise WazuhParseError('unsupported_fragmentation', DATA + key) from None
    text = _string(eventdata, 'scriptBlockText', DATA + 'scriptBlockText')
    if text is None or not text.strip():
        raise WazuhParseError('incomplete_script', DATA + 'scriptBlockText') from None
    # Text stays ONLY in the hashed raw evidence; it is not a command line.


def _parse(raw, *, kind, source_ref, environment_id, ingested_at, collection_mode):
    ingestion = _context(source_ref, environment_id, ingested_at, collection_mode)
    document = decode_document(raw)
    if document.get('_source') is None:
        raise WazuhParseError('missing_source', '_source') from None
    source = _object(document, '_source', '_source')
    data = _object(source, 'data', '_source.data')
    win = _object(data, 'win', '_source.data.win')
    system = _object(win, 'system', '_source.data.win.system')
    provider, event_code, mapping = (
        ('Microsoft-Windows-Sysmon', '1', 'wazuh-sysmon1-v1') if kind == 'sysmon1'
        else ('Microsoft-Windows-PowerShell', '4104', 'wazuh-powershell4104-v1')
    )
    for key, expected in (('providerName', provider), ('channel', provider + '/Operational'),
                          ('eventID', event_code)):
        if type(system.get(key)) is not str:
            raise WazuhParseError('invalid_field', SYSTEM + key) from None
        if system[key] != expected:
            raise WazuhParseError('unsupported_profile', SYSTEM + key) from None
    if system.get('systemTime') is None:
        raise WazuhParseError('missing_event_time', SYSTEM + 'systemTime') from None
    try:
        timestamp = PreciseTimestamp.parse(system['systemTime'])
    except (ValueError, TypeError):
        raise WazuhParseError('invalid_event_time', SYSTEM + 'systemTime') from None

    agent = _object(source, 'agent', '_source.agent', optional=True)
    manager = _object(source, 'manager', '_source.manager', optional=True)
    rule = _object(source, 'rule', '_source.rule', optional=True)
    eventdata = _object(win, 'eventdata', '_source.data.win.eventdata', optional=True)
    agent_id = _string(agent, 'id', '_source.agent.id')
    agent_name = _string(agent, 'name', '_source.agent.name')
    manager_name = _string(manager, 'name', '_source.manager.name')
    record_id = _string(system, 'eventRecordID', SYSTEM + 'eventRecordID')
    rule_id = rule.get('id')
    if type(rule_id) is int and rule_id >= 0:
        rule_id = str(rule_id)
    elif rule_id is not None and type(rule_id) is not str:
        raise WazuhParseError('invalid_field', '_source.rule.id') from None

    mapped = dict(
        timestamp=timestamp, ingested_at=ingestion, source_type='wazuh',
        environment_id=environment_id, event_provider=provider,
        source_record_id=_string(source, 'id', '_source.id'),
        asset_id=agent_id if collection_mode == 'direct' else None,
        hostname=_string(system, 'computer', SYSTEM + 'computer'),
        rule_id=rule_id, severity=_integer(rule, 'level', '_source.rule.level'),
    )
    extra = {}
    if kind == 'sysmon1':
        mapped['process_id'] = _decimal_pid(eventdata, 'processId', DATA + 'processId')
        for canonical, key in (('process_name', 'image'), ('parent_process_name', 'parentImage'),
                               ('command_line', 'commandLine'), ('username', 'user')):
            mapped[canonical] = _string(eventdata, key, DATA + key)
        extra = dict(
            process_guid=_string(eventdata, 'processGuid', DATA + 'processGuid'),
            parent_process_guid=_string(eventdata, 'parentProcessGuid', DATA + 'parentProcessGuid'),
            parent_process_id=_decimal_pid(eventdata, 'parentProcessId', DATA + 'parentProcessId'),
        )
    else:
        _single_part(eventdata)
        mapped['process_id'] = _decimal_pid(system, 'processID', SYSTEM + 'processID')
        mapped['file_path'] = _string(eventdata, 'path', DATA + 'path')
        extra = dict(
            script_block_id=_string(eventdata, 'scriptBlockId', DATA + 'scriptBlockId'),
            message_number=1, message_total=1,
        )

    raw_hash = hash_raw_event(raw)
    identity = ['wazuh-evidence-v1', environment_id, source_ref, 1, raw_hash]
    encoded = json.dumps(identity, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    event_id = 'wazuh:evidence-v1:' + hash_raw_event(encoded)
    mapped.update(event_id=event_id, raw_event_hash=raw_hash, raw_event_ref=source_ref + '#record=1')
    try:
        event = CanonicalEventV2.model_validate(mapped)
    except ValidationError as error:
        location = error.errors(include_input=False, include_context=False, include_url=False)[0]['loc']
        field = 'canonical.' + str(location[0]) if location else None
        raise WazuhParseError('canonical_validation', field) from None
    provenance = WindowsTelemetryProvenance(
        mapping_version=mapping, source_fraction_digits=timestamp.fractional_digits,
        source_ref=source_ref, event_id=event_id, raw_event_hash=raw_hash,
        raw_event_ref=event.raw_event_ref,
        line_end=raw.count(b'\n') + int(bool(raw) and not raw.endswith(b'\n')),
        collection_mode=collection_mode, collector_agent_id=agent_id,
        collector_agent_name=agent_name, collector_manager_name=manager_name,
        windows_event_id=event_code, windows_record_id=record_id, **extra,
    )
    return WindowsTelemetryResult(event=event, provenance=provenance)


def parse_wazuh_sysmon1_document(raw: bytes, *, source_ref, environment_id,
                                ingested_at, collection_mode) -> WindowsTelemetryResult:
    """Parse one complete Wazuh search hit for Sysmon process creation (ID 1)."""
    return _parse(raw, kind='sysmon1', source_ref=source_ref, environment_id=environment_id,
                  ingested_at=ingested_at, collection_mode=collection_mode)


def parse_wazuh_powershell4104_document(raw: bytes, *, source_ref, environment_id,
                                       ingested_at, collection_mode) -> WindowsTelemetryResult:
    """Parse one Wazuh PowerShell 4104 search hit with explicit nonempty 1/1 text."""
    return _parse(raw, kind='powershell4104', source_ref=source_ref, environment_id=environment_id,
                  ingested_at=ingested_at, collection_mode=collection_mode)
