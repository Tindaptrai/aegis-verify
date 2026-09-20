"""One offline manager archive Sysmon 3 UDP record; no collection or execution."""

from datetime import datetime
from ipaddress import IPv4Address
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp
from ._json import MAX_NUMERIC_CHARS, decode_document
from .errors import WazuhParseError
from .parser import _context, _integer, _object, _string


SYSTEM = 'data.win.system.'
DATA = 'data.win.eventdata.'
_TIME = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?')
_DECIMAL = re.compile(r'[0-9]{1,' + str(MAX_NUMERIC_CHARS) + '}')


class NetworkTelemetryProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)

    mapping_version: Literal['wazuh-sysmon3-archive-udp-v1'] = 'wazuh-sysmon3-archive-udp-v1'
    envelope: Literal['manager_archive'] = 'manager_archive'
    timestamp_basis: Literal['sysmon.utcTime'] = 'sysmon.utcTime'
    timestamp_policy: Literal['lossless-nanosecond-v2'] = 'lossless-nanosecond-v2'
    source_fraction_digits: int
    source_ref: str
    record_index: Literal[1] = 1
    line_start: Literal[1] = 1
    line_end: int
    raw_event_ref: str
    raw_event_hash: str
    event_id: str
    collection_mode: Literal['direct', 'forwarded', 'unknown']
    collector_agent_id: str | None
    collector_agent_name: str | None
    collector_manager_name: str | None
    windows_event_id: Literal['3'] = '3'
    windows_record_id: str | None
    process_guid: str | None


class NetworkTelemetryResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)

    event: CanonicalEventV2
    provenance: NetworkTelemetryProvenance


def _source_time(eventdata):
    value = eventdata.get('utcTime')
    if value is None:
        raise WazuhParseError('missing_event_time', DATA + 'utcTime') from None
    if type(value) is not str or _TIME.fullmatch(value) is None:
        raise WazuhParseError('invalid_event_time', DATA + 'utcTime') from None
    try:
        return PreciseTimestamp.parse(value.replace(' ', 'T') + 'Z')
    except (ValueError, TypeError):
        raise WazuhParseError('invalid_event_time', DATA + 'utcTime') from None


def _decimal(eventdata, key, *, maximum=None):
    value = _string(eventdata, key, DATA + key)
    if value is None:
        return None
    if _DECIMAL.fullmatch(value) is None:
        raise WazuhParseError('invalid_field', DATA + key) from None
    number = int(value, 10)
    if maximum is not None and number > maximum:
        raise WazuhParseError('invalid_field', DATA + key) from None
    return number


def _ipv4(eventdata, key):
    value = _string(eventdata, key, DATA + key)
    if value is None:
        return None
    try:
        return IPv4Address(value)
    except ValueError:
        raise WazuhParseError('invalid_field', DATA + key) from None


def parse_wazuh_sysmon3_archive_record(
    raw: bytes, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp, collection_mode: str,
) -> NetworkTelemetryResult:
    """Parse exact archive bytes. Observed network activity is not a verdict.

    Deliberately rejects search hits, TCP and IPv6. Optional absent facts remain
    null. Caller retains original raw bytes; full_log and unknown fields are
    never interpreted or used to fill gaps in the decoded source fields.
    """
    ingestion = _context(source_ref, environment_id, ingested_at, collection_mode)
    source = decode_document(raw)
    if '_source' in source:
        raise WazuhParseError('unsupported_profile', '_source') from None
    data = _object(source, 'data', 'data')
    win = _object(data, 'win', 'data.win')
    system = _object(win, 'system', 'data.win.system')
    eventdata = _object(win, 'eventdata', 'data.win.eventdata')
    for key, expected in (
        ('providerName', 'Microsoft-Windows-Sysmon'),
        ('channel', 'Microsoft-Windows-Sysmon/Operational'), ('eventID', '3'),
    ):
        if type(system.get(key)) is not str:
            raise WazuhParseError('invalid_field', SYSTEM + key) from None
        if system[key] != expected:
            raise WazuhParseError('unsupported_profile', SYSTEM + key) from None
    protocol = _string(eventdata, 'protocol', DATA + 'protocol')
    if protocol != 'udp':
        raise WazuhParseError('unsupported_profile', DATA + 'protocol') from None
    timestamp = _source_time(eventdata)

    agent = _object(source, 'agent', 'agent', optional=True)
    manager = _object(source, 'manager', 'manager', optional=True)
    rule = _object(source, 'rule', 'rule', optional=True)
    agent_id = _string(agent, 'id', 'agent.id')
    agent_name = _string(agent, 'name', 'agent.name')
    manager_name = _string(manager, 'name', 'manager.name')
    record_id = _string(system, 'eventRecordID', SYSTEM + 'eventRecordID')
    process_guid = _string(eventdata, 'processGuid', DATA + 'processGuid')
    rule_id = rule.get('id')
    if type(rule_id) is int and rule_id >= 0:
        rule_id = str(rule_id)
    elif rule_id is not None and type(rule_id) is not str:
        raise WazuhParseError('invalid_field', 'rule.id') from None

    raw_hash = hash_raw_event(raw)
    identity = ['wazuh-evidence-v1', environment_id, source_ref, 1, raw_hash]
    identity_bytes = json.dumps(identity, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    event_id = 'wazuh:evidence-v1:' + hash_raw_event(identity_bytes)
    raw_ref = source_ref + '#record=1'
    mapped = dict(
        event_id=event_id, timestamp=timestamp, source_type='wazuh',
        environment_id=environment_id, ingested_at=ingestion,
        raw_event_ref=raw_ref, raw_event_hash=raw_hash,
        source_record_id=_string(source, 'id', 'id'),
        event_provider=system['providerName'],
        hostname=_string(system, 'computer', SYSTEM + 'computer'),
        asset_id=agent_id if collection_mode == 'direct' else None,
        src_ip=_ipv4(eventdata, 'sourceIp'), dst_ip=_ipv4(eventdata, 'destinationIp'),
        src_port=_decimal(eventdata, 'sourcePort', maximum=65535),
        dst_port=_decimal(eventdata, 'destinationPort', maximum=65535),
        protocol=protocol, process_id=_decimal(eventdata, 'processId'),
        process_name=_string(eventdata, 'image', DATA + 'image'),
        username=_string(eventdata, 'user', DATA + 'user'),
        event_action='observed', rule_id=rule_id,
        severity=_integer(rule, 'level', 'rule.level'),
    )
    try:
        event = CanonicalEventV2.model_validate(mapped)
    except ValidationError as error:
        location = error.errors(include_input=False, include_context=False, include_url=False)[0]['loc']
        field = 'canonical.' + str(location[0]) if location else None
        raise WazuhParseError('canonical_validation', field) from None
    provenance = NetworkTelemetryProvenance(
        source_fraction_digits=timestamp.fractional_digits, source_ref=source_ref,
        line_end=raw.count(b'\n') + int(bool(raw) and not raw.endswith(b'\n')),
        raw_event_ref=raw_ref, raw_event_hash=raw_hash, event_id=event_id,
        collection_mode=collection_mode, collector_agent_id=agent_id,
        collector_agent_name=agent_name, collector_manager_name=manager_name,
        windows_record_id=record_id, process_guid=process_guid,
    )
    return NetworkTelemetryResult(event=event, provenance=provenance)
