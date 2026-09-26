"""One offline manager alert whose data is a Cowrie login failure; no collection.

The record proves that Wazuh raised a rule for a Cowrie event. It is a
wazuh-source event: the Wazuh rule ID is the detection, the Cowrie data is
where the tuple, protocol, username, source time and session identity come
from, through the Cowrie connector's own mapping so the direct Cowrie parsers
and this one agree on every canonical value for the same record.
"""

from datetime import datetime
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp
from aegis_verify.connectors.cowrie._context import session_key as cowrie_session_key
from aegis_verify.connectors.cowrie._mapping import map_cowrie_event
from aegis_verify.connectors.cowrie.errors import CowrieParseError
from ._json import decode_document
from .errors import WazuhParseError
from .parser import _context, _integer, _object, _string


_RULE_ID = re.compile(r'[0-9]{1,128}')
_SAFE_LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', re.ASCII)
SUPPORTED_KIND = 'cowrie.login.failed'


class CowrieAlertProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)

    mapping_version: Literal['wazuh-cowrie-alert-v1'] = 'wazuh-cowrie-alert-v1'
    envelope: Literal['manager_alert'] = 'manager_alert'
    timestamp_basis: Literal['cowrie.data.timestamp'] = 'cowrie.data.timestamp'
    source_event_type: Literal['cowrie.login.failed'] = 'cowrie.login.failed'
    authentication_outcome: Literal['failure'] = 'failure'
    source_fraction_digits: int
    source_ref: str
    sensor_id: str
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
    # Wazuh receipt time as written, kept apart from the Cowrie source time.
    collector_received_at: str | None
    wazuh_rule_id: str
    wazuh_rule_level: int | None
    # Opaque key only; the raw Cowrie session identifier is never stored.
    session_key: str
    source_sensor: str | None
    source_uuid: str | None


class CowrieAlertResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)

    event: CanonicalEventV2
    provenance: CowrieAlertProvenance


def _rule_id(rule):
    value = rule.get('id')
    if type(value) is int and value >= 0:
        return str(value)
    if type(value) is str and _RULE_ID.fullmatch(value) is not None:
        return value
    raise WazuhParseError('invalid_field', 'rule.id') from None


def parse_wazuh_cowrie_alert_record(
    raw: bytes, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp, collection_mode: str, sensor_id: str,
) -> CowrieAlertResult:
    """Parse exact alert bytes. A raised Wazuh rule is not a compromise verdict.

    Deliberately rejects search hits, rules outside the `cowrie` group, any
    record carrying a password member, data that is not one login failure,
    records without a source session, and non-decimal Wazuh rule IDs.
    `sensor_id` must be the same label the direct Cowrie parsers were given, so
    both views derive the same session key.
    """
    ingestion = _context(source_ref, environment_id, ingested_at, collection_mode)
    if type(sensor_id) is not str or _SAFE_LABEL.fullmatch(sensor_id) is None:
        raise WazuhParseError('invalid_context', 'sensor_id') from None
    source = decode_document(raw)
    if '_source' in source:
        raise WazuhParseError('unsupported_profile', '_source') from None
    rule = _object(source, 'rule', 'rule')
    groups = rule.get('groups')
    if type(groups) is not list or any(type(item) is not str for item in groups):
        raise WazuhParseError('invalid_field', 'rule.groups') from None
    if 'cowrie' not in groups:
        raise WazuhParseError('unsupported_profile', 'rule.groups') from None
    rule_id = _rule_id(rule)
    data = _object(source, 'data', 'data')
    if 'password' in data:
        # A credential must never enter canonical events, provenance or reports.
        raise WazuhParseError('unsupported_profile', 'data.password') from None
    kind = data.get('eventid')
    if type(kind) is not str:
        raise WazuhParseError('invalid_field', 'data.eventid') from None
    if kind != SUPPORTED_KIND:
        raise WazuhParseError('unsupported_profile', 'data.eventid') from None
    try:
        # The Cowrie vocabulary is rooted at the event object; re-root under data.
        fields, metadata = map_cowrie_event(data, prefix='')
    except CowrieParseError as error:
        path = error.diagnostic.field_path
        raise WazuhParseError(error.diagnostic.code, 'data.' + path if path else None) from None
    if metadata['session'] is None:
        raise WazuhParseError('invalid_field', 'data.session') from None

    agent = _object(source, 'agent', 'agent', optional=True)
    manager = _object(source, 'manager', 'manager', optional=True)
    agent_id = _string(agent, 'id', 'agent.id')
    agent_name = _string(agent, 'name', 'agent.name')
    manager_name = _string(manager, 'name', 'manager.name')
    received_at = _string(source, 'timestamp', 'timestamp')
    key = cowrie_session_key(environment_id, sensor_id, metadata['session'])

    raw_hash = hash_raw_event(raw)
    identity = ['wazuh-evidence-v1', environment_id, source_ref, 1, raw_hash]
    identity_bytes = json.dumps(identity, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    event_id = 'wazuh:evidence-v1:' + hash_raw_event(identity_bytes)
    raw_ref = source_ref + '#record=1'
    # The honeypot host is the destination of the flow, not the initiator: no hostname.
    fields.update(
        source_type='wazuh', event_provider='cowrie', rule_id=rule_id,
        source_record_id=_string(source, 'id', 'id'),
        asset_id=agent_id if collection_mode == 'direct' else None,
        session_key=key,
    )
    try:
        event = CanonicalEventV2(**fields, event_id=event_id, environment_id=environment_id,
                                 ingested_at=ingestion, raw_event_ref=raw_ref, raw_event_hash=raw_hash)
    except ValidationError as error:
        location = error.errors(include_input=False, include_context=False, include_url=False)[0]['loc']
        field = 'canonical.' + str(location[0]) if location else None
        raise WazuhParseError('canonical_validation', field) from None
    provenance = CowrieAlertProvenance(
        source_fraction_digits=metadata['source_fraction_digits'], source_ref=source_ref,
        sensor_id=sensor_id,
        line_end=raw.count(b'\n') + int(bool(raw) and not raw.endswith(b'\n')),
        raw_event_ref=raw_ref, raw_event_hash=raw_hash, event_id=event_id,
        collection_mode=collection_mode, collector_agent_id=agent_id,
        collector_agent_name=agent_name, collector_manager_name=manager_name,
        collector_received_at=received_at, wazuh_rule_id=rule_id,
        wazuh_rule_level=_integer(rule, 'level', 'rule.level'),
        session_key=key, source_sensor=metadata['source_sensor'], source_uuid=metadata['source_uuid'],
    )
    return CowrieAlertResult(event=event, provenance=provenance)
