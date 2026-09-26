"""One offline manager alert record whose data is a Suricata alert; no collection.

The record proves that Wazuh raised a rule for a Suricata alert. It is a
wazuh-source event: the Wazuh rule ID is the detection, the Suricata data is
where the flow tuple, signature and source time come from. Tuple and time
policy are shared with the Suricata connector so A02 and A04 see the same
values for the same alert.
"""

from datetime import datetime
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp
from aegis_verify.connectors.suricata._mapping import map_alert
from aegis_verify.connectors.suricata.errors import SuricataParseError
from ._json import decode_document
from .errors import WazuhParseError
from .parser import _context, _integer, _object, _string


_RULE_ID = re.compile(r'[0-9]{1,128}')


class SuricataAlertProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)

    mapping_version: Literal['wazuh-suricata-alert-v1'] = 'wazuh-suricata-alert-v1'
    envelope: Literal['manager_alert'] = 'manager_alert'
    timestamp_basis: Literal['suricata.data.timestamp'] = 'suricata.data.timestamp'
    action_scope: Literal['alert_rule'] = 'alert_rule'
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
    # Wazuh receipt time as written, kept apart from the Suricata source time.
    collector_received_at: str | None
    wazuh_rule_id: str
    wazuh_rule_level: int | None
    signature_id: str | None
    signature_gid: str | None
    signature_rev: str | None
    signature_text: str | None
    signature_category: str | None
    app_proto: str | None
    in_iface: str | None
    source_alert_action: str | None
    flow_id_raw: str | None


class SuricataAlertResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)

    event: CanonicalEventV2
    provenance: SuricataAlertProvenance


def _rule_id(rule):
    value = rule.get('id')
    if type(value) is int and value >= 0:
        return str(value)
    if type(value) is str and _RULE_ID.fullmatch(value) is not None:
        return value
    raise WazuhParseError('invalid_field', 'rule.id') from None


def parse_wazuh_suricata_alert_record(
    raw: bytes, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp, collection_mode: str,
) -> SuricataAlertResult:
    """Parse exact alert bytes. A raised Wazuh rule is not a prevention verdict.

    Deliberately rejects search hits, records whose rule is not from the
    Suricata group, records whose data is not an alert, and records without a
    decimal Wazuh rule ID. `event_action` stays what the alert says; an IDS
    `allowed` is never turned into prevention evidence.
    """
    ingestion = _context(source_ref, environment_id, ingested_at, collection_mode)
    source = decode_document(raw)
    if '_source' in source:
        raise WazuhParseError('unsupported_profile', '_source') from None
    rule = _object(source, 'rule', 'rule')
    groups = rule.get('groups')
    if type(groups) is not list or any(type(item) is not str for item in groups):
        raise WazuhParseError('invalid_field', 'rule.groups') from None
    if 'suricata' not in groups:
        raise WazuhParseError('unsupported_profile', 'rule.groups') from None
    rule_id = _rule_id(rule)
    data = _object(source, 'data', 'data')
    if type(data.get('event_type')) is not str:
        raise WazuhParseError('invalid_field', 'data.event_type') from None
    if data['event_type'] != 'alert':
        raise WazuhParseError('unsupported_profile', 'data.event_type') from None
    try:
        # The Suricata vocabulary is rooted at the EVE object; re-root under data.
        fields, metadata = map_alert(data, prefix='')
    except SuricataParseError as error:
        path = error.diagnostic.field_path
        raise WazuhParseError(error.diagnostic.code, 'data.' + path if path else None) from None

    agent = _object(source, 'agent', 'agent', optional=True)
    manager = _object(source, 'manager', 'manager', optional=True)
    agent_id = _string(agent, 'id', 'agent.id')
    agent_name = _string(agent, 'name', 'agent.name')
    manager_name = _string(manager, 'name', 'manager.name')
    received_at = _string(source, 'timestamp', 'timestamp')

    raw_hash = hash_raw_event(raw)
    identity = ['wazuh-evidence-v1', environment_id, source_ref, 1, raw_hash]
    identity_bytes = json.dumps(identity, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    event_id = 'wazuh:evidence-v1:' + hash_raw_event(identity_bytes)
    raw_ref = source_ref + '#record=1'
    # The firewall running the agent is not the endpoint of the flow: no hostname.
    fields.update(
        source_type='wazuh', event_provider='suricata', rule_id=rule_id,
        source_record_id=_string(source, 'id', 'id'),
        asset_id=agent_id if collection_mode == 'direct' else None,
    )
    try:
        event = CanonicalEventV2(**fields, event_id=event_id, environment_id=environment_id,
                                 ingested_at=ingestion, raw_event_ref=raw_ref, raw_event_hash=raw_hash)
    except ValidationError as error:
        location = error.errors(include_input=False, include_context=False, include_url=False)[0]['loc']
        field = 'canonical.' + str(location[0]) if location else None
        raise WazuhParseError('canonical_validation', field) from None
    provenance = SuricataAlertProvenance(
        source_fraction_digits=metadata['source_fraction_digits'], source_ref=source_ref,
        line_end=raw.count(b'\n') + int(bool(raw) and not raw.endswith(b'\n')),
        raw_event_ref=raw_ref, raw_event_hash=raw_hash, event_id=event_id,
        collection_mode=collection_mode, collector_agent_id=agent_id,
        collector_agent_name=agent_name, collector_manager_name=manager_name,
        collector_received_at=received_at, wazuh_rule_id=rule_id,
        wazuh_rule_level=_integer(rule, 'level', 'rule.level'),
        signature_id=metadata['signature_id'], signature_gid=metadata['signature_gid'],
        signature_rev=metadata['signature_rev'], signature_text=metadata['signature_text'],
        signature_category=metadata['signature_category'], app_proto=metadata['app_proto'],
        in_iface=metadata['in_iface'], source_alert_action=metadata['source_alert_action'],
        flow_id_raw=metadata['flow_id_raw'],
    )
    return SuricataAlertResult(event=event, provenance=provenance)
