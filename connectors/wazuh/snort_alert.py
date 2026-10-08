"""One offline manager alert record whose data is a Snort 3 alert; no collection.

The record proves that Wazuh received a Snort alert and raised its own rule for
it. It is a wazuh-source event: the Wazuh rule ID is the detection, the Snort
alert is where the flow tuple, signature and source time come from. The tuple
and time policy are the Snort connector's own, so a direct Snort view and this
Wazuh view of the same alert carry identical values.

Pinned profile (Lab C): Wazuh reads `alert_json` with the `json` decoder, so the
record keeps the original alert line in `full_log` and a stringified copy of it
in `data`. The line in `full_log` is what gets mapped; every field in `data` is
then required to match it, which is what makes "Wazuh received this alert" a
checked statement instead of an assumption.
"""

from datetime import datetime
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp
from aegis_verify.connectors.snort._mapping import map_alert
from aegis_verify.connectors.snort.errors import PINNED_FIELDS, SnortParseError
from ._json import decode_document
from .errors import WazuhParseError
from .parser import _context, _integer, _object, _string


_RULE_ID = re.compile(r'[0-9]{1,128}')
# Group written by a Wazuh rule that decodes Snort output. Either spelling is accepted;
# the matched one is recorded. Without it the record is some other source's alert.
SNORT_GROUPS = ('snort3', 'snort')
DECODER = 'json'


class SnortAlertProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)

    mapping_version: Literal['wazuh-snort-alert-v1'] = 'wazuh-snort-alert-v1'
    envelope: Literal['manager_alert'] = 'manager_alert'
    timestamp_basis: Literal['snort.full_log.timestamp'] = 'snort.full_log.timestamp'
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
    # Wazuh receipt time as written, kept apart from the Snort source time.
    collector_received_at: str | None
    # Where the agent read the alert, as the manager recorded it.
    collector_location: str | None
    decoder_name: str
    wazuh_rule_id: str
    wazuh_rule_level: int | None
    wazuh_rule_groups: tuple[str, ...]
    # How many stringified fields in `data` were confirmed against `full_log`.
    confirmed_data_fields: int
    source_seconds: int
    signature_id: str
    signature_gid: str
    signature_rev: str
    signature_text: str
    signature_category: str
    app_proto: str
    direction: str
    pkt_gen: str
    pkt_len: int
    pkt_num: int
    source_alert_action: str
    source_priority: int
    has_ip_header: bool


class SnortAlertResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid', hide_input_in_errors=True)

    event: CanonicalEventV2
    provenance: SnortAlertProvenance


def _rule_id(rule):
    value = rule.get('id')
    if type(value) is int and value >= 0:
        return str(value)
    if type(value) is str and _RULE_ID.fullmatch(value) is not None:
        return value
    raise WazuhParseError('invalid_field', 'rule.id') from None


def _groups(rule):
    groups = rule.get('groups')
    if type(groups) is not list or not groups or any(type(item) is not str for item in groups):
        raise WazuhParseError('invalid_field', 'rule.groups') from None
    if not any(group in SNORT_GROUPS for group in groups):
        raise WazuhParseError('unsupported_profile', 'rule.groups') from None
    return tuple(groups)


def _alert_line(source):
    """The original alert line kept by the json decoder, decoded with the same bounds."""
    text = source.get('full_log')
    if type(text) is not str or not text:
        raise WazuhParseError('invalid_field', 'full_log') from None
    line = decode_document(text.encode('utf-8'))
    try:
        return map_alert(line), line
    except SnortParseError as error:
        # A Snort diagnostic names a field of the line; report the envelope field instead,
        # so the message cannot say which value inside the line was rejected.
        raise WazuhParseError(error.diagnostic.code, 'full_log') from None


def _confirm_data(data, line):
    """Every field of the decoded copy must equal the line, as the strings Wazuh wrote."""
    if set(data) != set(line):
        raise WazuhParseError('unsupported_profile', 'data') from None
    for key in PINNED_FIELDS:
        if key not in line:
            continue
        value, expected = data[key], line[key]
        if type(value) is not str or value != (expected if type(expected) is str else str(expected)):
            raise WazuhParseError('invalid_field', 'data.' + key) from None
    return len(data)


def parse_wazuh_snort_alert_record(
    raw: bytes, *, source_ref: str, environment_id: str,
    ingested_at: datetime | str | PreciseTimestamp, collection_mode: str,
) -> SnortAlertResult:
    """Parse exact alert bytes. A raised Wazuh rule is not a prevention verdict.

    Deliberately rejects search hits, records whose rule is not from a Snort
    group, records that did not come through the `json` decoder, records without
    the original alert line, records whose decoded copy disagrees with that line,
    and records without a decimal Wazuh rule ID. `event_action` stays what the
    alert says; an IDS `allow` is never turned into prevention evidence.
    """
    ingestion = _context(source_ref, environment_id, ingested_at, collection_mode)
    source = decode_document(raw)
    if '_source' in source:
        raise WazuhParseError('unsupported_profile', '_source') from None
    rule = _object(source, 'rule', 'rule')
    groups = _groups(rule)
    rule_id = _rule_id(rule)
    decoder = _object(source, 'decoder', 'decoder')
    if decoder.get('name') != DECODER:
        raise WazuhParseError('unsupported_profile', 'decoder.name') from None
    (fields, metadata, has_ip), line = _alert_line(source)
    confirmed = _confirm_data(_object(source, 'data', 'data'), line)

    agent = _object(source, 'agent', 'agent', optional=True)
    manager = _object(source, 'manager', 'manager', optional=True)
    agent_id = _string(agent, 'id', 'agent.id')
    agent_name = _string(agent, 'name', 'agent.name')
    manager_name = _string(manager, 'name', 'manager.name')
    received_at = _string(source, 'timestamp', 'timestamp')
    location = _string(source, 'location', 'location')

    raw_hash = hash_raw_event(raw)
    identity = ['wazuh-evidence-v1', environment_id, source_ref, 1, raw_hash]
    identity_bytes = json.dumps(identity, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    event_id = 'wazuh:evidence-v1:' + hash_raw_event(identity_bytes)
    raw_ref = source_ref + '#record=1'
    # The sensor running the agent is not an endpoint of the flow: no hostname.
    fields.update(
        source_type='wazuh', event_provider='snort', rule_id=rule_id,
        source_record_id=_string(source, 'id', 'id'),
        asset_id=agent_id if collection_mode == 'direct' else None,
    )
    try:
        event = CanonicalEventV2(**fields, event_id=event_id, environment_id=environment_id,
                                 ingested_at=ingestion, raw_event_ref=raw_ref, raw_event_hash=raw_hash)
    except ValidationError as error:
        location_path = error.errors(include_input=False, include_context=False, include_url=False)[0]['loc']
        field = 'canonical.' + str(location_path[0]) if location_path else None
        raise WazuhParseError('canonical_validation', field) from None
    provenance = SnortAlertProvenance(
        source_fraction_digits=metadata['source_fraction_digits'], source_ref=source_ref,
        line_end=raw.count(b'\n') + int(bool(raw) and not raw.endswith(b'\n')),
        raw_event_ref=raw_ref, raw_event_hash=raw_hash, event_id=event_id,
        collection_mode=collection_mode, collector_agent_id=agent_id,
        collector_agent_name=agent_name, collector_manager_name=manager_name,
        collector_received_at=received_at, collector_location=location, decoder_name=DECODER,
        wazuh_rule_id=rule_id, wazuh_rule_level=_integer(rule, 'level', 'rule.level'),
        wazuh_rule_groups=groups, confirmed_data_fields=confirmed,
        source_seconds=metadata['source_seconds'], signature_id=metadata['signature_id'],
        signature_gid=metadata['signature_gid'], signature_rev=metadata['signature_rev'],
        signature_text=metadata['signature_text'], signature_category=metadata['signature_category'],
        app_proto=metadata['app_proto'], direction=metadata['direction'], pkt_gen=metadata['pkt_gen'],
        pkt_len=metadata['pkt_len'], pkt_num=metadata['pkt_num'],
        source_alert_action=metadata['source_alert_action'], source_priority=metadata['source_priority'],
        has_ip_header=has_ip,
    )
    return SnortAlertResult(event=event, provenance=provenance)
