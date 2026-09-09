"""Direction A: one local Wazuh search-hit containing a Suricata alert."""
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import re

from pydantic import ValidationError

from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp
from aegis_verify.connectors.wazuh._json import MAX_BYTES, decode_document
from aegis_verify.connectors.wazuh.errors import WazuhParseError

from ._fields import decimal_id, number, object_field, text
from ._mapping import map_alert
from .errors import SuricataParseError
from .models import SuricataParseResult, SuricataProvenance
from ._context import validate_context


def parse_suricata_wazuh_document(raw: bytes, *, source_ref: str, environment_id: str,
                                  ingested_at: datetime | str | PreciseTimestamp,
                                  deployment_mode: str) -> SuricataParseResult:
    ingested = validate_context(source_ref, environment_id, ingested_at, deployment_mode)
    try:
        document = decode_document(raw)
    except WazuhParseError as error:
        d = error.diagnostic
        raise SuricataParseError(d.code, line=d.line, column=d.column) from None
    if document.get('_source') is None:
        raise SuricataParseError('missing_source', '_source')
    source = object_field(document['_source'], '_source')
    data = object_field(source.get('data'), '_source.data')
    rule = object_field(source.get('rule'), '_source.rule')
    groups = rule.get('groups')
    if type(groups) is not list or any(type(item) is not str for item in groups):
        raise SuricataParseError('invalid_field', '_source.rule.groups')
    if 'suricata' not in groups:
        raise SuricataParseError('unsupported_profile', '_source.rule.groups')
    if type(data.get('event_type')) is not str:
        raise SuricataParseError('invalid_field', '_source.data.event_type')
    if data['event_type'] != 'alert':
        raise SuricataParseError('unsupported_profile', '_source.data.event_type')
    fields, metadata = map_alert(data)
    agent = object_field(source.get('agent'), '_source.agent', optional=True)
    manager = object_field(source.get('manager'), '_source.manager', optional=True)
    rule_id = rule.get('id')
    rule_id = decimal_id(rule_id, '_source.rule.id') if type(rule_id) is int else text(rule_id, '_source.rule.id')
    fields.update(rule_id=rule_id, source_record_id=text(source.get('id'), '_source.id'))
    metadata.update(wazuh_rule_id=rule_id, wazuh_rule_level=number(rule.get('level'), '_source.rule.level'),
                    collector_manager_name=text(manager.get('name'), '_source.manager.name'))
    for key in ('id', 'name', 'ip'):
        metadata['collector_agent_' + key] = text(agent.get(key), '_source.agent.' + key)

    raw_hash = hash_raw_event(raw)
    identity = json.dumps(['suricata-evidence-v1', environment_id, source_ref, 1, raw_hash],
                          ensure_ascii=True, separators=(',', ':')).encode('utf-8')
    event_id = 'suricata:evidence-v1:' + sha256(identity).hexdigest()
    lines = re.split(rb'\r\n|\r|\n', raw)
    line_end = len(lines) - (1 if lines[-1] == b'' else 0)
    try:
        event = CanonicalEventV2(**fields, event_id=event_id, environment_id=environment_id,
                                 ingested_at=ingested, raw_event_hash=raw_hash,
                                 raw_event_ref=f'{source_ref}#L1-L{line_end}')
    except ValidationError as error:
        loc = error.errors(include_input=False, include_context=False, include_url=False)[0]['loc']
        path = 'canonical.' + str(loc[0]) if loc else None
        raise SuricataParseError('canonical_validation', path) from None
    provenance = SuricataProvenance(**metadata, source_ref=source_ref, line_end=line_end,
        event_id=event_id, raw_event_hash=raw_hash, deployment_mode=deployment_mode,
        warnings=('ids_blocked_action_requires_review',) if deployment_mode == 'ids' and fields['event_action'] == 'blocked' else ())
    return SuricataParseResult(event=event, provenance=provenance)


def load_suricata_wazuh_document(path: str | Path, *, source_ref: str, environment_id: str,
                                 ingested_at: datetime | str | PreciseTimestamp,
                                 deployment_mode: str) -> SuricataParseResult:
    try:
        if not isinstance(path, (str, Path)):
            raise TypeError
        with open(path, 'rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
    except (OSError, TypeError, ValueError):
        raise SuricataParseError('io_error') from None
    return parse_suricata_wazuh_document(raw, source_ref=source_ref, environment_id=environment_id,
        ingested_at=ingested_at, deployment_mode=deployment_mode)
