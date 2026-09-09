"""Bounded direct EVE JSONL: atomic bytes API and lazy, explicit-outcome file API."""
from collections.abc import Iterator
from datetime import datetime
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re

from pydantic import ValidationError

from aegis_verify.connectors.wazuh._json import MAX_BYTES, decode_document
from aegis_verify.connectors.wazuh.errors import WazuhParseError
from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp

from ._context import validate_context, validate_label
from ._eve_mapping import map_eve
from .errors import SuricataParseError
from .eve_models import SuricataEveProvenance, SuricataEveRecord

MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 100_000
_BOM = b'\xef\xbb\xbf'


def _line(raw, index, context):
    data_bytes = raw
    if raw.startswith(_BOM):
        if index != 1:
            raise SuricataParseError('invalid_bom')
        data_bytes = raw[len(_BOM):]
    raw_hash = hash_raw_event(raw)
    raw_ref = f"{context['source_ref']}#L{index}-L{index}"
    provenance = dict(source_ref=context['source_ref'], sensor_id=context['sensor_id'],
        deployment_mode=context['deployment_mode'], record_index=index,
        line_start=index, line_end=index, raw_event_hash=raw_hash, raw_event_ref=raw_ref)
    if not data_bytes.strip(b' \t\r\n'):
        return SuricataEveRecord(status='skipped', reason='blank_line',
                                provenance=SuricataEveProvenance(**provenance))
    try:
        document = decode_document(raw)
    except WazuhParseError as error:
        d = error.diagnostic
        raise SuricataParseError(d.code, column=d.column) from None
    kind = document.get('event_type')
    if type(kind) is not str or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', kind):
        raise SuricataParseError('invalid_field', 'event_type')
    provenance['event_type'] = kind
    if kind not in ('alert', 'flow'):
        return SuricataEveRecord(status='skipped', reason='unsupported_event_type',
                                provenance=SuricataEveProvenance(**provenance))
    fields, metadata = map_eve(document, kind)
    identity = ['suricata-eve-evidence-v1', context['environment_id'],
                context['sensor_id'], context['source_ref'], index, raw_hash]
    event_id = 'suricata:eve-evidence-v1:' + sha256(json.dumps(
        identity, ensure_ascii=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    try:
        event = CanonicalEventV2(**fields, event_id=event_id, environment_id=context['environment_id'],
            ingested_at=context['ingested_at'], raw_event_ref=raw_ref, raw_event_hash=raw_hash)
    except ValidationError as error:
        loc = error.errors(include_input=False, include_context=False, include_url=False)[0]['loc']
        raise SuricataParseError('canonical_validation', 'canonical.' + str(loc[0]) if loc else None) from None
    warnings = ('ids_blocked_action_requires_review',) if context['deployment_mode']=='ids' and fields.get('event_action')=='blocked' else ()
    return SuricataEveRecord(status='parsed', event=event,
        provenance=SuricataEveProvenance(**provenance, **metadata, event_id=event_id,
                                       timestamp_basis='eve.timestamp', warnings=warnings))


def _read_stream(stream, context):
    total, index = 0, 0
    while True:
        raw = stream.readline(MAX_BYTES + 1)
        if not raw:
            return
        index += 1
        total += len(raw)
        try:
            if index > MAX_RECORDS:
                raise SuricataParseError('max_records')
            if total > MAX_FILE_BYTES:
                raise SuricataParseError('total_input_too_large')
            if len(raw) > MAX_BYTES:
                raise SuricataParseError('input_too_large')
            yield _line(raw, index, context)
        except SuricataParseError as error:
            d = error.diagnostic
            raise SuricataParseError(d.code, d.field_path, line=index,
                                    record_index=index, column=d.column) from None


def _context(source_ref, environment_id, sensor_id, ingested_at, deployment_mode):
    ingested = validate_context(source_ref, environment_id, ingested_at, deployment_mode)
    validate_label(sensor_id, 'sensor_id')
    return dict(source_ref=source_ref, environment_id=environment_id, sensor_id=sensor_id,
                ingested_at=ingested, deployment_mode=deployment_mode)


def parse_suricata_eve_jsonl(raw: bytes, *, source_ref: str, environment_id: str,
    sensor_id: str, ingested_at: datetime | str | PreciseTimestamp,
    deployment_mode: str) -> tuple[SuricataEveRecord, ...]:
    """Return every physical line outcome, or raise without returning a partial tuple."""
    context = _context(source_ref, environment_id, sensor_id, ingested_at, deployment_mode)
    if type(raw) is not bytes:
        raise SuricataParseError('input_type')
    if len(raw) > MAX_FILE_BYTES:
        raise SuricataParseError('total_input_too_large')
    count = raw.count(b'\n') + int(bool(raw) and not raw.endswith(b'\n'))
    if count > MAX_RECORDS:
        raise SuricataParseError('max_records', line=MAX_RECORDS+1, record_index=MAX_RECORDS+1)
    with BytesIO(raw) as stream:
        return tuple(_read_stream(stream, context))


def iter_suricata_eve_file(path: str | Path, *, source_ref: str, environment_id: str,
    sensor_id: str, ingested_at: datetime | str | PreciseTimestamp,
    deployment_mode: str) -> Iterator[SuricataEveRecord]:
    """Lazy: a later error leaves earlier yields valid but the overall import incomplete.

    Exhaust the iterator or call close() when stopping early to release its file.
    """
    context = _context(source_ref, environment_id, sensor_id, ingested_at, deployment_mode)
    if not isinstance(path, (str, Path)):
        raise SuricataParseError('io_error') from None
    try:
        with open(path, 'rb') as stream:
            yield from _read_stream(stream, context)
    except OSError:
        raise SuricataParseError('io_error') from None
    except ValueError as error:
        if isinstance(error, SuricataParseError):
            raise
        raise SuricataParseError('io_error') from None
