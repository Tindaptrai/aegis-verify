"""Bounded Snort 3 alert_json JSONL: atomic bytes API and lazy, explicit-outcome file API."""
from collections.abc import Iterator
from datetime import datetime
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path

from pydantic import ValidationError

from aegis_verify.connectors.wazuh._json import MAX_BYTES, decode_document
from aegis_verify.connectors.wazuh.errors import WazuhParseError
from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp

from ._context import validate_context
from ._mapping import map_alert
from .errors import SnortParseError
from .models import SnortAlertJsonProvenance, SnortAlertJsonRecord

MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 100_000
_BOM = b'\xef\xbb\xbf'


def _line(raw, index, context):
    data_bytes = raw
    if raw.startswith(_BOM):
        if index != 1:
            raise SnortParseError('invalid_bom')
        data_bytes = raw[len(_BOM):]
    raw_hash = hash_raw_event(raw)
    raw_ref = f"{context['source_ref']}#L{index}-L{index}"
    provenance = dict(source_ref=context['source_ref'], sensor_id=context['sensor_id'],
        deployment_mode=context['deployment_mode'], record_index=index,
        line_start=index, line_end=index, raw_event_hash=raw_hash, raw_event_ref=raw_ref)
    if not data_bytes.strip(b' \t\r\n'):
        return SnortAlertJsonRecord(status='skipped', reason='blank_line',
                                    provenance=SnortAlertJsonProvenance(**provenance))
    try:
        document = decode_document(raw)
    except WazuhParseError as error:
        d = error.diagnostic
        raise SnortParseError(d.code, column=d.column) from None
    fields, metadata, has_ip = map_alert(document)
    if not has_ip:
        return SnortAlertJsonRecord(status='skipped', reason='no_ip_header',
                                    provenance=SnortAlertJsonProvenance(**provenance, **metadata))
    identity = ['snort3-alert-json-evidence-v1', context['environment_id'],
                context['sensor_id'], context['source_ref'], index, raw_hash]
    event_id = 'snort:alert-json-evidence-v1:' + sha256(json.dumps(
        identity, ensure_ascii=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    try:
        event = CanonicalEventV2(**fields, event_id=event_id, environment_id=context['environment_id'],
            ingested_at=context['ingested_at'], raw_event_ref=raw_ref, raw_event_hash=raw_hash)
    except ValidationError as error:
        loc = error.errors(include_input=False, include_context=False, include_url=False)[0]['loc']
        raise SnortParseError('canonical_validation', 'canonical.' + str(loc[0]) if loc else None) from None
    warnings = (('ids_blocked_action_requires_review',)
                if context['deployment_mode'] == 'ids' and fields['event_action'] == 'blocked' else ())
    return SnortAlertJsonRecord(status='parsed', event=event,
        provenance=SnortAlertJsonProvenance(**provenance, **metadata, event_id=event_id,
                                            timestamp_basis='alert_json.seconds', warnings=warnings))


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
                raise SnortParseError('max_records')
            if total > MAX_FILE_BYTES:
                raise SnortParseError('total_input_too_large')
            if len(raw) > MAX_BYTES:
                raise SnortParseError('input_too_large')
            yield _line(raw, index, context)
        except SnortParseError as error:
            d = error.diagnostic
            raise SnortParseError(d.code, d.field_path, line=index,
                                  record_index=index, column=d.column) from None


def parse_snort_alert_json(raw: bytes, *, source_ref: str, environment_id: str,
    sensor_id: str, ingested_at: datetime | str | PreciseTimestamp,
    deployment_mode: str) -> tuple[SnortAlertJsonRecord, ...]:
    """Return every physical line outcome, or raise without returning a partial tuple."""
    context = validate_context(source_ref, environment_id, sensor_id, ingested_at, deployment_mode)
    if type(raw) is not bytes:
        raise SnortParseError('input_type')
    if len(raw) > MAX_FILE_BYTES:
        raise SnortParseError('total_input_too_large')
    count = raw.count(b'\n') + int(bool(raw) and not raw.endswith(b'\n'))
    if count > MAX_RECORDS:
        raise SnortParseError('max_records', line=MAX_RECORDS + 1, record_index=MAX_RECORDS + 1)
    with BytesIO(raw) as stream:
        return tuple(_read_stream(stream, context))


def iter_snort_alert_json_file(path: str | Path, *, source_ref: str, environment_id: str,
    sensor_id: str, ingested_at: datetime | str | PreciseTimestamp,
    deployment_mode: str) -> Iterator[SnortAlertJsonRecord]:
    """Lazy: a later error leaves earlier yields valid but the overall import incomplete.

    Exhaust the iterator or call close() when stopping early to release its file.
    """
    context = validate_context(source_ref, environment_id, sensor_id, ingested_at, deployment_mode)
    if not isinstance(path, (str, Path)):
        raise SnortParseError('io_error') from None
    try:
        with open(path, 'rb') as stream:
            yield from _read_stream(stream, context)
    except OSError:
        raise SnortParseError('io_error') from None
    except ValueError as error:
        if isinstance(error, SnortParseError):
            raise
        raise SnortParseError('io_error') from None
