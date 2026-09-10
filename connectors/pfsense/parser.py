"""Bounded offline ingestion of pfSense filterlog evidence."""

from collections.abc import Iterator
from datetime import datetime
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from typing import BinaryIO

from pydantic import ValidationError

from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp

from ._context import make_context
from ._mapping import map_filterlog_line
from .errors import PfSenseParseError
from .models import PfSenseContext, PfSenseProvenance, PfSenseRecord

MAX_LINE_BYTES = 256 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 100_000
_BOM = b"\xef\xbb\xbf"


def _line(raw: bytes, index: int, context: PfSenseContext) -> PfSenseRecord:
    data = raw
    if index == 1 and data.startswith(_BOM):
        data = data[len(_BOM):]
    if _BOM in data:
        raise PfSenseParseError("invalid_bom") from None
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise PfSenseParseError("invalid_encoding") from None
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    fields, metadata, reason = map_filterlog_line(text, context)
    raw_hash = hash_raw_event(raw)
    raw_ref = f"{context.source_ref}#L{index}-L{index}"
    provenance = dict(
        source_ref=context.source_ref, sensor_id=context.sensor_id,
        source_year=context.source_year, source_utc_offset=context.source_utc_offset,
        record_index=index, line_start=index, line_end=index,
        raw_event_hash=raw_hash, raw_event_ref=raw_ref,
    ) | metadata
    if fields is None:
        return PfSenseRecord(status="skipped", reason=reason,
                             provenance=PfSenseProvenance(**provenance))
    identity = ["pfsense-filterlog-evidence-v1", context.environment_id,
                context.sensor_id, context.source_ref, index, raw_hash,
                context.source_year, context.source_utc_offset]
    digest = sha256(json.dumps(identity, ensure_ascii=True,
                              separators=(",", ":")).encode("utf-8")).hexdigest()
    event_id = "pfsense:filterlog-evidence-v1:" + digest
    try:
        event = CanonicalEventV2(
            **fields, event_id=event_id, environment_id=context.environment_id,
            ingested_at=context.ingested_at, raw_event_ref=raw_ref,
            raw_event_hash=raw_hash,
        )
    except ValidationError as error:
        location = error.errors(
            include_input=False, include_context=False, include_url=False
        )[0]["loc"]
        field = "canonical." + str(location[0]) if location else None
        raise PfSenseParseError("canonical_validation", field) from None
    return PfSenseRecord(status="parsed", event=event,
                         provenance=PfSenseProvenance(**provenance, event_id=event_id))


def _read_stream(stream: BinaryIO, context: PfSenseContext) -> Iterator[PfSenseRecord]:
    total, index = 0, 0
    while True:
        try:
            raw = stream.readline(MAX_LINE_BYTES + 1)
        except (OSError, ValueError):
            raise PfSenseParseError("io_error", line=index + 1,
                                    record_index=index + 1) from None
        if not raw:
            return
        index += 1
        total += len(raw)
        try:
            if index > MAX_RECORDS:
                raise PfSenseParseError("max_records") from None
            if total > MAX_FILE_BYTES:
                raise PfSenseParseError("total_input_too_large") from None
            if len(raw) > MAX_LINE_BYTES:
                raise PfSenseParseError("input_too_large") from None
            yield _line(raw, index, context)
        except PfSenseParseError as error:
            raise PfSenseParseError(error.code, error.field_path, line=index,
                                    record_index=index) from None


def parse_pfsense_filterlog(
    raw: bytes, *, source_ref: str, environment_id: str, sensor_id: str,
    ingested_at: datetime | str | PreciseTimestamp, source_year: int,
    source_utc_offset: str,
) -> tuple[PfSenseRecord, ...]:
    """Return all physical line outcomes atomically, or raise a safe parse error.

    Hashes include exact original line bytes, including any BOM and LF/CRLF.
    Caller year and offset supply missing BSD timestamp facts; no clock is read.
    """
    context = make_context(
        source_ref=source_ref, environment_id=environment_id, sensor_id=sensor_id,
        ingested_at=ingested_at, source_year=source_year,
        source_utc_offset=source_utc_offset,
    )
    if type(raw) is not bytes:
        raise PfSenseParseError("input_type") from None
    if len(raw) > MAX_FILE_BYTES:
        raise PfSenseParseError("total_input_too_large") from None
    count = raw.count(b"\n") + int(bool(raw) and not raw.endswith(b"\n"))
    if count > MAX_RECORDS:
        raise PfSenseParseError("max_records", line=MAX_RECORDS + 1,
                                record_index=MAX_RECORDS + 1) from None
    with BytesIO(raw) as stream:
        return tuple(_read_stream(stream, context))


def iter_pfsense_filterlog_file(
    path: str | Path, *, source_ref: str, environment_id: str, sensor_id: str,
    ingested_at: datetime | str | PreciseTimestamp, source_year: int,
    source_utc_offset: str,
) -> Iterator[PfSenseRecord]:
    """Read an offline binary file lazily with bounded per-line reads.

    A later error means the entire ingestion is INCOMPLETE despite prior yields.
    Exhaust this iterator to establish completion; call close() when stopping
    early to release the file. Early closure does not establish completion.
    """
    context = make_context(
        source_ref=source_ref, environment_id=environment_id, sensor_id=sensor_id,
        ingested_at=ingested_at, source_year=source_year,
        source_utc_offset=source_utc_offset,
    )
    if not isinstance(path, (str, Path)):
        raise PfSenseParseError("io_error") from None
    try:
        with open(path, "rb") as stream:
            yield from _read_stream(stream, context)
    except PfSenseParseError:
        raise
    except (OSError, ValueError):
        raise PfSenseParseError("io_error") from None
