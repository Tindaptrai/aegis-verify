"""Bounded offline parser for native Cowrie JSONL evidence."""

from collections.abc import Iterator
from datetime import datetime
from io import BytesIO
from pathlib import Path
import re

from pydantic import ValidationError

from aegis_verify.connectors.wazuh._json import MAX_BYTES, decode_document
from aegis_verify.connectors.wazuh.errors import WazuhParseError
from aegis_verify.evidence import hash_raw_event
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp

from ._context import native_evidence_id, session_key, validate_context
from ._mapping import map_cowrie_event
from .errors import CowrieParseError
from .models import SOURCE_KINDS
from .native_models import CowrieNativeProvenance, CowrieNativeRecord


MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 100_000
_BOM = b"\xef\xbb\xbf"
_EVENT_KIND = re.compile(
    r"cowrie\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", re.ASCII
)


def _decode(raw: bytes) -> dict:
    try:
        return decode_document(raw)
    except WazuhParseError as error:
        diagnostic = error.diagnostic
        raise CowrieParseError(
            diagnostic.code,
            line=diagnostic.line,
            column=diagnostic.column,
            record_index=diagnostic.record_index,
        ) from None


def _line(raw: bytes, index: int, context: dict) -> CowrieNativeRecord:
    if raw.startswith(_BOM) and (
        index != 1 or raw.startswith(_BOM + _BOM)
    ):
        raise CowrieParseError("invalid_bom") from None

    raw_hash = hash_raw_event(raw)
    raw_ref = f"{context['source_ref']}#L{index}-L{index}"
    identifier = native_evidence_id(
        context["environment_id"],
        context["sensor_id"],
        context["source_ref"],
        index,
        raw_hash,
    )
    provenance = {
        "environment_id": context["environment_id"],
        "sensor_id": context["sensor_id"],
        "source_ref": context["source_ref"],
        "record_index": index,
        "line_start": index,
        "line_end": index,
        "event_id": identifier,
        "raw_event_hash": raw_hash,
        "raw_event_ref": raw_ref,
    }
    content = raw[len(_BOM):] if index == 1 and raw.startswith(_BOM) else raw
    if not content.strip(b" \t\r\n"):
        return CowrieNativeRecord(
            status="skipped",
            reason="blank_line",
            provenance=CowrieNativeProvenance(**provenance),
        )

    document = _decode(raw)
    kind = document.get("eventid")
    if (
        type(kind) is not str
        or len(kind) > 128
        or _EVENT_KIND.fullmatch(kind) is None
    ):
        raise CowrieParseError("invalid_field", "eventid") from None
    if kind not in SOURCE_KINDS:
        provenance["source_event_type"] = kind
        return CowrieNativeRecord(
            status="skipped",
            reason="unsupported_event_type",
            provenance=CowrieNativeProvenance(**provenance),
        )

    fields, metadata = map_cowrie_event(document, prefix="")
    fields["source_record_id"] = None
    try:
        event = CanonicalEventV2(
            **fields,
            event_id=identifier,
            environment_id=context["environment_id"],
            ingested_at=context["ingested_at"],
            raw_event_hash=raw_hash,
            raw_event_ref=raw_ref,
        )
    except ValidationError as error:
        location = error.errors(
            include_input=False, include_context=False, include_url=False
        )[0]["loc"]
        field_path = "canonical." + str(location[0]) if location else None
        raise CowrieParseError("canonical_validation", field_path) from None
    source_session = metadata["session"]
    native_provenance = CowrieNativeProvenance(
        **provenance,
        **metadata,
        timestamp_basis="cowrie.timestamp",
        session_key=(
            session_key(context["environment_id"], context["sensor_id"], source_session)
            if source_session is not None
            else None
        ),
    )
    return CowrieNativeRecord(
        status="parsed", event=event, provenance=native_provenance
    )


def _read_stream(stream, context: dict) -> Iterator[CowrieNativeRecord]:
    total = 0
    index = 0
    while True:
        raw = stream.readline(MAX_BYTES + 1)
        if not raw:
            return
        index += 1
        total += len(raw)
        try:
            if index > MAX_RECORDS:
                raise CowrieParseError("max_records") from None
            if total > MAX_FILE_BYTES:
                raise CowrieParseError("total_input_too_large") from None
            if len(raw) > MAX_BYTES:
                raise CowrieParseError("input_too_large") from None
            yield _line(raw, index, context)
        except CowrieParseError as error:
            diagnostic = error.diagnostic
            raise CowrieParseError(
                diagnostic.code,
                diagnostic.field_path,
                line=index,
                column=diagnostic.column,
                record_index=index,
            ) from None


def _context(source_ref, environment_id, sensor_id, ingested_at) -> dict:
    ingestion = validate_context(source_ref, environment_id, sensor_id, ingested_at)
    return {
        "source_ref": source_ref,
        "environment_id": environment_id,
        "sensor_id": sensor_id,
        "ingested_at": ingestion,
    }


def parse_cowrie_jsonl(
    raw: bytes,
    *,
    source_ref: str,
    environment_id: str,
    sensor_id: str,
    ingested_at: datetime | str | PreciseTimestamp,
) -> tuple[CowrieNativeRecord, ...]:
    """Return every physical-line outcome atomically, or raise on any failure."""

    context = _context(source_ref, environment_id, sensor_id, ingested_at)
    if type(raw) is not bytes:
        raise CowrieParseError("input_type") from None
    if len(raw) > MAX_FILE_BYTES:
        raise CowrieParseError("total_input_too_large") from None
    count = raw.count(b"\n") + int(bool(raw) and not raw.endswith(b"\n"))
    if count > MAX_RECORDS:
        raise CowrieParseError(
            "max_records", line=MAX_RECORDS + 1, record_index=MAX_RECORDS + 1
        ) from None
    with BytesIO(raw) as stream:
        return tuple(_read_stream(stream, context))


def iter_cowrie_file(
    path: str | Path,
    *,
    source_ref: str,
    environment_id: str,
    sensor_id: str,
    ingested_at: datetime | str | PreciseTimestamp,
) -> Iterator[CowrieNativeRecord]:
    """Yield lazily; exhaust or close the iterator to release the input file."""

    context = _context(source_ref, environment_id, sensor_id, ingested_at)
    if not isinstance(path, (str, Path)):
        raise CowrieParseError("io_error") from None
    try:
        stream = open(path, "rb")
    except (OSError, ValueError):
        raise CowrieParseError("io_error") from None
    try:
        with stream:
            yield from _read_stream(stream, context)
    except OSError:
        raise CowrieParseError("io_error") from None
