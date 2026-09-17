"""Explicit, bytes-only manager JSONL adapter with canonical events and trace.

No filesystem, network, live collection, time substitution or assurance inference.
All input is verified before returning a result; errors never return partial data.
"""

from dataclasses import replace
import hashlib
import io
import re

from ._snapshot_contracts import (
    ManagerSnapshot, ManagerSnapshotError, ManagerSnapshotResult, ManagerSnapshotScope,
    SnapshotDocument, SnapshotLedgerEntry, SnapshotMetadata,
)
from ._snapshot_scope import classify, validate_scope, valid_text
from ._json import MAX_BYTES, decode_document
from .errors import WazuhParseError
from .windows_telemetry import (
    parse_wazuh_sysmon1_document, parse_wazuh_powershell4104_document,
)


MAX_SNAPSHOTS = 32
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_LINES = 20_000
MAX_DOCUMENTS = 100
_BOM = b'\xef\xbb\xbf'
# Reserve 11 characters for "-line-20000" within the parser's 128-char label.
_LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,115}')
_HASH = re.compile(r'[0-9a-f]{64}')
_PARSERS = {
    'wazuh-sysmon1-v1': parse_wazuh_sysmon1_document,
    'wazuh-powershell4104-v1': parse_wazuh_powershell4104_document,
}


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _inputs(snapshots):
    if type(snapshots) is not tuple:
        raise ManagerSnapshotError('invalid_input')
    if len(snapshots) > MAX_SNAPSHOTS:
        raise ManagerSnapshotError('resource_limit')
    labels, hashes, total = set(), set(), 0
    for index, item in enumerate(snapshots):
        def fail(code):
            raise ManagerSnapshotError(code, snapshot_index=index)

        if type(item) is not ManagerSnapshot:
            fail('invalid_input')
        label, raw, digest = (getattr(item, key, None) for key in ('source_label', 'raw', 'sha256'))
        if (type(label) is not str or _LABEL.fullmatch(label) is None or type(raw) is not bytes
                or type(digest) is not str or _HASH.fullmatch(digest) is None):
            fail('invalid_input')
        total += len(raw)
        if len(raw) > MAX_SNAPSHOT_BYTES or total > MAX_TOTAL_BYTES:
            fail('resource_limit')
        if _digest(raw) != digest:
            fail('hash_mismatch')
        if label in labels or digest in hashes:
            fail('duplicate_snapshot')
        labels.add(label)
        hashes.add(digest)


def _record(body, bom_removed):
    if bom_removed:
        body = body[len(_BOM):]
    if body.startswith(_BOM):
        raise ManagerSnapshotError('invalid_record')
    if not body.strip(b' \t\r'):
        return body, None, None
    wrapped = b'{"_source":' + body + b'}'
    if len(wrapped) > MAX_BYTES:
        raise ManagerSnapshotError('resource_limit')
    try:
        record = decode_document(body)
    except WazuhParseError as error:
        raise ManagerSnapshotError('invalid_record', parser_code=error.diagnostic.code) from None
    if '_source' in record:
        raise ManagerSnapshotError('invalid_record')
    return body, record, wrapped


def _identity(record):
    record_id = record.get('id')
    if record_id is not None and not valid_text(record_id):
        raise ManagerSnapshotError('invalid_record')
    manager = record.get('manager')
    if manager is not None and type(manager) is not dict:
        raise ManagerSnapshotError('invalid_record')
    name = manager.get('name') if manager else None
    if name is not None and not valid_text(name):
        raise ManagerSnapshotError('invalid_record')
    return (name, record_id) if record_id is not None else None


def parse_manager_snapshots(snapshots: tuple[ManagerSnapshot, ...], *,
                            scope: ManagerSnapshotScope) -> ManagerSnapshotResult:
    """Parse verified snapshot bytes; start/end are a closed Windows-time interval.

    Scope declares direct agent collection. Records lacking enough metadata to
    classify are errors. Evidence retains the parser's missing/null semantics.
    Source labels must remain stable to preserve derived evidence identity.
    """
    start, end, ingestion = validate_scope(scope)
    _inputs(snapshots)
    documents, ledger, metadata = [], [], []
    identities, bodies = set(), set()
    for index, item in enumerate(snapshots):
        count, offset = 0, 0
        for line in io.BytesIO(item.raw):
            count += 1
            try:
                if len(ledger) >= MAX_LINES:
                    raise ManagerSnapshotError('resource_limit')
                body = line[:-1] if line.endswith(b'\n') else line
                if line.endswith(b'\r\n'):
                    body = body[:-1]
                bom = offset == 0 and body.startswith(_BOM)
                body, record, wrapped = _record(body, bom)
                row = SnapshotLedgerEntry(
                    item.source_label, item.sha256, count, offset, len(line),
                    _digest(line), bom, 'bookkeeping', 'blank_line',
                )
                if record is not None:
                    identity, body_hash = _identity(record), _digest(body)
                    if body_hash in bodies or (identity is not None and identity in identities):
                        raise ManagerSnapshotError('duplicate_record')
                    bodies.add(body_hash)
                    if identity is not None:
                        identities.add(identity)
                    parser, reason = classify(record, scope, start, end)
                    row = replace(row, disposition='excluded', reason=reason,
                                  source_record_id=record.get('id'))
                    if parser is not None:
                        if len(documents) >= MAX_DOCUMENTS:
                            raise ManagerSnapshotError('resource_limit')
                        source_ref = item.source_label + '-line-' + str(count)
                        try:
                            telemetry = _PARSERS[parser](
                                wrapped, source_ref=source_ref, environment_id=scope.environment_id,
                                ingested_at=ingestion, collection_mode='direct',
                            )
                        except WazuhParseError as error:
                            raise ManagerSnapshotError('parser_error', parser_code=error.diagnostic.code) from None
                        documents.append(SnapshotDocument(wrapped, source_ref, parser, telemetry))
                        row = replace(row, disposition='selected', document_sha256=_digest(wrapped),
                                      document_source_ref=source_ref)
                ledger.append(row)
            except ManagerSnapshotError as error:
                diagnostic = error.diagnostic
                raise ManagerSnapshotError(diagnostic.code, snapshot_index=index, line=count,
                                           parser_code=diagnostic.parser_code) from None
            offset += len(line)
        metadata.append(SnapshotMetadata(item.source_label, item.sha256, len(item.raw), count))
    return ManagerSnapshotResult(tuple(documents), tuple(ledger), tuple(metadata))
