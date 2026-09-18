"""Snapshot transport metadata; never substitutes for canonical evidence."""

from dataclasses import dataclass, field
from typing import Literal

from .windows_telemetry import WindowsTelemetryResult


@dataclass(frozen=True, slots=True)
class ManagerSnapshot:
    source_label: str
    raw: bytes = field(repr=False)
    sha256: str


@dataclass(frozen=True, slots=True)
class ManagerSnapshotScope:
    agent_id: str
    hostname: str
    environment_id: str
    start: str
    end: str
    ingested_at: str


@dataclass(frozen=True, slots=True)
class SnapshotMetadata:
    source_label: str
    sha256: str
    byte_length: int
    line_count: int


@dataclass(frozen=True, slots=True)
class SnapshotDocument:
    raw: bytes = field(repr=False)
    source_ref: str
    parser: Literal['wazuh-sysmon1-v1', 'wazuh-powershell4104-v1']
    telemetry: WindowsTelemetryResult = field(repr=False)


@dataclass(frozen=True, slots=True)
class SnapshotLedgerEntry:
    source_label: str
    snapshot_sha256: str
    line: int
    byte_offset: int
    byte_length: int
    line_sha256: str
    bom_removed: bool
    disposition: Literal['selected', 'excluded', 'bookkeeping']
    reason: str
    source_record_id: str | None = None
    document_sha256: str | None = None
    document_source_ref: str | None = None


@dataclass(frozen=True, slots=True)
class ManagerSnapshotResult:
    documents: tuple[SnapshotDocument, ...]
    ledger: tuple[SnapshotLedgerEntry, ...]
    snapshots: tuple[SnapshotMetadata, ...]

    @property
    def collection_assurance(self) -> Literal['unknown']:
        # Reading all supplied bytes cannot prove collection completeness.
        return 'unknown'


@dataclass(frozen=True, slots=True)
class SnapshotDiagnostic:
    code: str
    snapshot_index: int | None
    line: int | None
    parser_code: str | None


_CODES = frozenset({'invalid_input', 'invalid_context', 'hash_mismatch', 'invalid_record',
                    'unclassifiable_record', 'parser_error', 'duplicate_snapshot',
                    'duplicate_record', 'resource_limit'})


class ManagerSnapshotError(ValueError):
    def __init__(self, code, *, snapshot_index=None, line=None, parser_code=None):
        from .errors import _CODES as parser_codes

        self.diagnostic = SnapshotDiagnostic(
            code if type(code) is str and code in _CODES else 'invalid_input',
            snapshot_index if type(snapshot_index) is int and snapshot_index >= 0 else None,
            line if type(line) is int and line > 0 else None,
            parser_code if type(parser_code) is str and parser_code in parser_codes else None,
        )
        super().__init__(self.diagnostic.code)
