"""Atomic, bounded assembly of explicit fixture bundles."""

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

from ..models import CanonicalEventV2
from ..validation import EvaluationContext, EvaluationProfile
from .contracts import BundleManifest
from .errors import IntakeError
from .io import _bundle_relative, bundle_path, local_path, read_local
from .registry import LedgerEntry, parse_entry


MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_PHYSICAL_LINES = 20_000
MAX_EVENTS = 10_000
_UNSUPPORTED_REASONS = frozenset(
    {"unsupported_event_type", "unsupported_ip_version", "unsupported_protocol"}
)


@dataclass(frozen=True, slots=True)
class IntakeResult:
    events: tuple[CanonicalEventV2, ...]
    ledger: tuple[LedgerEntry, ...]
    inventory: tuple[dict, ...]


def _context_fingerprint(entry) -> str:
    encoded = json.dumps(
        entry.context.model_dump(mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _inventory(root: Path, manifest: BundleManifest, *, identities=None, source_refs=None, prefix=""):
    selected = []
    identities = set() if identities is None else identities
    source_refs = set() if source_refs is None else source_refs
    for index, entry in enumerate(manifest.files):
        if entry.source_ref in source_refs:
            raise IntakeError("duplicate_source_ref", stage="inputs", file_index=index, field="source_ref")
        source_refs.add(entry.source_ref)
        try:
            path = bundle_path(root, entry.path)
            info = path.stat()
        except IntakeError as error:
            raise IntakeError(
                error.code,
                stage=error.stage,
                file_index=index,
                field=error.field,
                line=error.line,
            ) from None
        except (OSError, ValueError):
            raise IntakeError("input_io", stage="evidence", file_index=index) from None
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise IntakeError("duplicate_file", stage="inputs", file_index=index, field="path")
        identities.add(identity)
        selected.append((index, path, entry, manifest.environment_id, prefix + entry.path))
    return tuple(selected)


def _physical_lines(raw: bytes) -> int:
    return raw.count(b"\n") + int(bool(raw) and not raw.endswith(b"\n"))


def load_bundle(root: Path, manifest: BundleManifest) -> IntakeResult:
    """Read, verify and parse all entries, returning nothing on any failure."""
    if type(manifest) is not BundleManifest:
        raise IntakeError("invalid_manifest", stage="inputs")
    return _load_selected(_inventory(root, manifest))


def load_bundle_set(root: Path, members: tuple[tuple[str, BundleManifest], ...]) -> IntakeResult:
    """Atomically load leaves with shared budgets and evidence identity checks.

    Source references are already assigned by their producer. Only inventory
    paths are qualified here, so canonical IDs and ledger references still
    identify the exact source reference that the parser consumed.
    """
    if type(members) is not tuple:
        raise IntakeError("invalid_manifest", stage="inputs")
    if len(members) > 32:
        raise IntakeError("resource_limit", stage="inputs")
    root = local_path(root, directory=True, stage="inputs")
    selected, identities, source_refs, directories = [], set(), set(), set()
    environment_id = None
    for member in members:
        if type(member) is not tuple or len(member) != 2 or type(member[1]) is not BundleManifest:
            raise IntakeError("invalid_manifest", stage="inputs")
        relative, manifest = member
        relative = _bundle_relative(relative, stage="inputs")
        directory = local_path(root / relative, directory=True, stage="inputs")
        if directory in directories:
            raise IntakeError("duplicate_file", stage="inputs", field="path")
        directories.add(directory)
        if environment_id is not None and manifest.environment_id != environment_id:
            raise IntakeError("environment_mismatch", stage="inputs", field="environment_id")
        environment_id = manifest.environment_id
        selected.extend(_inventory(directory, manifest, identities=identities,
                                   source_refs=source_refs, prefix=relative + "/"))
    return _load_selected(selected)


def _load_selected(selected) -> IntakeResult:
    """Use one accumulator for single bundles and complete collection sets."""
    events = []
    ledger = []
    inventory = []
    total_bytes = 0
    total_lines = 0
    for index, path, entry, environment_id, inventory_path in selected:
        try:
            raw = read_local(path, limit=MAX_FILE_BYTES, stage="evidence")
        except IntakeError as error:
            raise IntakeError(
                error.code,
                stage=error.stage,
                file_index=index,
                field=error.field,
                line=error.line,
            ) from None
        total_bytes += len(raw)
        total_lines += _physical_lines(raw)
        if total_bytes > MAX_TOTAL_EVIDENCE_BYTES or total_lines > MAX_PHYSICAL_LINES:
            raise IntakeError("resource_limit", stage="evidence", file_index=index)
        if sha256(raw).hexdigest() != entry.sha256:
            raise IntakeError("hash_mismatch", stage="evidence", file_index=index)
        try:
            entry_events, entry_ledger = parse_entry(raw, entry, environment_id)
        except IntakeError as error:
            raise IntakeError(
                error.code,
                stage=error.stage,
                file_index=index,
                field=error.field,
                line=error.line,
            ) from None
        if len(events) + len(entry_events) > MAX_EVENTS:
            raise IntakeError("resource_limit", stage="evidence", file_index=index)
        events.extend(entry_events)
        ledger.extend(entry_ledger)
        inventory.append(
            {
                "source_ref": entry.source_ref,
                "path": inventory_path,
                "parser": entry.parser,
                "sha256": entry.sha256,
                "context_fingerprint": _context_fingerprint(entry),
                "display_label": entry.display_label,
                "derived_from": (
                    None
                    if entry.derived_from is None
                    else entry.derived_from.model_dump(mode="json")
                ),
            }
        )
    return IntakeResult(tuple(events), tuple(ledger), tuple(inventory))


def check_collection(
    intake: IntakeResult, profile: EvaluationProfile, context: EvaluationContext
) -> None:
    """Reject unsupported evidence hidden by caller-attested completeness."""
    rules = {rule.assertion_id: rule for rule in profile.rules}
    unsupported_sources = {
        item.source_type for item in intake.ledger if item.reason in _UNSUPPORTED_REASONS
    }
    for declaration in context.declarations:
        rule = rules.get(declaration.assertion_id)
        if rule is None or rule.role != "detection" or rule.capability != "supported":
            raise IntakeError(
                "invalid_collection_declaration", stage="collection", field="declarations"
            )
        if (
            declaration.status == "complete_for_scope"
            and rule.source_type in unsupported_sources
        ):
            raise IntakeError(
                "collection_conflict", stage="collection", field="declarations"
            )
