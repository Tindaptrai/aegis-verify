"""Explicit offline snapshot transport; not a lab attestation."""

from dataclasses import dataclass
from pathlib import Path
import re

from pydantic import ValidationError

from ..connectors.wazuh.manager_snapshot import (
    ManagerSnapshot, ManagerSnapshotScope, ManagerSnapshotError,
    MAX_SNAPSHOTS, MAX_SNAPSHOT_BYTES, MAX_TOTAL_BYTES,
)
from ..intake import IntakeError, decode_config, local_path
from ..intake.io import MAX_CONFIG_BYTES
from ._bundle_io import checked_file, read_file, output_target, write_file, inventory, strict_path
from ._bundle_render import digest, render


@dataclass(frozen=True, slots=True)
class SnapshotFile:
    path: str | Path
    source_label: str
    sha256: str


class SnapshotBundleError(ValueError):
    """Sanitized diagnostic; never includes source bytes, paths or config values."""

    def __init__(self):
        super().__init__('invalid_snapshot_bundle')


_HASH = re.compile(r'[0-9a-f]{64}')
_FAILURES = (IntakeError, ManagerSnapshotError, ValidationError, OSError, ValueError, TypeError)


def _read_sources(snapshots):
    if type(snapshots) is not tuple or len(snapshots) > MAX_SNAPSHOTS:
        raise SnapshotBundleError()
    selected, total, identities = [], 0, set()
    for item in snapshots:
        if (type(item) is not SnapshotFile or type(getattr(item, 'source_label', None)) is not str
                or type(getattr(item, 'sha256', None)) is not str or _HASH.fullmatch(item.sha256) is None
                or not isinstance(getattr(item, 'path', None), (str, Path))):
            raise SnapshotBundleError()
        path = checked_file(item.path)
        info = path.stat()
        identity = (info.st_dev, info.st_ino)
        total += info.st_size
        if identity in identities or info.st_size > MAX_SNAPSHOT_BYTES or total > MAX_TOTAL_BYTES:
            raise SnapshotBundleError()
        identities.add(identity)
        selected.append(item)
    result, consumed = [], 0
    for item in selected:
        raw = read_file(item.path, min(MAX_SNAPSHOT_BYTES, MAX_TOTAL_BYTES - consumed))
        consumed += len(raw)
        if digest(raw) != item.sha256:
            raise SnapshotBundleError()
        result.append(ManagerSnapshot(item.source_label, raw, item.sha256))
    return tuple(result)


def prepare_snapshot_bundle(snapshots, *, scope, profile, context, destination):
    """Create a new unknown transport outside Git. Partial writes are retained."""
    try:
        target = output_target(destination)
        source_bytes = _read_sources(snapshots)
        payload, completion, _ = render(source_bytes, scope, profile, context)
        target.mkdir(mode=0o700)  # Exclusive; no exist_ok or overwrite.
        (target / 'snapshots').mkdir(mode=0o700)
        (target / 'documents').mkdir(mode=0o700)
        for relative, raw in payload.items():
            write_file(target, relative, raw)
        # Re-read all expected payloads before publishing the completion marker.
        if inventory(target) != set(payload):
            raise SnapshotBundleError()
        for relative, raw in payload.items():
            if read_file(target / relative, len(raw)) != raw:
                raise SnapshotBundleError()
        write_file(target, 'snapshot-bundle.json', completion)
        return target
    except _FAILURES:
        raise SnapshotBundleError() from None


def verify_snapshot_bundle(root):
    """Rebuild trace from pinned snapshot copies, not from ledger assertions."""
    try:
        root = local_path(strict_path(root), directory=True)
        completion = read_file(root / 'snapshot-bundle.json', MAX_CONFIG_BYTES)
        manifest = decode_config(completion, stage='inputs')
        if set(manifest) != {'kind', 'version', 'scope', 'snapshots', 'files'}:
            raise SnapshotBundleError()
        if manifest['kind'] != 'snapshot_transport_unknown' or manifest['version'] != '0.1.0':
            raise SnapshotBundleError()
        if type(manifest['scope']) is not dict:
            raise SnapshotBundleError()
        scope = ManagerSnapshotScope(**manifest['scope'])
        descriptors = manifest['snapshots']
        if type(descriptors) is not list or len(descriptors) > MAX_SNAPSHOTS:
            raise SnapshotBundleError()
        sources = []
        for item in descriptors:
            if type(item) is not dict or set(item) != {'source_label', 'sha256', 'path'}:
                raise SnapshotBundleError()
            sha = item['sha256']
            if type(sha) is not str or _HASH.fullmatch(sha) is None or item['path'] != 'snapshots/' + sha + '.jsonl':
                raise SnapshotBundleError()
            sources.append(SnapshotFile(root / item['path'], item['source_label'], sha))
        snapshots = _read_sources(tuple(sources))
        profile = read_file(root / 'profile.json', MAX_CONFIG_BYTES)
        context = read_file(root / 'context.json', MAX_CONFIG_BYTES)
        payload, expected_completion, result = render(snapshots, scope, profile, context)
        if completion != expected_completion or inventory(root) != set(payload) | {'snapshot-bundle.json'}:
            raise SnapshotBundleError()
        for relative, raw in payload.items():
            if read_file(root / relative, len(raw)) != raw:
                raise SnapshotBundleError()
        return result
    except _FAILURES:
        raise SnapshotBundleError() from None
