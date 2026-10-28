"""Verify retained adaptive Wazuh metadata before canonical bundle intake.

Successful leaves cover one half-open query window, but each leaf has its own
Indexer snapshot. Query completion never supplies collection completeness.
"""

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re

from aegis_verify.intake.contracts import BundleManifest, parse_manifest
from aegis_verify.intake.errors import IntakeError
from aegis_verify.intake.io import MAX_CONFIG_BYTES, bundle_path, decode_config, local_path, read_local
from aegis_verify.models import PreciseTimestamp


_DIGEST = re.compile(r"[0-9a-f]{64}")
_LEAF = re.compile(r"attempt-([0-9]{4})")


@dataclass(frozen=True, slots=True)
class CollectionSet:
    members: tuple[tuple[str, BundleManifest], ...]
    environment_id: str
    start: PreciseTimestamp
    end: PreciseTimestamp
    record_count: int
    input_fingerprint: str


def _invalid() -> IntakeError:
    return IntakeError("invalid_input", stage="collection")


def _present(path: Path) -> bool:
    # A dangling link or any other object named INCOMPLETE is still a marker.
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise IntakeError("input_io", stage="collection") from None
    return True


def _timestamp(value) -> PreciseTimestamp:
    try:
        return PreciseTimestamp.parse(value)
    except (ValueError, TypeError, AttributeError):
        raise _invalid() from None


def _count(value, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise _invalid()
    return value


def _digest(value) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise _invalid()
    return value


def _read(root, name, *, expected_hash=None):
    raw = read_local(bundle_path(root, name), limit=MAX_CONFIG_BYTES, stage="collection")
    if expected_hash is not None and sha256(raw).hexdigest() != _digest(expected_hash):
        raise IntakeError("hash_mismatch", stage="collection")
    return decode_config(raw, stage="collection"), raw


def _completed(data):
    if (data.get("schema_version") != "0.1.0"
            or data.get("query_complete") is not True
            or data.get("collection_assurance") != "unknown"
            or data.get("cleanup_failed") is not False):
        raise _invalid()


def read_collection_set(root: Path) -> CollectionSet:
    """Read bounded, hash-checked leaves without trusting generated canonical.json.

    Overflow parent attempts stay diagnostic and are not loaded. Their source
    totals cannot be compared with successful leaves from different snapshots.
    """
    root = local_path(root, directory=True, stage="collection")
    if _present(root / "INCOMPLETE"):
        raise _invalid()
    batch, batch_raw = _read(root, "batch.json")
    _completed(batch)
    leaves = batch.get("collections")
    if type(leaves) is not list or not leaves:
        raise _invalid()
    if len(leaves) > 32:
        raise IntakeError("resource_limit", stage="collection")
    attempts = _count(batch.get("attempts"), 63)
    if attempts < len(leaves) or batch.get("snapshot_scope") != "per-collection":
        raise _invalid()
    record_count = _count(batch.get("record_count"), 3200)
    environment = batch.get("environment_id")
    if type(environment) is not str or not environment.strip():
        raise _invalid()
    if any(type(batch.get(key)) is not str or not batch[key] for key in ("agent_id", "index")):
        raise _invalid()
    start, end = _timestamp(batch.get("start")), _timestamp(batch.get("end"))
    if start >= end:
        raise _invalid()
    fingerprint = sha256(b"aegis-collection-set-v1\0")
    fingerprint.update(len(batch_raw).to_bytes(8, "big"))
    fingerprint.update(batch_raw)
    members, paths, total, boundary = [], set(), 0, start
    for leaf in leaves:
        if type(leaf) is not dict:
            raise _invalid()
        name = leaf.get("path")
        match = _LEAF.fullmatch(name) if type(name) is str else None
        if match is None or not 1 <= int(match[1]) <= attempts or name in paths:
            raise _invalid()
        paths.add(name)
        directory = local_path(root / name, directory=True, stage="collection")
        if _present(directory / "INCOMPLETE") or leaf.get("cleanup_failed") is not False:
            raise _invalid()
        leaf_start, leaf_end = _timestamp(leaf.get("start")), _timestamp(leaf.get("end"))
        if leaf_start != boundary or leaf_start >= leaf_end or leaf_end > end:
            raise _invalid()
        boundary = leaf_end
        count = _count(leaf.get("record_count"), 100)
        collection, _ = _read(directory, "collection.json", expected_hash=_digest(leaf.get("collection_sha256")))
        _completed(collection)
        if (_count(collection.get("record_count"), 100) != count
                or collection.get("end_exclusive") is not True
                or collection.get("timestamp_basis") != "wazuh.timestamp"
                or _timestamp(collection.get("start")) != leaf_start
                or _timestamp(collection.get("end")) != leaf_end
                or any(collection.get(key) != batch[key] for key in ("environment_id", "agent_id", "index"))):
            raise _invalid()
        if count:
            inputs, inputs_raw = _read(directory, "inputs.json", expected_hash=_digest(leaf.get("inputs_sha256")))
            manifest = parse_manifest(inputs)
            if manifest.environment_id != environment:
                raise IntakeError("environment_mismatch", stage="collection", field="environment_id")
            if len(manifest.files) != count:
                raise _invalid()
            # The collector assigns this namespace before canonical parsing.
            if any(entry.source_ref != f"{name}-hit-{number:06d}"
                   for number, entry in enumerate(manifest.files, 1)):
                raise _invalid()
        else:
            if "inputs_sha256" not in leaf or leaf["inputs_sha256"] is not None or _present(directory / "inputs.json"):
                raise _invalid()
            inputs_raw = b""
            manifest = parse_manifest(dict(bundle_schema_version="0.1.0", environment_id=environment, files=[]))
        fingerprint.update(len(inputs_raw).to_bytes(8, "big"))
        fingerprint.update(inputs_raw)
        members.append((name, manifest))
        total += count
    if boundary != end or total != record_count:
        raise _invalid()
    return CollectionSet(tuple(members), environment, start, end, total, fingerprint.hexdigest())
