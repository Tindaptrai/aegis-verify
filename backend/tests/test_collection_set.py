"""Synthetic collection sets share intake bounds and one canonical evaluation."""

from hashlib import sha256
import json
from pathlib import Path
import shutil

import pytest

from aegis_verify.cli import service
from aegis_verify.intake import IntakeError, parse_manifest
from aegis_verify.intake import loader


FIXTURE = Path(__file__).resolve().parents[2] / "tests/fixtures/cli/synthetic-detected"
START = "2026-01-01T00:00:00Z"
MID = "2026-01-01T00:00:01.500000000Z"
END = "2026-01-01T00:01:00Z"


def _write(path, data):
    raw = json.dumps(data, sort_keys=True).encode()
    path.write_bytes(raw)
    return sha256(raw).hexdigest()


def _batch(root, *, empty=False, missing_alert=False):
    """Keep the synthetic telemetry and detection in different leaf windows."""
    source_manifest = json.loads((FIXTURE / "inputs.json").read_text())
    for name in ("scenario.yaml", "profile.json", "context.json"):
        shutil.copyfile(FIXTURE / name, root / name)
    leaves, members = [], []
    for number, (start, end) in enumerate(((START, MID), (MID, END)), 1):
        name = f"attempt-{number:04d}"
        directory = root / name
        directory.mkdir()
        files = []
        if not empty and not (missing_alert and number == 2):
            entry = dict(source_manifest["files"][number - 1])
            shutil.copyfile(FIXTURE / entry["path"], directory / entry["path"])
            entry["source_ref"] = name + "-hit-000001"
            files.append(entry)
        manifest = dict(bundle_schema_version="0.1.0", environment_id="synthetic-lab", files=files)
        inputs_hash = _write(directory / "inputs.json", manifest) if files else None
        collection = dict(schema_version="0.1.0", environment_id="synthetic-lab",
                          start=start, end=end, agent_id="901", index="synthetic-index",
                          record_count=len(files), query_complete=True, collection_assurance="unknown",
                          cleanup_failed=False, timestamp_basis="wazuh.timestamp", end_exclusive=True,
                          profiles=["wazuh-win4688-v2"], responses=[], derivations=[])
        collection_hash = _write(directory / "collection.json", collection)
        leaves.append(dict(path=name, start=start, end=end, record_count=len(files),
                           cleanup_failed=False, collection_sha256=collection_hash,
                           inputs_sha256=inputs_hash))
        members.append((name, parse_manifest(manifest)))
    batch = dict(schema_version="0.1.0", environment_id="synthetic-lab", start=START, end=END,
                 agent_id="901", index="synthetic-index", collections=leaves, attempts=2,
                 record_count=sum(leaf["record_count"] for leaf in leaves), query_complete=True,
                 collection_assurance="unknown", snapshot_scope="per-collection", cleanup_failed=False)
    _write(root / "batch.json", batch)
    return batch, tuple(members)


def _load(root, members):
    load = getattr(loader, "load_bundle_set", None)
    assert callable(load), "collection-set intake is required"
    return load(root, members)


def _evaluate(root):
    evaluate = getattr(service, "evaluate_collection_set", None)
    assert callable(evaluate), "collection-set evaluation is required"
    return evaluate(root / "scenario.yaml", root)


def test_set_intake_qualifies_paths_without_rewriting_evidence_refs(tmp_path):
    _, members = _batch(tmp_path)
    result = _load(tmp_path, members)
    assert len(result.events) == 2
    assert [item["path"] for item in result.inventory] == [
        "attempt-0001/activity.json", "attempt-0002/alert.json"]
    assert [event.raw_event_ref for event in result.events] == [
        "attempt-0001-hit-000001#record=1", "attempt-0002-hit-000001#record=1"]


@pytest.mark.parametrize("limit", ["MAX_TOTAL_EVIDENCE_BYTES", "MAX_PHYSICAL_LINES", "MAX_EVENTS"])
def test_set_intake_enforces_budgets_across_leaves(tmp_path, monkeypatch, limit):
    _, members = _batch(tmp_path)
    actual = (sum((tmp_path / name / manifest.files[0].path).stat().st_size for name, manifest in members)
              if limit == "MAX_TOTAL_EVIDENCE_BYTES" else 2)
    monkeypatch.setattr(loader, limit, actual - 1)
    with pytest.raises(IntakeError) as caught:
        _load(tmp_path, members)
    assert caught.value.code == "resource_limit"


def test_set_intake_rejects_duplicate_source_refs_across_leaves(tmp_path):
    _, members = _batch(tmp_path)
    changed = members[1][1].model_dump(mode="json")
    changed["files"][0]["source_ref"] = members[0][1].files[0].source_ref
    members = (members[0], (members[1][0], parse_manifest(changed)))
    with pytest.raises(IntakeError) as caught:
        _load(tmp_path, members)
    assert caught.value.code == "duplicate_source_ref"


def test_set_intake_rejects_physical_file_aliases_across_leaves(tmp_path):
    _, members = _batch(tmp_path)
    first = tmp_path / members[0][0] / members[0][1].files[0].path
    second = tmp_path / members[1][0] / members[1][1].files[0].path
    second.unlink()
    second.hardlink_to(first)
    with pytest.raises(IntakeError) as caught:
        _load(tmp_path, members)
    assert caught.value.code == "duplicate_file"


def test_set_evaluation_joins_witnesses_across_leaves_once_with_unknown_assurance(tmp_path):
    _batch(tmp_path)
    report = _evaluate(tmp_path)
    assert report["counts"]["parsed"] == 2
    assert report["evaluation"]["final_status"] == "Detected"
    detection = report["evaluation"]["assertions"][1]
    assert len(detection["witness_pairs"]) == 1
    assert len(detection["evidence_ids"]) == 2
    assert detection["collection_assurance"] == "unknown"
    assert report["comparison_inputs"]["context"]["declarations"] == []
    assert [item["source_ref"] for item in report["timeline"]["events"]] == [
        "attempt-0001-hit-000001", "attempt-0002-hit-000001"]


def test_missing_alert_and_empty_leaf_do_not_attest_completeness(tmp_path):
    _batch(tmp_path, missing_alert=True)
    report = _evaluate(tmp_path)
    assert report["counts"]["parsed"] == 1
    detection = report["evaluation"]["assertions"][1]
    assert detection["outcome"] == "inconclusive"
    assert detection["collection_assurance"] == "unknown"


def test_all_empty_leaves_are_valid_scope_metadata(tmp_path):
    _batch(tmp_path, empty=True)
    report = _evaluate(tmp_path)
    assert report["counts"]["parsed"] == 0
    assert report["intake"] == {"inventory": [], "ledger": []}


@pytest.mark.parametrize("target", ["batch", "leaf"])
def test_set_evaluation_rejects_incomplete_markers(tmp_path, target):
    _batch(tmp_path)
    directory = tmp_path if target == "batch" else tmp_path / "attempt-0002"
    (directory / "INCOMPLETE").write_text("incomplete")
    with pytest.raises(IntakeError) as caught:
        _evaluate(tmp_path)
    assert caught.value.stage == "collection"


@pytest.mark.parametrize("filename", ["inputs.json", "collection.json", "alert.json"])
def test_set_evaluation_rejects_changed_leaf_bytes(tmp_path, filename):
    _batch(tmp_path)
    path = tmp_path / "attempt-0002" / filename
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(IntakeError) as caught:
        _evaluate(tmp_path)
    assert caught.value.code == "hash_mismatch"


@pytest.mark.parametrize("filename", ["inputs.json", "collection.json", "alert.json"])
def test_set_evaluation_rejects_missing_leaf_files(tmp_path, filename):
    _batch(tmp_path)
    (tmp_path / "attempt-0002" / filename).unlink()
    with pytest.raises(IntakeError):
        _evaluate(tmp_path)


@pytest.mark.parametrize("field,value", [
    ("attempts", 64), ("attempts", True), ("attempts", 1), ("record_count", 99),
    ("cleanup_failed", True), ("query_complete", False),
    ("collection_assurance", "complete_for_scope"), ("snapshot_scope", "global"),
    ("environment_id", "other-lab"), ("end", "2026-01-01T00:02:00Z"),
])
def test_set_evaluation_rejects_invalid_batch_metadata(tmp_path, field, value):
    batch, _ = _batch(tmp_path)
    batch[field] = value
    _write(tmp_path / "batch.json", batch)
    with pytest.raises(IntakeError):
        _evaluate(tmp_path)


@pytest.mark.parametrize("start", ["2026-01-01T00:00:01Z", "2026-01-01T00:00:02Z"])
def test_set_evaluation_rejects_overlapping_or_gapped_windows(tmp_path, start):
    batch, _ = _batch(tmp_path)
    batch["collections"][1]["start"] = start
    path = tmp_path / "attempt-0002/collection.json"
    collection = json.loads(path.read_text())
    collection["start"] = start
    batch["collections"][1]["collection_sha256"] = _write(path, collection)
    _write(tmp_path / "batch.json", batch)
    with pytest.raises(IntakeError):
        _evaluate(tmp_path)


@pytest.mark.parametrize("field,value", [
    ("record_count", 101), ("record_count", 0), ("cleanup_failed", True),
    ("query_complete", False), ("collection_assurance", "complete_for_scope"),
    ("environment_id", "other-lab"), ("agent_id", "other-agent"),
    ("index", "other-index"), ("end_exclusive", False),
    ("timestamp_basis", "receipt-time"),
])
def test_set_evaluation_rejects_invalid_collection_metadata(tmp_path, field, value):
    batch, _ = _batch(tmp_path)
    path = tmp_path / "attempt-0002/collection.json"
    collection = json.loads(path.read_text())
    collection[field] = value
    batch["collections"][1]["collection_sha256"] = _write(path, collection)
    _write(tmp_path / "batch.json", batch)
    with pytest.raises(IntakeError):
        _evaluate(tmp_path)


def test_set_input_fingerprint_binds_batch_and_ordered_manifest_bytes(tmp_path):
    batch, _ = _batch(tmp_path)
    original = _evaluate(tmp_path)["input_fingerprints"]["inputs"]
    batch["attempts"] = 3  # A failed overflow parent is diagnostic, not a record-count constraint.
    _write(tmp_path / "batch.json", batch)
    changed_batch = _evaluate(tmp_path)["input_fingerprints"]["inputs"]
    assert changed_batch != original
    path = tmp_path / "attempt-0002/inputs.json"
    path.write_bytes(path.read_bytes() + b"\n")
    batch["collections"][1]["inputs_sha256"] = sha256(path.read_bytes()).hexdigest()
    _write(tmp_path / "batch.json", batch)
    assert _evaluate(tmp_path)["input_fingerprints"]["inputs"] != changed_batch


def test_set_metadata_rejects_duplicate_leaf_entries(tmp_path):
    batch, _ = _batch(tmp_path)
    batch["collections"][1] = batch["collections"][0]
    _write(tmp_path / "batch.json", batch)
    with pytest.raises(IntakeError):
        _evaluate(tmp_path)


def test_set_metadata_rejects_more_than_32_leaves(tmp_path):
    batch, _ = _batch(tmp_path)
    batch["collections"] = batch["collections"] * 17
    batch["attempts"] = 63
    _write(tmp_path / "batch.json", batch)
    with pytest.raises(IntakeError) as caught:
        _evaluate(tmp_path)
    assert caught.value.code == "resource_limit"


def test_empty_leaf_rejects_unexpected_inputs_manifest(tmp_path):
    _batch(tmp_path, empty=True)
    _write(tmp_path / "attempt-0001/inputs.json", dict(
        bundle_schema_version="0.1.0", environment_id="synthetic-lab", files=[]))
    with pytest.raises(IntakeError):
        _evaluate(tmp_path)


def test_set_intake_rejects_different_environments(tmp_path):
    _, members = _batch(tmp_path)
    changed = members[1][1].model_dump(mode="json")
    changed["environment_id"] = "other-lab"
    members = (members[0], (members[1][0], parse_manifest(changed)))
    with pytest.raises(IntakeError) as caught:
        _load(tmp_path, members)
    assert caught.value.code == "environment_mismatch"


@pytest.mark.parametrize("relative", ["../attempt-0002", "C:/elsewhere", "attempt-0002/../attempt-0002"])
def test_set_intake_rejects_unsafe_leaf_paths(tmp_path, relative):
    _, members = _batch(tmp_path)
    with pytest.raises(IntakeError) as caught:
        _load(tmp_path, (members[0], (relative, members[1][1])))
    assert caught.value.code == "invalid_path"
