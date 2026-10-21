"""The wheel resource stage must ship public inputs and a working UI only."""

from hashlib import sha256
import json
from pathlib import Path
import runpy
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[2]


def stage(root, target):
    return runpy.run_path(str(ROOT / "scripts/stage_release_resources.py"))["stage_resources"](root, target)


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "release source"
    manifest = ROOT / "packaging/public-resources.json"
    files = json.loads(manifest.read_bytes())
    # The notice is an available source input even before the package selection
    # includes it; the retention assertion below catches a missing allowlist item.
    for source_name in set(files.values()) | {"frontend/THIRD_PARTY_NOTICES.txt"}:
        target = root / source_name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / source_name, target)
    (root / "packaging").mkdir(exist_ok=True)
    shutil.copyfile(manifest, root / "packaging/public-resources.json")
    static = root / "frontend/dist"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text('<script src="/assets/index-demo.js"></script><link href="/assets/index-demo.css">')
    (static / "assets/index-demo.js").write_text("console.log('public UI');")
    (static / "assets/index-demo.css").write_text("body { color: black }")
    return root


def test_resource_stage_copies_exact_bytes_and_excludes_unlisted_files(source, tmp_path):
    # An accidental file in an approved directory must not become a release input.
    (source / "tests/fixtures/cli/scn005-elastic-synthetic/private.txt").write_text("DO-NOT-SHIP")
    (source / "frontend/dist/unreferenced-debug.json").write_text("DO-NOT-SHIP")
    target = tmp_path / "installed data"
    stage(source, target)
    assert len(list((target / "scenarios").glob("SCN-*.yaml"))) == 6
    assert (target / "static/assets/index-demo.js").is_file()
    assert (target / "licenses/frontend.txt").read_bytes() == (
        ROOT / "frontend/THIRD_PARTY_NOTICES.txt").read_bytes()
    assert not list(target.rglob("private.txt"))
    assert not list(target.rglob("unreferenced-debug.json"))
    assert (target / "fixtures/scn006-elastic-synthetic/filterlog.log").read_bytes() == (
        ROOT / "tests/fixtures/cli/scn006-elastic-synthetic/filterlog.log").read_bytes()
    bundle = json.loads((target / "bundle.json").read_bytes())
    assert bundle["schema_version"] == "1.0"
    for name, expected_hash in bundle["sha256"].items():
        assert sha256((target / name).read_bytes()).hexdigest() == expected_hash


def test_resource_stage_fails_when_fresh_frontend_is_missing(source, tmp_path):
    shutil.rmtree(source / "frontend/dist")
    with pytest.raises(ValueError, match="frontend"):
        stage(source, tmp_path / "target")


def test_resource_stage_rejects_asset_escape(source, tmp_path):
    (source / "frontend/dist/index.html").write_text('<script src="/assets/../../private.js"></script>')
    with pytest.raises(ValueError, match="asset"):
        stage(source, tmp_path / "target")


def test_resource_stage_removes_stale_build_data(source, tmp_path):
    target = tmp_path / "data"
    stage(source, target)
    (target / "stale-secret.txt").write_text("DO-NOT-SHIP")
    stage(source, target)
    assert not (target / "stale-secret.txt").exists()
