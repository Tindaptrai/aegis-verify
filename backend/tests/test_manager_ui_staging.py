"""Exercise the public Manager stager as a standalone command, without Django."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/stage_manager_ui.py"


@pytest.fixture
def build(tmp_path):
    root = tmp_path / "dist-manager"
    (root / "assets").mkdir(parents=True)
    (root / "manager.html").write_text('<script type="module" src="/static/manager/assets/manager-test.js"></script><link rel="stylesheet" href="/static/manager/assets/manager-test.css">')
    (root / "assets/manager-test.js").write_text('// synthetic public build')
    (root / "assets/manager-test.css").write_text('body{background:url("/static/manager/assets/logo-test.png")}')
    # Real logo is about 1.49 MB; a smaller budget would break the real build.
    (root / "assets/logo-test.png").write_bytes(b"synthetic-image" * 120_000)
    return root


def stage(build, target):
    return subprocess.run([sys.executable, "-B", str(SCRIPT), "--build-root", str(build),
                           "--static-root", str(target)], capture_output=True, text=True)


def test_stage_copies_only_manager_assets_and_hashes_without_touching_core(build, tmp_path):
    target = tmp_path / "public-static"
    (target / "assets").mkdir(parents=True)
    (target / "assets/core.js").write_text("synthetic dashboard sentinel")
    result = stage(build, target)
    assert result.returncode == 0, result.stderr
    manifest = json.loads((target / "manager/manifest.json").read_text())
    assert manifest["schema_version"] == "1.0"
    assert set(manifest["sha256"]) == {"manager.html", "assets/manager-test.js", "assets/manager-test.css", "assets/logo-test.png"}
    for relative, digest in manifest["sha256"].items():
        assert digest == sha256((build / relative).read_bytes()).hexdigest()
        if relative.startswith("assets/"):
            assert (target / "manager" / relative).read_bytes() == (build / relative).read_bytes()
    assert not (target / "manager/manager.html").exists()
    assert (target / "assets/core.js").read_text() == "synthetic dashboard sentinel"
    assert sorted(path.name for path in (target / "manager").iterdir()) == ["assets", "manifest.json"]
    (target / "manager/assets/stale.js").write_text("synthetic stale")
    assert stage(build, target).returncode == 0
    assert not (target / "manager/assets/stale.js").exists()


@pytest.mark.parametrize("invalid", ["missing", "traversal", "external", "mixed-core", "private", "nested", "oversize"])
def test_invalid_build_fails_before_changing_public_root(build, tmp_path, invalid):
    target = tmp_path / "public-static"
    target.mkdir()
    (target / "sentinel").write_text("unchanged")
    if invalid == "missing":
        (build / "manager.html").unlink()
    elif invalid in ("traversal", "external"):
        ref = "/static/manager/assets/../private.js" if invalid == "traversal" else "https://example.invalid/private.js"
        (build / "manager.html").write_text(f'<script src="{ref}"></script>')
    elif invalid == "mixed-core":
        (build / "index.html").write_text("synthetic dashboard")
    elif invalid == "private":
        (build / "assets/private.env").write_text("synthetic private")
    elif invalid == "nested":
        (build / "assets/nested").mkdir()
    else:
        (build / "assets/oversize.png").write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    result = stage(build, target)
    assert result.returncode != 0
    assert result.stderr.strip() == "manager_ui_unavailable"
    assert str(build) not in result.stderr
    assert [p.name for p in target.iterdir()] == ["sentinel"]


def test_symlink_source_or_destination_cannot_export_private_files(build, tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    (private / "secret.txt").write_text("synthetic private sentinel")
    link = build / "assets/symlink.js"
    try:
        link.symlink_to(private / "secret.txt")
    except OSError:
        pytest.skip("Platform does not permit synthetic symlink creation")
    target = tmp_path / "public-static"
    assert stage(build, target).returncode != 0
    assert not target.exists()
    link.unlink()
    target.mkdir()
    (target / "manager").symlink_to(private, target_is_directory=True)
    assert stage(build, target).returncode != 0
    assert (private / "secret.txt").read_text() == "synthetic private sentinel"
    assert list(private.iterdir()) == [private / "secret.txt"]


def test_unowned_destination_and_overlapping_source_are_rejected(build, tmp_path):
    target = tmp_path / "public-static"
    (target / "manager").mkdir(parents=True)
    (target / "manager/private.txt").write_text("synthetic private sentinel")
    assert stage(build, target).returncode != 0
    assert (target / "manager/private.txt").read_text() == "synthetic private sentinel"
    assert stage(build, build).returncode != 0
    assert (build / "manager.html").is_file()


def test_duplicate_reference_cannot_hide_private_target(build, tmp_path):
    (build / "manager.html").write_text('<script src="/private/secret.js" src="/static/manager/assets/manager-test.js"></script>')
    target = tmp_path / "public-static"
    result = stage(build, target)
    assert result.returncode != 0
    assert result.stderr.strip() == "manager_ui_unavailable"
    assert not target.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction boundary")
def test_junction_source_assets_and_destination_cannot_redirect(build, tmp_path):
    from _winapi import CreateJunction

    original = build / "assets"
    outside = tmp_path / "outside-assets"
    original.rename(outside)
    CreateJunction(str(outside), str(original))
    target = tmp_path / "public-static"
    try:
        assert stage(build, target).returncode != 0
        assert not target.exists()
    finally:
        original.rmdir()
        outside.rename(original)
    private = tmp_path / "private-destination"
    private.mkdir()
    (private / "secret.txt").write_text("synthetic private sentinel")
    target.mkdir()
    CreateJunction(str(private), str(target / "manager"))
    try:
        assert stage(build, target).returncode != 0
        assert list(private.iterdir()) == [private / "secret.txt"]
    finally:
        (target / "manager").rmdir()
