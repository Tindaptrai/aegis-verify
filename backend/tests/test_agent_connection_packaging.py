"""Public release boundaries exercised through the standalone package CLI."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/stage_agent_connection.py"
COMMIT = "1234567890abcdef1234567890abcdef12345678"


@pytest.fixture(params=["win-x64", "linux-x64"])
def package_input(request, tmp_path):
    source, build = tmp_path / "source", tmp_path / "build"
    source.mkdir()
    build.mkdir()
    names = json.loads((ROOT / "scripts/agent_connection_runtime_files.json").read_text(encoding="utf-8-sig"))["files"][request.param]
    for name in names:
        (build / name).write_bytes(b"synthetic public binary")
    (build / "aegis-agent.runtimeconfig.json").write_text(json.dumps({"runtimeOptions": {
        "tfm": "net10.0", "includedFrameworks": [{"name": "Microsoft.NETCore.App", "version": "10.0.13"}]}}))
    platform = "windows" if request.param == "win-x64" else "linux"
    scripts = ["Install-Agent.ps1", "Uninstall-Agent.ps1"] if platform == "windows" else ["install.sh", "uninstall.sh", "aegis-agent.service"]
    deploy = source / "deploy/agent" / platform
    deploy.mkdir(parents=True)
    for name in scripts:
        (deploy / name).write_text("# synthetic public installer\n")
    guide = source / "docs/manager/AGENT_CONNECTION_RUNBOOK.md"
    guide.parent.mkdir(parents=True)
    guide.write_text("Synthetic public guide\n")
    return source, build, request.param, scripts


def stage(data, output, *extra):
    source, build, rid, _ = data
    return subprocess.run([sys.executable, "-B", str(SCRIPT), "--source-root", str(source),
        "--build-root", str(build), "--output-root", str(output), "--runtime", rid,
        "--version", "0.1.0", "--commit", COMMIT, *extra], capture_output=True, text=True)


def archive_payload(path):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            return {name: archive.read(name) for name in archive.namelist()}
    with tarfile.open(path) as archive:
        return {entry.name: archive.extractfile(entry).read() for entry in archive if entry.isfile()}


def test_public_packages_have_stable_hashes_layout_metadata_and_no_private_source(package_input, tmp_path):
    source, build, rid, scripts = package_input
    (source / "real-private.env").write_text("DO NOT EXPORT synthetic private")
    output = tmp_path / "output"
    result = stage(package_input, output)
    assert result.returncode == 0, result.stderr
    extension = ".zip" if rid == "win-x64" else ".tar.gz"
    archive = output / ("AEGIS-Agent-Connection-0.1.0-" + rid + extension)
    data = archive_payload(archive)
    assert set(name for name in data if not name.startswith("bin/")) == {*scripts, "AGENT_CONNECTION_RUNBOOK.md", "version.json", "SHA256SUMS.txt"}
    metadata = json.loads(data["version.json"])
    assert metadata == {"schema_version": "1.0", "version": "0.1.0", "source_commit": COMMIT,
                        "runtime": rid, "dotnet_runtime": "10.0.13"}
    lines = data["SHA256SUMS.txt"].decode().splitlines()
    assert lines == sorted(lines, key=lambda line: line[66:])
    hashes = {line[66:]: line[:64] for line in lines}
    assert set(hashes) == set(data) - {"SHA256SUMS.txt"}
    assert all(sha256(data[name]).hexdigest() == digest for name, digest in hashes.items())
    assert (output / (archive.name + ".sha256")).read_text() == sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n"
    other = tmp_path / "other"
    assert stage(package_input, other).returncode == 0
    assert (other / archive.name).read_bytes() == archive.read_bytes()
    assert stage(package_input, output).returncode != 0
    assert not any(b"DO NOT EXPORT" in content for content in data.values())


@pytest.mark.parametrize("bad", ["missing", "private", "unknown-dll", "directory", "runtime", "source-script", "overlap", "version-traversal", "commit"])
def test_malformed_or_private_input_is_rejected_before_output(package_input, tmp_path, bad):
    source, build, rid, scripts = package_input
    output, extra = tmp_path / "output", []
    if bad == "missing":
        (build / ("aegis-agent.exe" if rid == "win-x64" else "aegis-agent")).unlink()
    elif bad == "private":
        (build / "state.json").write_text("synthetic secret")
    elif bad == "unknown-dll":
        (build / "System.Private.Secret.dll").write_text("synthetic secret")
    elif bad == "directory":
        (build / "private").mkdir()
    elif bad == "runtime":
        (build / "aegis-agent.runtimeconfig.json").write_text('{"runtimeOptions":{"includedFrameworks":[{"name":"Microsoft.NETCore.App","version":"10.0.12"}]}}')
    elif bad == "source-script":
        (source / "deploy/agent" / ("windows" if rid == "win-x64" else "linux") / scripts[0]).unlink()
    elif bad == "overlap":
        output = build / "output"
    elif bad == "version-traversal":
        extra = ["--version", "../private"]
    else:
        extra = ["--commit", "not-a-commit"]
    result = stage(package_input, output, *extra)
    assert result.returncode != 0
    assert not output.exists()


def test_source_build_output_links_and_hardlinks_cannot_export_private_bytes(package_input, tmp_path):
    source, build, rid, _ = package_input
    private = tmp_path / "private"
    private.write_bytes(b"synthetic private")
    name = "aegis-agent.dll"
    (build / name).unlink()
    (build / name).hardlink_to(private)
    assert stage(package_input, tmp_path / "hardlink-output").returncode != 0
    (build / name).unlink()
    try:
        (build / name).symlink_to(private)
    except OSError:
        pytest.skip("Symlink creation privilege unavailable; native POSIX gate exercises links")
    assert stage(package_input, tmp_path / "symlink-output").returncode != 0


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junction boundary")
def test_junction_build_and_output_are_rejected(package_input, tmp_path):
    from _winapi import CreateJunction
    source, build, rid, scripts = package_input
    alias = tmp_path / "alias"
    CreateJunction(str(build), str(alias))
    try:
        assert stage((source, alias, rid, scripts), tmp_path / "output").returncode != 0
    finally:
        alias.rmdir()
    output = tmp_path / "public-output"
    CreateJunction(str(build), str(output))
    try:
        assert stage(package_input, output).returncode != 0
    finally:
        output.rmdir()
