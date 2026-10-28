"""Public release boundaries exercised through the standalone package CLI."""
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/stage_agent_connection.py"
COMMIT = "1234567890abcdef1234567890abcdef12345678"
NOTICE_HASHES = {
    "win-x64": {
        "LICENSE.TXT": "d7a68596ab69b06f51ca278a6545148e4269a9381c26d597c13df5d88e08cf5b",
        "THIRD-PARTY-NOTICES.TXT": "6d15e10a101c6bfff2ab4429ed061bf76c456fc4b23ad6b03e0d0f8377148a21",
    },
    "linux-x64": {
        "LICENSE.TXT": "cfc21f5e8bd655ae997eec916138b707b1d290b83272c02a95c9f821b8c87310",
        "THIRD-PARTY-NOTICES.TXT": "66f1d4e44973185519bb4aa8a9718eb22fc7af2cc532e3ae9cfc4c127ee7fc54",
    },
}


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
    (build / "aegis-agent.deps.json").write_text(json.dumps({"libraries": {"aegis-agent/0.2.0": {"type": "project"}}}))
    platform = "windows" if request.param == "win-x64" else "linux"
    scripts = ["Install-Agent.ps1", "Uninstall-Agent.ps1"] if platform == "windows" else ["install.sh", "uninstall.sh", "aegis-agent.service"]
    deploy = source / "deploy/agent" / platform
    deploy.mkdir(parents=True)
    for name in scripts:
        (deploy / name).write_text("# synthetic public installer\n")
    guide = source / "docs/manager/AGENT_CONNECTION_RUNBOOK.md"
    guide.parent.mkdir(parents=True)
    guide.write_text("Synthetic public guide\n")
    notices = source / "deploy/agent/runtime-notices" / request.param
    notices.mkdir(parents=True)
    for name in NOTICE_HASHES[request.param]:
        (notices / name).write_bytes((ROOT / "deploy/agent/runtime-notices" / request.param / name).read_bytes())
    return source, build, request.param, scripts


def stage(data, output, *extra):
    source, build, rid, _ = data
    return subprocess.run([sys.executable, "-B", str(SCRIPT), "--source-root", str(source),
        "--build-root", str(build), "--output-root", str(output), "--runtime", rid,
        "--version", "0.2.0", "--commit", COMMIT, *extra], capture_output=True, text=True)


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
    archive = output / ("AEGIS-Agent-Connection-0.2.0-" + rid + extension)
    data = archive_payload(archive)
    assert set(name for name in data if not name.startswith("bin/")) == {*scripts, "AGENT_CONNECTION_RUNBOOK.md", "version.json", "SHA256SUMS.txt"}
    metadata = json.loads(data["version.json"])
    assert metadata == {"schema_version": "1.0", "version": "0.2.0", "source_commit": COMMIT,
                        "runtime": rid, "dotnet_runtime": "10.0.13"}
    lines = data["SHA256SUMS.txt"].decode().splitlines()
    assert lines == sorted(lines, key=lambda line: line[66:])
    hashes = {line[66:]: line[:64] for line in lines}
    assert set(hashes) == set(data) - {"SHA256SUMS.txt"}
    assert all(sha256(data[name]).hexdigest() == digest for name, digest in hashes.items())
    for name, digest in NOTICE_HASHES[rid].items():
        assert sha256(data["bin/" + name]).hexdigest() == digest
        assert hashes["bin/" + name] == digest
    provenance = json.loads(data["bin/DOTNET-RUNTIME-NOTICES.json"])
    package = "microsoft.netcore.app.runtime." + rid
    assert provenance == {
        "package": package, "version": "10.0.13", "runtime": rid,
        "source": "https://api.nuget.org/v3-flatcontainer/" + package + "/10.0.13/" + package + ".10.0.13.nupkg",
        "files": NOTICE_HASHES[rid],
    }
    assert (output / (archive.name + ".sha256")).read_text() == sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n"
    other = tmp_path / "other"
    assert stage(package_input, other).returncode == 0
    assert (other / archive.name).read_bytes() == archive.read_bytes()
    assert stage(package_input, output).returncode != 0
    assert not any(b"DO NOT EXPORT" in content for content in data.values())


@pytest.mark.parametrize("bad", ["missing-license", "missing-third-party", "changed", "other-rid", "private", "hardlink"])
def test_runtime_notices_fail_closed_before_output(package_input, tmp_path, bad):
    source, _, rid, _ = package_input
    directory = source / "deploy/agent/runtime-notices" / rid
    license_file = directory / "LICENSE.TXT"
    if bad.startswith("missing-"):
        (license_file if bad == "missing-license" else directory / "THIRD-PARTY-NOTICES.TXT").unlink()
    elif bad == "changed":
        license_file.write_bytes(license_file.read_bytes() + b"changed")
    elif bad == "other-rid":
        other = "linux-x64" if rid == "win-x64" else "win-x64"
        license_file.write_bytes((ROOT / "deploy/agent/runtime-notices" / other / "LICENSE.TXT").read_bytes())
    elif bad == "private":
        (directory / "state.json").write_text("DO NOT EXPORT synthetic private")
    else:
        copy = tmp_path / "notice-copy"
        copy.write_bytes(license_file.read_bytes())
        license_file.unlink()
        license_file.hardlink_to(copy)
    output = tmp_path / "output"
    result = stage(package_input, output)
    assert result.returncode != 0
    assert result.stderr.strip() == "agent_package_invalid"
    assert not output.exists()


def test_windows_public_guide_scopes_each_script_to_reviewed_child_process():
    """Static public-command contract; intentionally does not execute a policy probe."""
    guide = (ROOT / "docs/manager/AGENT_CONNECTION_RUNBOOK.md").read_text(encoding="utf-8-sig")
    blocks = re.findall(r"```powershell\n(.*?)```", guide, flags=re.S)
    commands = [line for block in blocks for line in block.splitlines() if re.search(r"\.\\(?:Install|Uninstall)-Agent\.ps1", line)]
    assert len(commands) == 4  # install, upgrade, uninstall, replacement recovery
    assert all(re.search(r"powershell\.exe.*-NoProfile -ExecutionPolicy Bypass -File \.\\(?:Install|Uninstall)-Agent\.ps1", line) for line in commands)
    assert guide.index("Get-FileHash") < guide.index("-ExecutionPolicy Bypass")
    assert guide.index("Get-ExecutionPolicy -List") < guide.index("-ExecutionPolicy Bypass")
    assert all(term in guide for term in ("Restricted", "RemoteSigned", "Internet", "Group Policy", "MachinePolicy", "UserPolicy"))
    assert "Set-ExecutionPolicy" not in guide


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


def test_package_version_must_match_published_binary(package_input, tmp_path):
    result = stage(package_input, tmp_path / "output", "--version", "0.1.0")
    assert result.returncode != 0
    assert result.stderr.strip() == "agent_package_invalid"
    assert not (tmp_path / "output").exists()


def test_native_workflow_stages_current_connection_version():
    import xml.etree.ElementTree as ET
    project = ET.parse(ROOT / "agent/connection/Aegis.Connection/Aegis.Connection.csproj")
    version = project.findtext(".//Version")
    workflow = (ROOT / ".github/workflows/agent-connection.yml").read_text()
    assert "--version " + version + " --commit" in workflow
    for rid, extension in (("win-x64", ".zip"), ("linux-x64", ".tar.gz")):
        assert "AEGIS-Agent-Connection-" + version + "-" + rid + extension in workflow


@pytest.mark.parametrize("metadata", [[], {"libraries": []}, {"libraries": {}},
    {"libraries": {"aegis-agent/0.1.0": {}}},
    {"libraries": {"aegis-agent/0.1.0": {}, "aegis-agent/0.2.0": {}}}])
def test_invalid_application_metadata_is_rejected(package_input, tmp_path, metadata):
    _, build, _, _ = package_input
    (build / "aegis-agent.deps.json").write_text(json.dumps(metadata))
    result = stage(package_input, tmp_path / "output")
    assert result.returncode != 0
    assert result.stderr.strip() == "agent_package_invalid"
    assert not (tmp_path / "output").exists()
