"""Public release boundaries exercised through the standalone package CLI."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
from types import SimpleNamespace
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/stage_agent_connection.py"
CANONICAL_SCENARIO = b'# Draft manifest. Issue #2 will formalize and validate the scenario schema.\nid: SCN-001\nname: PowerShell Execution\nversion: 0.1.0\nstatus: draft\ndescription: >-\n  Execute an approved, non-destructive PowerShell test script and verify that\n  endpoint telemetry and the expected Wazuh detection are present.\nsafety:\n  destructive: false\n  authorization_required: true\n  notes: Run only in the approved lab with a reviewed test payload.\nexpected_sources:\n  - sysmon\n  - powershell\n  - wazuh\nexpected_outcome: detected\nassertions:\n  - id: SCN-001-A01\n    description: PowerShell process execution telemetry exists.\n    source: sysmon\n  - id: SCN-001-A02\n    description: PowerShell script or command telemetry exists.\n    source: powershell\n  - id: SCN-001-A03\n    description: Wazuh detection references the execution evidence.\n    source: wazuh\ntags:\n  - regression-demo\n  - gap-fix-retest\n'
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
    (build / "aegis-agent.deps.json").write_text(json.dumps({"libraries": {"aegis-agent/0.3.0": {"type": "project"}}}))
    platform = "windows" if request.param == "win-x64" else "linux"
    scripts = ["Install-Agent.ps1", "Uninstall-Agent.ps1", "Enable-Execution.ps1"] if platform == "windows" else ["install.sh", "uninstall.sh", "aegis-agent.service"]
    deploy = source / "deploy/agent" / platform
    deploy.mkdir(parents=True)
    for name in scripts:
        (deploy / name).write_text("# synthetic public installer\n")
    guide = source / "docs/manager/AGENT_CONNECTION_RUNBOOK.md"
    guide.parent.mkdir(parents=True)
    guide.write_text("Synthetic public guide\n")
    (source / "canonical-scenario.yaml").write_bytes(CANONICAL_SCENARIO)
    (guide.parent / "windows-web-execution.md").write_text("Synthetic public execution guide\n")
    notices = source / "deploy/agent/runtime-notices" / request.param
    notices.mkdir(parents=True)
    for name in NOTICE_HASHES[request.param]:
        (notices / name).write_bytes((ROOT / "deploy/agent/runtime-notices" / request.param / name).read_bytes())
    return source, build, request.param, scripts


def stage(data, output, *extra, canonical=True):
    source, build, rid, _ = data
    canonical = ["--canonical-scenario", str(source / "canonical-scenario.yaml")] if rid == "win-x64" and canonical else []
    return subprocess.run([sys.executable, "-B", str(SCRIPT), "--source-root", str(source),
        "--build-root", str(build), "--output-root", str(output), "--runtime", rid,
        "--version", "0.3.0", "--commit", COMMIT, *canonical, *extra], capture_output=True, text=True)


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
    archive = output / ("AEGIS-Agent-Connection-0.3.0-" + rid + extension)
    data = archive_payload(archive)
    expected = {*scripts, "AGENT_CONNECTION_RUNBOOK.md", "version.json", "SHA256SUMS.txt"}
    if rid == "win-x64":
        expected |= {"WINDOWS_WEB_EXECUTION.md", "execution/SCN-001-powershell-execution.yaml"}
        assert data["execution/SCN-001-powershell-execution.yaml"] == CANONICAL_SCENARIO
    assert set(name for name in data if not name.startswith("bin/")) == expected
    assert all(name not in data for name in ("profile.json", "installed-grant.json", "manager-execution-v2-public.pem", "state.json", "kit.json", "study.json"))
    if rid == "linux-x64":
        assert not any(name.startswith("execution/") or name == "Enable-Execution.ps1" for name in data)
    metadata = json.loads(data["version.json"])
    assert metadata == {"schema_version": "1.0", "version": "0.3.0", "source_commit": COMMIT,
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


def test_windows_public_guide_uses_reviewed_file_without_policy_override():
    guide = (ROOT / "docs/manager/AGENT_CONNECTION_RUNBOOK.md").read_text(encoding="utf-8-sig")
    blocks = re.findall(r"```powershell\n(.*?)```", guide, flags=re.S)
    commands = [line for block in blocks for line in block.splitlines() if re.search(r"\.\\(?:Install|Uninstall)-Agent\.ps1", line)]
    assert len(commands) == 4
    assert all(re.search(r"powershell\.exe.*-NoLogo -NoProfile -NonInteractive -File \.\\(?:Install|Uninstall)-Agent\.ps1", line) for line in commands)
    assert guide.index("Get-FileHash") < guide.index("-NoLogo")
    assert guide.index("Get-ExecutionPolicy -List") < guide.index("-NoLogo")
    assert all(term in guide for term in ("Restricted", "RemoteSigned", "Internet", "Group Policy", "MachinePolicy", "UserPolicy"))
    assert all(term not in guide for term in (" -ExecutionPolicy", "Set-ExecutionPolicy", "Unblock-File"))


@pytest.mark.parametrize("bad", ["missing", "crlf", "tampered", "empty", "hardlink"])
def test_canonical_scenario_asset_rejects_unreviewed_bytes_before_output(package_input, tmp_path, bad):
    source, _, rid, _ = package_input
    if rid != "win-x64":
        assert stage(package_input, tmp_path / "linux-output").returncode == 0
        return  # Linux never consumes the deliberately unrelated canonical input.
    path = source / "canonical-scenario.yaml"
    if bad == "missing": path.unlink()
    elif bad == "crlf": path.write_bytes(CANONICAL_SCENARIO.replace(b"\n", b"\r\n"))
    elif bad == "tampered": path.write_bytes(CANONICAL_SCENARIO.replace(b"SCN-001", b"SCN-002"))
    elif bad == "empty": path.write_bytes(b"")
    else:
        copy = tmp_path / "canonical-copy"
        copy.write_bytes(path.read_bytes())
        path.unlink()
        path.hardlink_to(copy)
    output = tmp_path / "output"
    assert stage(package_input, output).returncode != 0
    assert not output.exists()


def test_linux_rejects_execution_asset_input(package_input, tmp_path):
    source, _, rid, _ = package_input
    if rid != "linux-x64":
        assert stage(package_input, tmp_path / "windows-output").returncode == 0
        return
    output = tmp_path / "output"
    assert stage(package_input, output, "--canonical-scenario", str(source / "canonical-scenario.yaml")).returncode != 0
    assert not output.exists()


def test_windows_requires_explicit_canonical_blob_input(package_input, tmp_path):
    _, _, rid, _ = package_input
    output = tmp_path / "output"
    result = stage(package_input, output, canonical=False)
    assert result.returncode == (1 if rid == "win-x64" else 0)
    assert output.exists() == (rid == "linux-x64")


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


@pytest.mark.parametrize("location", ["source", "build", "output-parent", "source-asset-parent"])
def test_reparse_paths_are_rejected_without_path_is_junction(package_input, tmp_path, monkeypatch, location):
    source, build, rid, _ = package_input
    output = tmp_path / "public" / "output"
    output.parent.mkdir()
    platform = "windows" if rid == "win-x64" else "linux"
    reparse = {"source": source, "build": build, "output-parent": output.parent,
               "source-asset-parent": source / "deploy/agent" / platform}[location]
    original_lstat = Path.lstat

    def reparse_lstat(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if path == reparse:
            fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
            fields["st_file_attributes"] = fields.get("st_file_attributes", 0) | 0x400
            return SimpleNamespace(**fields)
        return info

    # Python 3.11 exposes Windows reparse attributes but has no is_junction API.
    monkeypatch.delattr(Path, "is_junction", raising=False)
    monkeypatch.setattr(Path, "lstat", reparse_lstat)
    spec = importlib.util.spec_from_file_location("agent_connection_packaging", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    canonical = source / "canonical-scenario.yaml" if rid == "win-x64" else None
    with pytest.raises(ValueError):
        module.stage_agent_connection(source, build, output, rid, "0.3.0", COMMIT, canonical)
    assert not output.exists()


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
    {"libraries": {"aegis-agent/0.1.0": {}, "aegis-agent/0.3.0": {}}}])
def test_invalid_application_metadata_is_rejected(package_input, tmp_path, metadata):
    _, build, _, _ = package_input
    (build / "aegis-agent.deps.json").write_text(json.dumps(metadata))
    result = stage(package_input, tmp_path / "output")
    assert result.returncode != 0
    assert result.stderr.strip() == "agent_package_invalid"
    assert not (tmp_path / "output").exists()
