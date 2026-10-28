"""Build deterministic public presence-agent archives from a closed runtime manifest.

The runtime filename inventory is reviewed with each pinned runtime upgrade. It
must never be learned from arbitrary build output or its dependency JSON.
"""
import argparse
import gzip
from hashlib import sha256
import io
import json
from pathlib import Path
import re
import stat
import sys
import tarfile
from tempfile import TemporaryDirectory
import zipfile


def checked_path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError()
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError()
    return path.resolve()


def read_public(path):
    path = checked_path(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 100 * 1024 * 1024:
        raise ValueError()
    return path.read_bytes()


def payload(source, build, runtime, version, commit):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?", version):
        raise ValueError()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError()
    inventory = json.loads(read_public(Path(__file__).absolute().with_name("agent_connection_runtime_files.json")).decode("utf-8-sig"))
    names = inventory["files"][runtime]
    if inventory["runtime_version"] != "10.0.13" or len(names) != len(set(names)):
        raise ValueError()
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) for name in names):
        raise ValueError()
    if set(path.name for path in build.iterdir()) != set(names):
        raise ValueError()
    files = {"bin/" + name: read_public(build / name) for name in names}
    # The caller's archive label must describe the published application. This
    # reads version metadata only; the closed runtime inventory above remains
    # the sole authority for payload filenames.
    dependencies = json.loads(files["bin/aegis-agent.deps.json"])
    if not isinstance(dependencies, dict):
        raise ValueError()
    libraries = dependencies.get("libraries", {})
    if (not isinstance(libraries, dict)
            or {name for name in libraries if name.startswith("aegis-agent/")} != {"aegis-agent/" + version}):
        raise ValueError()
    config = json.loads(files["bin/aegis-agent.runtimeconfig.json"])
    if config.get("runtimeOptions", {}).get("includedFrameworks") != [{"name": "Microsoft.NETCore.App", "version": "10.0.13"}]:
        raise ValueError()
    notices = inventory["notices"][runtime]
    notice_names = {"LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"}
    notice_root = checked_path(source / "deploy/agent/runtime-notices" / runtime)
    if set(notices["files"]) != notice_names or set(path.name for path in notice_root.iterdir()) != notice_names:
        raise ValueError()
    for name, digest in notices["files"].items():
        data = read_public(notice_root / name)
        if sha256(data).hexdigest() != digest:
            raise ValueError()
        files["bin/" + name] = data
    files["bin/DOTNET-RUNTIME-NOTICES.json"] = (json.dumps(notices, indent=2, sort_keys=True) + "\n").encode()
    platform = "windows" if runtime == "win-x64" else "linux"
    scripts = ("Install-Agent.ps1", "Uninstall-Agent.ps1") if platform == "windows" else ("install.sh", "uninstall.sh", "aegis-agent.service")
    for name in scripts:
        files[name] = read_public(source / "deploy/agent" / platform / name)
    files["AGENT_CONNECTION_RUNBOOK.md"] = read_public(source / "docs/manager/AGENT_CONNECTION_RUNBOOK.md")
    files["version.json"] = (json.dumps({"schema_version": "1.0", "version": version, "source_commit": commit,
        "runtime": runtime, "dotnet_runtime": "10.0.13"}, indent=2, sort_keys=True) + "\n").encode()
    files["SHA256SUMS.txt"] = "".join(sha256(data).hexdigest() + "  " + name + "\n" for name, data in sorted(files.items())).encode()
    return files


def write_archive(path, files, runtime):
    if runtime == "win-x64":
        with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(files.items()):
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(entry, data)
    else:
        with path.open("xb") as output, gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, data in sorted(files.items()):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    entry.mode = 0o755 if name in ("bin/aegis-agent", "bin/createdump", "install.sh", "uninstall.sh") else 0o644
                    archive.addfile(entry, io.BytesIO(data))


def stage_agent_connection(source_root, build_root, output_root, runtime, version, commit):
    source, build, output = map(checked_path, (source_root, build_root, output_root))
    if output.exists() or any(output.is_relative_to(root) or root.is_relative_to(output) for root in (source, build)):
        raise ValueError()
    files = payload(source, build, runtime, version, commit)
    extension = ".zip" if runtime == "win-x64" else ".tar.gz"
    name = "AEGIS-Agent-Connection-" + version + "-" + runtime + extension
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".agent-public-", dir=output.parent) as temporary:
        staged = Path(temporary) / "release"
        staged.mkdir()
        archive = staged / name
        write_archive(archive, files, runtime)
        (staged / (name + ".sha256")).write_text(sha256(archive.read_bytes()).hexdigest() + "  " + name + "\n", encoding="ascii", newline="\n")
        # mkdir is exclusive on both Windows and POSIX. rename alone could
        # replace an empty directory created by a concurrent invocation.
        output.mkdir()
        for item in sorted(staged.iterdir()):
            with (output / item.name).open("xb") as destination:
                destination.write(item.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "build-root", "output-root"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--runtime", choices=("win-x64", "linux-x64"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        stage_agent_connection(args.source_root, args.build_root, args.output_root, args.runtime, args.version, args.commit)
    except (OSError, ValueError, TypeError, KeyError):
        print("agent_package_invalid", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
