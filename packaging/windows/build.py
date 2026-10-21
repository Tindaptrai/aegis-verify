"""Freeze an exact installed wheel from a prepared private Windows build environment.

This stdlib-only driver installs nothing and never imports AEGIS from the checkout.
Start with onedir; request --onefile only after the onedir artifact passes review.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import zipfile


PYINSTALLER_VERSION = "6.22.3"
CHECKOUT = Path(__file__).resolve().parents[2]
RUNTIME_DISTRIBUTIONS = (
    "aegis-verify", "pydantic", "pydantic_core", "PyYAML", "annotated-types",
    "typing-extensions", "typing-inspection",
)


def _version_resource(version):
    """Use the installed wheel version in the Windows PE version resource."""
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
        raise ValueError("invalid_windows_version")
    parts = tuple(int(part) for part in version.split("."))
    if any(part > 65535 for part in parts):
        raise ValueError("invalid_windows_version")
    numbers = repr((*parts, 0))
    return f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={numbers}, prodvers={numbers}, mask=0x3f,
    flags=0, OS=0x40004, fileType=0x1, subtype=0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [
    StringStruct('CompanyName', 'AEGIS Verify contributors'),
    StringStruct('FileDescription', 'AEGIS Verify for Windows'),
    StringStruct('FileVersion', '{version}.0'),
    StringStruct('InternalName', 'aegis'),
    StringStruct('OriginalFilename', 'aegis.exe'),
    StringStruct('ProductName', 'AEGIS Verify'),
    StringStruct('ProductVersion', '{version}')
  ])]), VarFileInfo([VarStruct('Translation', [1033, 1200])])]
)\n"""

# Runs in the selected interpreter with -I, outside the checkout. Only installed
# files are accepted; RECORD is expected to change during wheel installation.
PROBE = r'''
import hashlib
import importlib.metadata as metadata
import json
from pathlib import Path
import sys
import zipfile

wheel, expected_hash, expected_pyinstaller, names = sys.argv[1:]
prefix = Path(sys.prefix).resolve()
if sys.prefix == sys.base_prefix:
    raise SystemExit("isolated_build_venv_required")
dist = metadata.distribution("aegis-verify")
if metadata.version("PyInstaller") != expected_pyinstaller:
    raise SystemExit("pyinstaller_version_mismatch")
direct = json.loads(dist.read_text("direct_url.json") or "{}")
if direct.get("dir_info", {}).get("editable") is True:
    raise SystemExit("editable_install_forbidden")
archive = direct.get("archive_info", {})
recorded_hash = archive.get("hashes", {}).get("sha256")
if recorded_hash is None and archive.get("hash", "").startswith("sha256="):
    recorded_hash = archive["hash"].partition("=")[2]
if recorded_hash != expected_hash:
    raise SystemExit("installed_wheel_provenance_mismatch")
checked = 0
with zipfile.ZipFile(wheel) as source:
    for member in source.infolist():
        if member.is_dir() or member.filename.endswith(".dist-info/RECORD"):
            continue
        if not (member.filename.startswith("aegis_verify/") or ".dist-info/" in member.filename):
            continue
        installed = Path(dist.locate_file(member.filename)).resolve()
        if not installed.is_relative_to(prefix) or not installed.is_file():
            raise SystemExit("installed_wheel_file_missing")
        if hashlib.sha256(installed.read_bytes()).digest() != hashlib.sha256(source.read(member)).digest():
            raise SystemExit("installed_wheel_bytes_mismatch")
        checked += 1
import aegis_verify
import aegis_verify.resources
if not Path(aegis_verify.__file__).resolve().is_relative_to(prefix):
    raise SystemExit("source_import_forbidden")
versions, licenses = {}, []
frontend_license = Path(aegis_verify.resources.__file__).resolve().parent / "data/licenses/frontend.txt"
if not frontend_license.is_relative_to(prefix) or not frontend_license.is_file():
    raise SystemExit("frontend_license_missing")
licenses.append({"distribution": "frontend", "name": "THIRD_PARTY_NOTICES.txt", "path": str(frontend_license)})
for name in json.loads(names) + ["PyInstaller"]:
    item = metadata.distribution(name)
    versions[name] = item.version
    for member in item.files or ():
        filename = Path(str(member)).name.lower()
        if ("license" in filename or filename.startswith("copying") or filename.startswith("notice")):
            path = Path(item.locate_file(member)).resolve()
            if path.is_relative_to(prefix) and path.is_file():
                licenses.append({"distribution": name, "name": filename, "path": str(path)})
python_license = Path(sys.base_prefix) / "LICENSE.txt"
if not python_license.is_file():
    raise SystemExit("python_license_missing")
licenses.append({"distribution": "Python", "name": "LICENSE.txt", "path": str(python_license)})
print(json.dumps({"version": dist.version, "python": sys.version.split()[0],
    "architecture_bits": 64 if sys.maxsize > 2**32 else 32,
    "installed_wheel_files_checked": checked, "distributions": versions,
    "build_environment": {d.metadata["Name"]: d.version for d in metadata.distributions()},
    "licenses": licenses}))
'''


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _wheel_hash(path):
    try:
        with zipfile.ZipFile(path) as wheel:
            members = wheel.namelist()
            if len(members) != len(set(members)):
                raise ValueError
            for name in members:
                parts = PurePosixPath(name)
                if parts.is_absolute() or ".." in parts.parts or "\\" in name or ":" in name:
                    raise ValueError
            for directory in ("static", "scenarios", "fixtures", "dashboard-reports"):
                if not any(name.startswith(f"aegis_verify/resources/data/{directory}/") for name in members):
                    raise ValueError
            if "aegis_verify/resources/data/licenses/frontend.txt" not in members:
                raise ValueError
            if not any(name.endswith(".dist-info/WHEEL") for name in members):
                raise ValueError
            if wheel.testzip() is not None:
                raise ValueError
    except (OSError, zipfile.BadZipFile, ValueError):
        raise ValueError("invalid_wheel") from None
    return _sha256(path)


def _environment():
    environment = dict(os.environ)
    # -I also ignores these; remove them so subprocesses cannot inherit a source
    # import path or an alternate Python installation through the build driver.
    for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
        environment.pop(name, None)
    return environment


def _quickstart(onefile):
    executable = r".\aegis.exe" if onefile else r".\aegis\aegis.exe"
    return f"""# AEGIS Verify — Windows offline preview

Experimental unsigned build. Keep this release folder intact. Python, Node and
the source checkout are not needed for this offline walkthrough. Use a normal
Windows account and a terminal; this executable is a CLI, not a desktop wizard.

```powershell
$exe = '{executable}'
& $exe --version
$demo = Join-Path $env:LOCALAPPDATA ('AEGIS-Verify-demo-' + [guid]::NewGuid().ToString('N'))
& $exe demo --out $demo
& $exe dashboard --bundled --reports (Join-Path $demo 'reports')
```

Open the local URL printed by the dashboard. Inspect scenarios, assertions,
evidence IDs, timeline and before/after comparison. Ctrl+C stops this instance.
The output is a new direct child of the existing LOCALAPPDATA directory, so first
use does not require an existing AEGIS data folder. For another --out location,
its parent directory must already exist.

The public offline replay evaluates six sanitized lab-derivative cases and two
synthetic cases. It also includes two supplied synthetic reports for the separate
Gap/Fix regression example. It does not execute a scenario, contact a SIEM or
demonstrate enterprise-wide monitoring. Output belongs in your chosen data
directory; do not write it into the installed runtime.

For your own bundle, use `validate --help`, `compare --help` and
`dashboard --help`. Live collection needs approved private configuration,
credentials, CA and network access; SSH collection also needs OpenSSH. Windows
Operations checks need system PowerShell. No such operation starts automatically.

Keep SHA256SUMS.txt, BUILD-INFO.json and LICENSES with the release. Verify hashes
before use. This local pilot application does not run as a Windows service or
provide a shared intranet server. For MSI deployment, follow the separate IT guide.
"""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, type=Path, help="Prepared build venv Python; nothing is installed")
    parser.add_argument("--wheel", required=True, type=Path, help="Exact local wheel already installed in that venv")
    parser.add_argument("--out", required=True, type=Path, help="New directory outside this source checkout")
    parser.add_argument("--onefile", action="store_true", help="Optional second-stage build after onedir verification")
    options = parser.parse_args(argv)
    python = options.python.expanduser().resolve()
    wheel = options.wheel.expanduser().resolve()
    output = options.out.expanduser().resolve()
    try:
        if output.exists():
            raise ValueError("output_exists")
        if output.is_relative_to(CHECKOUT):
            raise ValueError("output_inside_checkout")
        wheel_hash = _wheel_hash(wheel)
        if sys.platform != "win32":
            raise ValueError("windows_build_required")
        if not python.is_file():
            raise ValueError("build_python_missing")
        environment = _environment()
        # A fresh non-source cwd prevents both the probe and PyInstaller analysis
        # from accidentally resolving backend/app or checkout-only data assets.
        output.mkdir(parents=True, exist_ok=False)
        work = output / "build-context"
        work.mkdir()
        result = subprocess.run(
            [str(python), "-I", "-X", "utf8", "-c", PROBE, str(wheel), wheel_hash,
             PYINSTALLER_VERSION, json.dumps(list(RUNTIME_DISTRIBUTIONS))],
            cwd=work, env=environment, capture_output=True, text=True, encoding="utf-8",
            timeout=120, check=False,
        )
        if result.returncode != 0:
            diagnostic = result.stderr.strip().splitlines()
            allowed = {
                "isolated_build_venv_required", "pyinstaller_version_mismatch", "editable_install_forbidden",
                "installed_wheel_provenance_mismatch", "installed_wheel_file_missing",
                "installed_wheel_bytes_mismatch", "source_import_forbidden", "python_license_missing",
                "frontend_license_missing",
            }
            code = diagnostic[-1] if diagnostic and diagnostic[-1] in allowed else "build_environment_invalid"
            raise ValueError(code)
        installation = json.loads(result.stdout)
        release = output / "release"
        release.mkdir()
        entry = work / "aegis_entry.py"
        entry.write_text("from aegis_verify.cli import main\n\nraise SystemExit(main())\n", encoding="utf-8")
        version_file = work / "windows-version.txt"
        version_file.write_text(_version_resource(installation["version"]), encoding="utf-8")
        command = [str(python), "-I", "-X", "utf8", "-m", "PyInstaller",
            "--noconfirm", "--clean", "--name", "aegis", "--console",
            "--onefile" if options.onefile else "--onedir",
            "--version-file", str(version_file),
            "--distpath", str(release), "--workpath", str(work / "work"), "--specpath", str(work),
            "--collect-submodules", "aegis_verify", "--collect-data", "aegis_verify.resources",
            "--recursive-copy-metadata", "aegis-verify"]
        # Runtime distribution metadata includes its declared license files.
        # Explicit data entries retain Python and bootloader notices as well,
        # including inside the optional single executable's embedded archive.
        for index, item in enumerate(installation["licenses"]):
            destination = f"third-party-licenses/{item['distribution']}/{index:02d}"
            command.extend(["--add-data", f"{item['path']}:{destination}"])
        command.append(str(entry))
        subprocess.run(command, cwd=work, env=environment, check=True)
        executable = release / "aegis.exe" if options.onefile else release / "aegis" / "aegis.exe"
        if not executable.is_file():
            raise ValueError("executable_missing")
        licenses = release / "LICENSES"
        for index, item in enumerate(installation.pop("licenses")):
            destination = licenses / item["distribution"] / f"{index:02d}-{item['name']}"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item["path"], destination)
        (release / "QUICKSTART.md").write_text(_quickstart(options.onefile), encoding="utf-8")
        application_version = installation.pop("version")
        information = {"kind": "aegis_windows_build", "version": "0.1.0",
            "application_version": application_version,
            "windows_file_version": application_version + ".0",
            "mode": "onefile" if options.onefile else "onedir", "signed": False,
            "source_wheel": wheel.name, "source_wheel_sha256": wheel_hash,
            "pyinstaller": PYINSTALLER_VERSION, **installation,
            "verification": "Build only; run the independent offline acceptance checks before distribution."}
        (release / "BUILD-INFO.json").write_text(json.dumps(information, indent=2) + "\n", encoding="utf-8")
        manifest = "".join(f"{_sha256(path)}  {path.relative_to(release).as_posix()}\n"
            for path in sorted(release.rglob("*")) if path.is_file())
        (release / "SHA256SUMS.txt").write_text(manifest, encoding="utf-8")
        print(json.dumps({"release": str(release), "executable": str(executable),
            "source_wheel_sha256": wheel_hash, "mode": information["mode"]}))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        error = sys.exception()
        code = str(error) if isinstance(error, ValueError) else "build_failed"
        print(f"AEGIS Windows build: {code}", file=sys.stderr)
        # Retain failed output for diagnosis; never remove an operator's files.
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
