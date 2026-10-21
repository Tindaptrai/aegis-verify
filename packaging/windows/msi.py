"""Build a per-machine x64 MSI from a verified AEGIS onedir release.

This stdlib-only driver installs nothing. Supply a separately prepared, pinned
WiX CLI and a public release produced by packaging/windows/build.py.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from uuid import UUID, uuid5
import xml.etree.ElementTree as ET


WIX_VERSION = "5.0.2"
UPGRADE_CODE = "{B68E2F81-6D3D-5CED-A16E-875DD032A752}"
CHECKOUT = Path(__file__).resolve().parents[2]
WXS_NAMESPACE = "http://wixtoolset.org/schemas/v4/wxs"
HASH = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    prefix + digit for prefix in ("COM", "LPT") for digit in "123456789¹²³"
}
ET.register_namespace("", WXS_NAMESPACE)


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _plain_path(path):
    """Reject links before following a path, including Windows reparse points."""
    information = path.lstat()
    if (stat.S_ISLNK(information.st_mode)
            or getattr(information, "st_file_attributes", 0) & 0x400
            or (stat.S_ISREG(information.st_mode) and information.st_nlink != 1)):
        raise ValueError("payload_link_forbidden")
    return information


def _safe_relative(value):
    parts = value.split("/")
    return bool(value) and all(
        part and part not in {".", ".."} and not part.endswith((".", " "))
        and not any(ord(character) < 32 or character in '<>:"\\|?*' for character in part)
        and part.split(".", 1)[0].upper() not in DEVICES
        for part in parts
    )


def _version(value):
    if (not isinstance(value, str) or len(value) > 13 or not VERSION.fullmatch(value)
            or any(int(part) > limit for part, limit in zip(value.split("."), (255, 255, 65535)))):
        raise ValueError("invalid_msi_version")
    return value


def validate_release(release):
    """Verify an exact complete onedir inventory without importing the application."""
    release = Path(release).absolute()
    if not stat.S_ISDIR(_plain_path(release).st_mode):
        raise ValueError("release_directory_required")
    actual = {}
    names = set()
    for directory, folders, files in os.walk(release, followlinks=False):
        for name in folders + files:
            path = Path(directory) / name
            information = _plain_path(path)
            relative = path.relative_to(release).as_posix()
            normalized = relative.casefold()
            if not _safe_relative(relative) or normalized in names:
                raise ValueError("invalid_payload_path")
            names.add(normalized)
            if stat.S_ISREG(information.st_mode):
                actual[relative] = path
            elif not stat.S_ISDIR(information.st_mode):
                raise ValueError("unsupported_payload_file")
    manifest = actual.get("SHA256SUMS.txt")
    if manifest is None:
        raise ValueError("invalid_payload_manifest")
    try:
        manifest_bytes = manifest.read_bytes()
        lines = manifest_bytes.decode("utf-8").splitlines()
        expected = {}
        listed_names = set()
        if not lines:
            raise ValueError
        for line in lines:
            if len(line) < 67 or line[64:66] != "  " or not HASH.fullmatch(line[:64]):
                raise ValueError
            relative = line[66:]
            normalized = relative.casefold()
            if (not _safe_relative(relative) or normalized == "sha256sums.txt"
                    or normalized in listed_names):
                raise ValueError
            listed_names.add(normalized)
            expected[relative] = line[:64]
    except (UnicodeError, ValueError):
        raise ValueError("invalid_payload_manifest") from None
    if set(actual) != set(expected) | {"SHA256SUMS.txt"}:
        raise ValueError("payload_inventory_mismatch")
    for relative, digest in expected.items():
        if _sha256(actual[relative]) != digest:
            raise ValueError("payload_hash_mismatch")
    required = {"BUILD-INFO.json", "QUICKSTART.md", "aegis/aegis.exe"}
    if (not required.issubset(actual)
            or not any(name.startswith("LICENSES/") for name in actual)
            or not any(name.startswith("aegis/_internal/") for name in actual)):
        raise ValueError("required_payload_missing")
    try:
        metadata = json.loads(actual["BUILD-INFO.json"].read_text(encoding="utf-8"))
        if (not isinstance(metadata, dict) or metadata.get("kind") != "aegis_windows_build"
                or metadata.get("mode") != "onedir" or metadata.get("architecture_bits") != 64
                or not isinstance(metadata.get("source_wheel_sha256"), str)
                or not HASH.fullmatch(metadata["source_wheel_sha256"])):
            raise ValueError
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("unsupported_release_metadata") from None
    version = _version(metadata.get("application_version"))
    return {"version": version, "files": sorted(actual),
            "payload_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "source_wheel_sha256": metadata["source_wheel_sha256"]}


def _identifier(prefix, relative):
    return prefix + hashlib.sha256(relative.casefold().encode("utf-8")).hexdigest()[:32]


def _guid(value):
    return "{" + str(uuid5(UUID(UPGRADE_CODE), value)).upper() + "}"


def product_code(version):
    return _guid("product:x64:" + _version(version))


def render_wxs(release, version):
    """Return core WiX authoring; identities depend only on destination paths."""
    release = Path(release).absolute()
    verified = validate_release(release)
    if _version(version) != verified["version"]:
        raise ValueError("release_version_mismatch")
    tag = lambda value: "{" + WXS_NAMESPACE + "}" + value
    element = lambda parent, name, **attributes: ET.SubElement(parent, tag(name), attributes)
    root = ET.Element(tag("Wix"))
    package = element(root, "Package", Name="AEGIS Verify", Manufacturer="AEGIS Verify",
                      Version=version, ProductCode=product_code(version), UpgradeCode=UPGRADE_CODE,
                      Language="1033", Scope="perMachine", InstallerVersion="500", Compressed="yes")
    element(package, "MajorUpgrade", Schedule="afterInstallInitialize",
            DowngradeErrorMessage="A newer version of AEGIS Verify is already installed.")
    element(package, "MediaTemplate", EmbedCab="yes")
    element(package, "Property", Id="ARPNOMODIFY", Value="1")
    element(package, "Property", Id="REBOOT", Value="ReallySuppress")
    element(package, "Launch", Condition="ALLUSERS = 1",
            Message="AEGIS Verify requires a per-machine installation.")
    program_files = element(package, "StandardDirectory", Id="ProgramFiles64Folder")
    install = element(program_files, "Directory", Id="INSTALLFOLDER", Name="AEGIS Verify")
    directories = {"": install}
    feature = element(package, "Feature", Id="Complete", Title="AEGIS Verify", Level="1")
    for relative in verified["files"]:
        parts = relative.split("/")
        for index in range(1, len(parts)):
            directory = "/".join(parts[:index])
            if directory not in directories:
                parent = "/".join(parts[:index - 1])
                directories[directory] = element(directories[parent], "Directory",
                                                  Id=_identifier("D_", directory), Name=parts[index - 1])
        component_id = _identifier("C_", relative)
        component = element(directories["/".join(parts[:-1])], "Component", Id=component_id,
                            Guid=_guid("component:x64:" + relative.casefold()), Bitness="always64")
        element(component, "File", Id=_identifier("F_", relative), Name=parts[-1],
                Source=str(release / relative), KeyPath="yes")
        element(feature, "ComponentRef", Id=component_id)
    menu_root = element(package, "StandardDirectory", Id="ProgramMenuFolder")
    menu = element(menu_root, "Directory", Id="AEGISMENU", Name="AEGIS Verify")
    menu_component = element(menu, "Component", Id="MenuShortcuts",
                             Guid=_guid("component:x64:machine-menu-shortcuts"), Bitness="always64")
    exe_id = _identifier("F_", "aegis/aegis.exe")
    element(menu_component, "Shortcut", Id="ConsoleShortcut", Name="AEGIS Verify Console",
            Advertise="no", Target="[System64Folder]cmd.exe",
            Arguments=f'/D /K ""[#{exe_id}]" --help"', WorkingDirectory="INSTALLFOLDER")
    element(menu_component, "Shortcut", Id="QuickstartShortcut", Name="AEGIS Verify Quickstart",
            Advertise="no", Target="[#" + _identifier("F_", "QUICKSTART.md") + "]",
            WorkingDirectory="INSTALLFOLDER")
    # ICE43 requires a context-aware registry key path for nonadvertised
    # shortcuts. ALLUSERS=1 is enforced above: HKMU resolves to HKLM, never HKCU.
    element(menu_component, "RegistryValue", Root="HKMU", Key=r"Software\AEGIS Verify",
            Name="ShortcutsInstalled", Type="integer", Value="1", KeyPath="yes")
    element(menu_component, "RemoveFolder", Id="RemoveMenuFolder", On="uninstall")
    element(feature, "ComponentRef", Id="MenuShortcuts")
    registration = element(install, "Component", Id="MachineRegistration",
                           Guid=_guid("component:x64:machine-registration"), Bitness="always64")
    for name, value, kind in (("Installed", "1", "integer"), ("InstallDir", "[INSTALLFOLDER]", "string"),
                              ("Version", version, "string")):
        attributes = {"Root": "HKLM", "Key": r"Software\AEGIS Verify", "Name": name,
                      "Type": kind, "Value": value}
        if name == "Installed":
            attributes["KeyPath"] = "yes"
        element(registration, "RegistryValue", **attributes)
    element(feature, "ComponentRef", Id="MachineRegistration")
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def _output_path(value, release):
    output = Path(value).expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("output_exists")
    resolved = output.resolve()
    if resolved.is_relative_to(CHECKOUT):
        raise ValueError("output_inside_checkout")
    if resolved.is_relative_to(release.resolve()):
        raise ValueError("output_inside_release")
    for ancestor in output.parents:
        if ancestor.exists():
            _plain_path(ancestor)
    return resolved


def _wix_version(wix, environment):
    result = subprocess.run([str(wix), "--version"], capture_output=True, text=True,
                            encoding="utf-8", env=environment, timeout=30, check=False)
    # Official CLI includes its source revision after '+'. No other major or
    # patch version, wrapper banner, or error output is accepted.
    if (result.returncode != 0 or not re.fullmatch(r"5\.0\.2(?:\+[A-Za-z0-9.-]+)?\s*", result.stdout)
            or result.stderr.strip()):
        raise ValueError("wix_version_mismatch")


def _install_guide(version, code):
    return f"""# AEGIS Verify {version} — Windows MSI

This unsigned preview installs the same verified offline onedir runtime for all
users under Program Files. Installation needs administrator approval. Run AEGIS
as a normal user. No application is launched by installation.

```powershell
msiexec.exe /i "AEGIS-Verify-{version}-x64.msi" /qn /norestart /L*v install.log
msiexec.exe /fomus {code} /qn /norestart /L*v repair.log
msiexec.exe /x {code} /qn /norestart /L*v uninstall.log
```

Use full paths in deployment tooling. The log parent directory must exist.
Exit 0 means success; 3010 means success with a requested restart, suppressed by
/norestart. Other codes need investigation. Close running AEGIS instances before
maintenance. Start Menu contains a console with CLI help and the installed
QUICKSTART.md. A Markdown viewer may be needed to open the quickstart shortcut.

Write reports, bundles and private configuration in a separate user-selected
data directory, such as LOCALAPPDATA. Upgrade and uninstall manage installed
runtime files and registration; they preserve external user data. Never store
private data or modify runtime files under Program Files. Follow QUICKSTART.md
for the explicit offline demo and local dashboard commands.

The installer adds no service, scheduled task, firewall rule, credential or
automatic collection. Silent installation does not provide shared-server access
or RBAC. Validate signing/EDR and deployment policy before a real pilot. Build
success and administrative extraction do not prove install/upgrade correctness.
"""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True, type=Path, help="Verified public onedir release")
    parser.add_argument("--wix", required=True, type=Path, help="Explicit separately prepared WiX 5.0.2 executable")
    parser.add_argument("--out", required=True, type=Path, help="New output directory outside the checkout and release")
    options = parser.parse_args(argv)
    try:
        release = options.release.expanduser().absolute()
        output = _output_path(options.out, release)
        verified = validate_release(release)
        if sys.platform != "win32":
            raise ValueError("windows_build_required")
        wix = options.wix.expanduser().absolute()
        if not wix.is_file() or wix.suffix.lower() != ".exe":
            raise ValueError("wix_executable_missing")
        _plain_path(wix)
        environment = dict(os.environ)
        for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
            environment.pop(name, None)
        _wix_version(wix, environment)
        output.mkdir(parents=True, exist_ok=False)
        work = output / "build-context"
        payload = work / "payload"
        payload.mkdir(parents=True)
        # Build from an exact checked snapshot, never an unchecked mutable glob.
        for relative in verified["files"]:
            destination = payload / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(release / relative, destination)
        snapshot = validate_release(payload)
        if snapshot != verified:
            raise ValueError("payload_changed_during_staging")
        version = verified["version"]
        authoring = work / "AEGIS-Verify.wxs"
        authoring.write_text(render_wxs(payload, version), encoding="utf-8", newline="\n")
        msi = output / f"AEGIS-Verify-{version}-x64.msi"
        command = [str(wix), "build", "-arch", "x64", "-intermediateFolder", str(work / "wix"),
                   "-o", str(msi), str(authoring)]
        # Native MSI actions only. ICE validation remains enabled.
        subprocess.run(command, cwd=work, env=environment, check=True, timeout=600,
                       stdout=sys.stderr, stderr=sys.stderr)
        if not msi.is_file() or msi.read_bytes()[:8] != bytes.fromhex("d0cf11e0a1b11ae1"):
            raise ValueError("msi_missing_or_invalid")
        build_info = output / "MSI-BUILD-INFO.json"
        information = {"kind": "aegis_windows_msi", "schema_version": "1.0.0",
            "application_version": version, "architecture": "x64", "scope": "perMachine", "signed": False,
            "wix": WIX_VERSION, "source_payload_sha256": verified["payload_sha256"],
            "source_wheel_sha256": verified["source_wheel_sha256"],
            "product_code": product_code(version), "upgrade_code": UPGRADE_CODE,
            "payload_files": len(verified["files"]), "msi_sha256": _sha256(msi),
            "verification": "Build only; independent extraction and disposable-machine acceptance required."}
        build_info.write_text(json.dumps(information, indent=2) + "\n", encoding="utf-8", newline="\n")
        guide = output / "INSTALL.md"
        guide.write_text(_install_guide(version, product_code(version)), encoding="utf-8", newline="\n")
        checksums = output / "SHA256SUMS.txt"
        checksums.write_text("".join(f"{_sha256(path)}  {path.name}\n"
                                    for path in (msi, guide, build_info)), encoding="utf-8", newline="\n")
        print(json.dumps({"msi": str(msi), "authoring": str(authoring), "build_info": str(build_info),
            "checksums": str(checksums), "install_guide": str(guide), "version": version,
            "product_code": product_code(version), "upgrade_code": UPGRADE_CODE,
            "payload_sha256": verified["payload_sha256"]}))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        error = sys.exception()
        code = str(error) if isinstance(error, ValueError) else "msi_build_failed"
        print(f"AEGIS MSI build: {code}", file=sys.stderr)
        # Failed output remains available for diagnosis; never delete user files.
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
