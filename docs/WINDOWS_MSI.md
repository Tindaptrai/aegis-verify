# Windows MSI: the same AEGIS core in two distribution formats

Version 0.4.0 provides a portable EXE/ZIP and a real Windows Installer MSI.
Both run the existing local CLI, offline validation/comparison, public demo and
loopback dashboard. The MSI installs the exact verified onedir release beneath
`Program Files\AEGIS Verify`, preserving the `aegis` runtime subdirectory and
license notices. A receiving machine needs neither Python nor Node.

The MSI is per-machine and x64. Administrator approval is needed to install;
normal users run the application. The common Start Menu has a console shortcut
that keeps CLI help visible and a shortcut to the installed `QUICKSTART.md`.
The latter uses the machine's Markdown association; a viewer may be needed.
Installation never launches AEGIS. This package adds no service, scheduled task,
firewall rule, login/RBAC, shared server or automatic live collection.

## Build prerequisite and reviewed pin

First build and verify the public onedir release using
[Windows distribution](WINDOWS_DISTRIBUTION.md). MSI packaging consumes that
release; it does not import the source application or repeat freezing.

[requirements-msi.json](../packaging/windows/requirements-msi.json) pins the
**build-only WiX CLI 5.0.2**. Core WiX can author the required native MSI tables
and embedded cabinet without an extension or application runtime dependency.
This avoids hand-maintaining MSI database tables. A .NET SDK/runtime is needed
only on the build machine. Do not install WiX globally or add it to AEGIS runtime
dependencies. The builder installs nothing and requires an explicit executable.

WiX 5.0.2 is covered by [MS-RL at its official tag](https://raw.githubusercontent.com/wixtoolset/wix/v5.0.2/LICENSE.TXT).
Its [official NuGet package](https://www.nuget.org/packages/wix/5.0.2) declares
`requireLicenseAcceptance=false`; the inspected package targets .NET 6 with
major-version roll-forward. OSMF terms were introduced in WiX 6, and WiX 7 adds
an explicit acceptance step. This build uses no OSMF acceptance flag, payment or
paid HeatWave extension. [Official version changes](https://docs.firegiant.com/wix/whatsnew/)

WiX 5 public consumer security servicing **ended on 2026-02-05**. This pin is
not the latest WiX release and is not described as supported. Reevaluate the pin,
license terms and [official security advisories](https://github.com/wixtoolset/issues/security/advisories)
before future production releases. The October 2026 review found three published
advisories whose affected ranges end before 5.0.2: two concern Burn and one
`RemoveFolderEx`. This MSI uses neither. That review is not a guarantee against
unknown defects. [Official lifecycle](https://docs.firegiant.com/wix/#lifecycle)

Example preparation in an existing private staging directory:

```powershell
dotnet tool install wix --version 5.0.2 --tool-path C:\staging\aegis-build\tools
```

Prepare the build tool separately, then run the driver with approved local paths:

```powershell
python -I -X utf8 packaging/windows/msi.py --release C:\staging\aegis-build\onedir\release --wix C:\staging\aegis-build\tools\wix.exe --out C:\staging\aegis-build\msi
```

`--out` must be new and outside both the checkout and input release. The driver
checks the complete payload inventory and hashes, rejects unsafe/duplicate paths,
links, junctions, reparse points, hard links, unlisted or missing files, onefile
input and non-x64 metadata. A separately staged snapshot is verified again before
WiX reads it. Keep the source release fixed while packaging. These checks bind
the MSI to the supplied release; they do not authenticate an untrusted manifest.

WiX runs with ICE validation enabled and native MSI actions only. A failed build
retains its output for diagnosis. Standard output is one JSON object containing
`msi`, `authoring`, `build_info`, `checksums`, `install_guide`, `version`,
`product_code`, `upgrade_code` and `payload_sha256`. The last value is the SHA-256
of the source release's manifest bytes. Build output includes:

- `AEGIS-Verify-0.4.0-x64.msi`: the genuine MSI with embedded cabinet.
- `MSI-BUILD-INFO.json`, `INSTALL.md` and `SHA256SUMS.txt`: distributable metadata.
- `build-context/AEGIS-Verify.wxs`, exact payload snapshot and WiX intermediates:
  local diagnostics. Authoring contains local source paths; keep this directory
  private instead of distributing the build context.

The installed runtime retains its own `BUILD-INFO.json` and `SHA256SUMS.txt`.
`MSI-BUILD-INFO.json` describes the outer package and records both source payload
and wheel hashes. The builder records `signed=false`; enterprise signing is a
separate release gate. Never claim an unsigned preview satisfies every EDR or
software distribution policy.

## Version and upgrade contract

MSI ProductVersion is the exact numeric `major.minor.build` application version
from the verified build metadata. Limits are 255, 255 and 65535. Prerelease,
local, four-part and ambiguous leading-zero versions are rejected. Windows
Installer ignores a fourth version part when comparing products.
[Microsoft ProductVersion](https://learn.microsoft.com/en-us/windows/win32/msi/productversion)

The committed UpgradeCode identifies this x64 product family. ProductCode is
derived from the family and version, so rebuilding a release does not create a
second product identity. Published versions are immutable: use a higher
three-part version when changing a released payload. Component GUIDs depend on
destination paths and architecture, not temporary staging paths, application
version or file hashes. Each file has its own component and explicit key path.

Major upgrades remove the older managed runtime after `InstallInitialize`, then
install the replacement within the Windows Installer transaction. A failed
transaction can restore the previous product. Downgrades are blocked. This
ordering also replaces changed unversioned runtime files and removes obsolete
managed files. Genuine PE file versions are retained; no fabricated file version
or force-overwrite setting substitutes for upgrade testing.
[WiX MajorUpgrade](https://docs.firegiant.com/wix/schema/wxs/majorupgrade/),
[Microsoft file rules](https://learn.microsoft.com/en-us/windows/win32/msi/file-versioning-rules)

Product registration uses HKLM64 `Software\AEGIS Verify`. Nonadvertised shortcut
key paths use context-aware HKMU, which resolves to HKLM because the package
enforces `ALLUSERS=1`; no per-user registry entry is installed. This satisfies
the registry key-path requirement of [ICE43](https://learn.microsoft.com/en-us/windows/win32/msi/ice43).

## Install, repair and uninstall

Use an administrator-approved deployment context and full paths. For interactive
installation, open the MSI through the approved software distribution process.
Silent examples (the log's parent directory must exist):

```powershell
msiexec.exe /i "C:\staging\AEGIS-Verify-0.4.0-x64.msi" /qn /norestart /L*v "C:\staging\install.log"
msiexec.exe /fomus "{ProductCode from MSI-BUILD-INFO.json}" /qn /norestart /L*v "C:\staging\repair.log"
msiexec.exe /x "{ProductCode from MSI-BUILD-INFO.json}" /qn /norestart /L*v "C:\staging\uninstall.log"
```

Close running AEGIS processes before maintenance. Code 0 means success; 3010 means
success with a requested restart, suppressed by `/norestart`. Retain logs and
investigate other return codes. Detect installed version through the product
registration or the actual installed executable's `--version`. Do not use
`Win32_Product` inventory queries, which can trigger repair.
[Microsoft command-line options](https://learn.microsoft.com/en-us/windows/win32/msi/standard-installer-command-line-options)

All reports, evidence bundles and private configuration belong in an external
user-selected directory with appropriate ACLs, for example a private directory
under `LOCALAPPDATA`. The installer owns runtime files and product registration;
it never registers, overwrites or removes external user data. Do not edit runtime
files or store private data under Program Files. The explicit demo command in
`QUICKSTART.md` creates a fresh output directory outside the installed runtime.

## Required acceptance

Run the unit checks with `python -m unittest discover -s packaging/windows -p test_msi.py -v`.
They need no installed WiX. The independent Windows artifact verifier and CI
workflow inspect real MSI tables and extract payload bytes. Review their output
against the exact source manifest and package hash.

On an explicitly disposable Windows runner/VM, verify silent install, installed
registration, common Start Menu targets, runtime use as a normal user, repair,
upgrade, downgrade rejection and uninstall. Upgrade coverage must include changed
unversioned data and an obsolete file. A labelled synthetic earlier-version MSI
exercises the mechanism; it is not evidence of migration from a shipped release.
Hash and ACL checks must show that external report/config sentinels survive
repair, upgrade and uninstall. Never use the production workstation for this
destructive lifecycle test.

Finally run the fresh-machine CLI and browser acceptance in
[Windows distribution](WINDOWS_DISTRIBUTION.md), using the downloaded MSI, normal
user permissions, an unrelated CWD, and paths with spaces/Unicode. Confirm EID,
timeline, comparison and input-error behavior; administrative extraction alone
does not prove the application or browser UI works. Human review, lab validation,
signing and deployment-policy approval remain release gates.
