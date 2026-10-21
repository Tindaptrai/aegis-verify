# Windows MSI validation

The MSI carries the same verified x64 onedir release under
`Program Files\AEGIS Verify`, including `aegis\aegis.exe`, resources, notices,
quickstart and build metadata. Product version is `0.4.0`; the executable file
version is `0.4.0.0`. This document describes the checks and their limits. A
successful build or table inspection does not establish successful installation.

## Read-only inspection on a development machine

Use Windows PowerShell under the machine's existing execution policy. The
default verifier opens the MSI database with Windows Installer's read-only mode.
It does not invoke `msiexec`, install a product, or modify the package.

```powershell
powershell -NoProfile -File .\packaging\windows\verify_msi.ps1 `
  -Msi 'C:\staging\AEGIS-Verify-0.4.0-x64.msi' `
  -Release 'C:\staging\verified-onedir\release'
```

Checks include:

- ProductVersion, stable UpgradeCode, `ALLUSERS=1`, x64 package and components,
  ProgramFiles64Folder and the fixed installation directory.
- Every payload path and the exact release file set, versioned executable,
  embedded cabinet streams and absence of external uncompressed payload files.
- Two nonadvertised common Start Menu shortcuts, their context-aware registry
  keypath, and separate HKLM64 application registration. The shortcut keypath
  uses HKMU (`Registry.Root=-1`) because ICE43 requires it. Enforced per-machine
  context resolves that key to HKLM. The installer also has an `ALLUSERS=1`
  launch condition.
- Upgrade and downgrade detection, the downgrade launch condition, and removal
  of the old product after InstallInitialize and before ProcessComponents.
- Absence of custom actions, services, environment changes, firewall extension
  rows and standard user data directories.

`-Release` is optional in default mode; supply the reviewed release to check
that the MSI file set agrees with the accepted payload. File hashes are compared
after extraction or installation. A successful command prints a JSON record.
`-Result <new-file.json>` also saves it without replacing an existing result.

## Administrative extraction without product registration

Extraction is separately opt-in and requires new output and log directories
outside the checkout. Their parents must already exist. `msiexec /a` creates an
administrative image; it does not run the normal product installation sequence.
The verifier keeps extracted files and logs for inspection, compares every
payload byte with the reviewed release, checks the executable version and runs
the existing distribution smoke against the extracted executable.

```powershell
powershell -NoProfile -File .\packaging\windows\verify_msi.ps1 `
  -Msi 'C:\staging\AEGIS-Verify-0.4.0-x64.msi' `
  -Release 'C:\staging\verified-onedir\release' `
  -ExtractTo 'C:\staging\new-administrative-image' `
  -LogDirectory 'C:\staging\new-extraction-logs' `
  -Python 'C:\tools\Python313\python.exe' `
  -SmokeScript 'C:\source\AEGIS-VERIFY\scripts\smoke_distribution.py' `
  -Result 'C:\staging\new-extraction-result.json'
```

Administrative extraction is not a substitute for install, repair, upgrade or
uninstall testing. It does not prove EDR policy acceptance or signing trust.

## Real install lifecycle on a disposable hosted runner

`.github/workflows/windows-distribution.yml` runs on GitHub's disposable
`windows-latest` runner. It prepares WiX 5.0.2 in a local tool directory, builds
a fresh wheel and freezes that exact installed wheel with build-only
PyInstaller 6.22.3. It independently smokes the wheel, onedir and onefile builds
outside the checkout. WiX database validation remains enabled.

The workflow first checks administrative extraction. It then invokes the
verifier with both `-InstallTest` and `-AcknowledgeDisposableRunner`. The verifier
also requires `GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted` and an
administrator process. It refuses existing related products, installation or
Start Menu directories. These switches are intended for this disposable CI
job; the local default never enables installation.

The install sequence is:

1. Silent install of the current MSI; compare all installed bytes, HKLM
   registration and common shortcuts; run the complete offline artifact smoke.
2. Remove one owned quickstart file, repair with `/fa`, and verify restoration.
3. Silent uninstall; verify removal of runtime, shortcuts and registration.
4. Install a labelled synthetic `0.3.99` MSI, then upgrade to the current MSI.
   Verify replacement of an unversioned changed file, removal of an older-only
   marker and exact current payload bytes; run the artifact smoke again.
5. Attempt the synthetic downgrade. Require the downgrade failure and log
   evidence of the expected version check, and verify current bytes remain.
6. Uninstall the upgraded product and verify cleanup. An external user-data
   sentinel must retain its original hash throughout. A final cleanup attempts
   to remove only product codes owned by this test if an intermediate step fails.

The synthetic older MSI derives from the generated current WXS. Only package
version/product identity, registry version, an explicit fixture label, a changed
quickstart source and an older-only marker component differ. It retains the
current application binary. This tests MSI upgrade mechanics; it does not prove
migration from a previous production release. It changes no security scenario,
fixture evidence, canonical event, detection rule or application ground truth.

Every installer call uses `/qn /norestart REBOOT=ReallySuppress` and a verbose
log. Exit `0` is success; `3010` is recorded separately as success requesting a
restart, which the test suppresses. Other codes fail, except the expected
downgrade rejection. Logs and step records remain available on failure.
[Microsoft installer options](https://learn.microsoft.com/en-us/windows/win32/msi/standard-installer-command-line-options)
and [repair options](https://learn.microsoft.com/windows-server/administration/windows-commands/msiexec)
describe the system operations used here.

The private Actions artifact retains a curated delivery directory for seven
days: MSI, portable ZIPs, wheel, authoring/build metadata, hashes, installer logs
and safe smoke results. It excludes virtual environments, tool caches,
credentials, the synthetic baseline installer and user data. This workflow
creates no GitHub Release and changes no repository visibility.

## Interpretation and local guards

A hosted runner has Python, Node and Git installed. Runtime smoke removes Python
and Node from PATH for the EXE; it is not a fresh enterprise Windows VM. A real
pilot still needs the downloaded artifact checked under the organization's
account, EDR, signing and deployment policies. Silent installation supplies no
multiuser server, service, automatic collection or firewall rule.

Run the local refusal tests without installing any product:

```text
python -I -m unittest discover -s packaging/windows -p test_verify_msi.py -v
```

These tests cover explicit acknowledgement, development/self-hosted runner
refusal, output containment and preservation of existing output/log/result
files. Actual lifecycle evidence comes from the corresponding CI result and
installer logs; this document makes no claim that an unrun check passed.
