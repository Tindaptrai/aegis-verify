# Windows demo launcher

`AEGIS-Demo.exe` is a small .NET Framework Windows helper for the existing
AEGIS Verify **0.4.0** executable. Put it beside the original `aegis.exe` and
double-click `AEGIS-Demo.exe`. Windows 10/11 with .NET Framework 4.8 is the target.
Python, Node, PowerShell and administrator rights are not needed to run it.

The helper prepares a fresh offline demo, starts its dashboard on an operating
system selected port, and opens the default browser after verifying the page,
12 readable reports and the six scenario manifests. The window shows the URL,
data directory and log. **Open Dashboard** can reopen the browser. **Stop and
close**, or closing the window, stops that helper's dashboard.

Each launch keeps its data and UTF-8 log in a new directory under
`%LOCALAPPDATA%\AEGIS Verify\Demo\session-<GUID>\`. The existing parent is created
before `aegis.exe demo --out <new-target>` runs. Existing demo sessions and user
reports are preserved. Errors remain visible in the window with the log and
data paths; the engine is never rebuilt or modified by the helper.

The demo uses the public offline replay already supplied by 0.4.0. Sanitized lab
derivatives and synthetic cases retain their original labels and conclusions.
SCN-001's private evidence is absent, and the known unregistered synthetic
SCN-999 reports remain visible. This is software replay verification; a new lab
validation still requires human review.

## Process ownership

The helper starts each AEGIS process suspended, assigns it to a private Windows
job with `KILL_ON_JOB_CLOSE`, and then resumes it. This includes the onefile
bootloader's descendants and avoids a race during assignment. A startup failure,
normal close or forced helper termination closes that job. No process is found
or stopped by executable name or by port. The default browser starts from the
helper outside the AEGIS job and remains independent.

The dashboard URL comes from the actual engine announcement. Only an HTTP
loopback URL with a root path and no credentials, query or fragment is accepted.
Readiness requests bypass proxies, reject redirects and use bounded response
sizes and timeouts.

## Build and verification

Use the adjacent `build.ps1` for the reviewed icon and delivery folder. The
underlying source requires only installed .NET Framework assemblies:

```powershell
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /warnaserror+ /target:winexe /reference:System.Windows.Forms.dll,System.Drawing.dll,System.Web.Extensions.dll /win32icon:packaging/windows/demo-launcher/assets/aegis-demo.ico /out:AEGIS-Demo.exe packaging/windows/demo-launcher/Launcher.cs
```

The helper's file version is **0.4.0.1** to identify this separate helper. The
neighboring core stays **0.4.0.0**. The window and taskbar use the helper's embedded
icon. The helper is unsigned, like the current local core artifact.

The test harness uses Python's standard library and compiles into a temporary
directory. It can be invoked on any platform; Windows execution tests skip where
the .NET Framework compiler is unavailable:

The Windows distribution workflow also runs these checks against its freshly
frozen onefile executable before building the MSI. Browser/UI interaction stays
a manual pilot check; automated checks suppress the browser and visible window.

```powershell
python packaging/windows/demo-launcher/test_launcher.py
$env:AEGIS_DEMO_TEST_EXE = 'I:\AEGIS-VERIFY\dist\windows-0.4.0\Onefile\aegis.exe'
python packaging/windows/demo-launcher/test_launcher.py
```

The opt-in real executable checks exercise paths with spaces and Unicode,
readiness against the real APIs, a collision on the engine's default port,
normal and forced termination, fresh sessions, preservation of existing files,
and survival of an unrelated process. The original executable's bytes are
checked before and after the suite. Tests open no browser or visible window and
never install an MSI.

For other automated Windows smoke checks, the helper accepts:

```text
AEGIS-Demo.exe --self-test <status.json> <stop-file> [--data-parent <existing-directory>]
```

This uses the same startup and cleanup path with UI and browser opening
suppressed. Status JSON is replaced atomically and includes `phase`, `url`,
`session`, `data`, `log`, `child_pids`, readiness counts and any error. Use a fresh
status path or remove an old status file before starting a new process. Once
`phase` is `ready`, create the stop file and wait for exit code 0; failures exit
with code 1. The optional existing data parent is available only with self-test
mode. The helper still creates a unique session below it and preserves it.
