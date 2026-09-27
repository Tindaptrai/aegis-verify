"""Create private evidence directories without relying on Windows mkdir mode."""

import base64
import os
from pathlib import Path
import subprocess


_WINDOWS_PRIVATE_ACL = """
$ErrorActionPreference = 'Stop'
$path = $env:AEGIS_PRIVATE_DIRECTORY_PATH
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$existing = [System.IO.Directory]::GetAccessControl($path)
if ($existing.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) {
    throw 'private directory owner differs from operator'
}
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
[System.IO.Directory]::SetAccessControl($path, $acl)
$actual = [System.IO.Directory]::GetAccessControl($path)
$rules = @($actual.GetAccessRules(
    $true, $true, [System.Security.Principal.SecurityIdentifier]))
if ($actual.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or
    $rules.Count -ne 1 -or
    $rules[0].IdentityReference.Value -ne $sid.Value -or
    $rules[0].AccessControlType -ne 'Allow' -or
    ([int]$rules[0].FileSystemRights -band 2032127) -ne 2032127 -or
    [int]$rules[0].InheritanceFlags -ne 3 -or
    [int]$rules[0].PropagationFlags -ne 0) {
    throw 'private directory ACL verification failed'
}
"""


def mkdir_private(path, *, exist_ok=False):
    """Create one directory; never repair or broaden an existing directory."""
    target = Path(path)
    try:
        target.mkdir(mode=0o700)
    except FileExistsError:
        if exist_ok and target.is_dir():
            return target
        raise
    if os.name == 'nt':
        executable = Path(os.environ.get('SystemRoot', '')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        try:
            subprocess.run(
                [str(executable), '-NoLogo', '-NoProfile', '-NonInteractive',
                 '-EncodedCommand', base64.b64encode(_WINDOWS_PRIVATE_ACL.encode('utf-16le')).decode('ascii')],
                env={**os.environ, 'AEGIS_PRIVATE_DIRECTORY_PATH': str(target)},
                capture_output=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=True,
            )
        except (OSError, subprocess.SubprocessError):
            raise OSError('private_directory_acl_failed') from None
    return target
