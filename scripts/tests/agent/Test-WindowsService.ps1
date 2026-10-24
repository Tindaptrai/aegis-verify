# Disposable GitHub Windows runner only; invoke with Windows PowerShell 5.1.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Install','Restart','Reinstall','Status','Uninstall')][string]$Action,
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [string]$ManagerOrigin,[string]$ServerCa,[string]$ExpectedDeviceId
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'InstallerDiagnostics.ps1')
$script:AgentInnerDiagnostic=$null
try {
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') { throw 'disposable_windows_ci_required' }
. (Join-Path $PackageRoot 'Install-Agent.ps1') -Manager $ManagerOrigin -ServerCa $ServerCa
Assert-AgentAdministrator
$binaryRoot = Join-Path $env:ProgramFiles 'AEGIS Agent'
$stateDirectory = Join-Path $env:ProgramData 'AEGIS/Agent'
$binary = Join-Path $binaryRoot 'bin/aegis-agent.exe'
$stateFile = Join-Path $stateDirectory 'state.json'
function Read-NativeStatus {
    $json = & $binary status --state-dir $stateDirectory
    if ($LASTEXITCODE -ne 0) { throw 'status_failed' }
    $value = $json | ConvertFrom-Json
    if ($ExpectedDeviceId -and $value.device_id -cne $ExpectedDeviceId) { throw 'ci_identity_conflict' }
    return $value
}
function Get-NativeKeyHash {
    $snapshot = [IO.File]::ReadAllText($stateFile) | ConvertFrom-Json
    $bytes = [Text.Encoding]::UTF8.GetBytes($snapshot.private_key_pem)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToBase64String($hash.ComputeHash($bytes)) }
    finally { [Array]::Clear($bytes,0,$bytes.Length); $hash.Dispose(); $snapshot=$null }
}
function Assert-NativeConfiguration {
    $service = Get-CimInstance Win32_Service -Filter "Name='AegisAgent'"
    Assert-AgentServiceConfiguration $service $binary $stateDirectory
    if (!$service) { throw 'ci_service_missing' }
    $sid = Get-AgentServiceSid
    Assert-AgentServiceTreeAcl $binaryRoot $sid 'Binary'
    Assert-AgentServiceTreeAcl $stateDirectory $sid 'State'
    Assert-AgentNativeServiceAcl
    if ($service.StartMode -ne 'Auto' -or !(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AegisAgent').DelayedAutoStart) { throw 'autostart_not_configured' }
}
function Invoke-ClosedInstaller([string]$Code) {
    foreach ($value in @($PackageRoot,$ManagerOrigin,$ServerCa)) { if ($value -and $value.Contains('"')) { throw 'invalid_test_argument' } }
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $start.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot 'Invoke-WindowsInstallerDiagnostic.ps1') + '" -PackageRoot "' + $PackageRoot + '"'
    if ($ManagerOrigin) { $start.Arguments += ' -ManagerOrigin "' + $ManagerOrigin + '"' }
    if ($ServerCa) { $start.Arguments += ' -ServerCa "' + $ServerCa + '"' }
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $process = [Diagnostics.Process]::Start($start)
    $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
    if ($Code) { $process.StandardInput.WriteLine($Code) }
    $process.StandardInput.Close()
    if (!$process.WaitForExit(90000)) { $process.Kill(); throw 'installer_timeout' }
    $output=$stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
    $diagnostic=Get-AgentCapturedDiagnostic $output $Code 'installer'
    if ($diagnostic.code -eq 'installer_output_secret_leak' -or $process.ExitCode -ne 0) { $script:AgentInnerDiagnostic=$diagnostic; throw 'native_installer_failed' }
}
function Assert-NativeOwnerConflict {
    # Only the disposable CI phase may alter the service owner. Production only
    # sets a fixed administrative owner immediately after creating a new service.
    if (!('Aegis.Agent.Tests.ServiceOwner' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
namespace Aegis.Agent.Tests {
    public static class ServiceOwner {
        [DllImport("advapi32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern IntPtr OpenSCManagerW(string machine,string database,uint access);
        [DllImport("advapi32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern IntPtr OpenServiceW(IntPtr manager,string name,uint access);
        [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetServiceObjectSecurity(IntPtr service,uint information,byte[] descriptor);
        [DllImport("advapi32.dll", ExactSpelling=true)]
        [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr handle);
        public static void Set(string owner) {
            IntPtr manager=IntPtr.Zero,service=IntPtr.Zero;
            try {
                manager=OpenSCManagerW(null,null,1);
                if (manager==IntPtr.Zero) throw new InvalidOperationException("ci_owner_setup_failed");
                service=OpenServiceW(manager,"AegisAgent",0x80000);
                if (service==IntPtr.Zero) throw new InvalidOperationException("ci_owner_setup_failed");
                RawSecurityDescriptor descriptor=new RawSecurityDescriptor("O:"+owner);
                byte[] bytes=new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes,0);
                if (!SetServiceObjectSecurity(service,1,bytes)) throw new InvalidOperationException("ci_owner_setup_failed");
            } finally {
                if (service!=IntPtr.Zero) CloseServiceHandle(service);
                if (manager!=IntPtr.Zero) CloseServiceHandle(manager);
            }
        }
    }
}
'@
    }
    $original = New-Object Security.AccessControl.CommonSecurityDescriptor($false,$false,(Get-AgentNativeServiceSecurity))
    $owner = $original.Owner.Value
    $before = (Get-FileHash -LiteralPath $stateFile -Algorithm SHA256).Hash
    $beforeCommand = (Get-CimInstance Win32_Service -Filter "Name='AegisAgent'").PathName
    try {
        [Aegis.Agent.Tests.ServiceOwner]::Set([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
        $refused=$false
        try { Install-AegisAgent $PackageRoot $null $null } catch { if ($_.Exception.Message -eq 'service_owner_invalid') { $refused=$true } else { throw } }
        if (!$refused) { throw 'untrusted_service_owner_installer_accepted' }
        $refused=$false
        try { & (Join-Path $PackageRoot 'Uninstall-Agent.ps1') | Out-Null } catch { if ($_.Exception.Message -eq 'service_owner_invalid') { $refused=$true } else { throw } }
        if (!$refused) { throw 'untrusted_service_owner_uninstaller_accepted' }
        if ((Get-FileHash -LiteralPath $stateFile -Algorithm SHA256).Hash -cne $before -or (Get-CimInstance Win32_Service -Filter "Name='AegisAgent'").PathName -cne $beforeCommand) { throw 'owner_conflict_changed_installation' }
    } finally { [Aegis.Agent.Tests.ServiceOwner]::Set($owner) }
    Assert-AgentNativeServiceAcl
}
if ($Action -eq 'Install') {
    if ((Get-Service AegisAgent -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $binaryRoot) -or (Test-Path -LiteralPath $stateDirectory)) { throw 'ci_target_already_exists' }
    if (!$ManagerOrigin -or !$ServerCa) { throw 'manager_and_server_ca_required' }
    $code=[Console]::In.ReadLine()
    if ($code -cnotmatch '^[0-9a-f]{64}$') { throw 'synthetic_code_required_on_stdin' }
    try { Invoke-ClosedInstaller $code } finally { $code=$null }
    Assert-NativeConfiguration
    $status=Read-NativeStatus
} else {
    if ($Action -ne 'Status' -and !$ExpectedDeviceId) { throw 'expected_device_id_required_for_mutation' }
    $status=Read-NativeStatus
    if ($Action -eq 'Restart' -or $Action -eq 'Reinstall') {
        $id=$status.device_id; $keyHash=Get-NativeKeyHash
        $watch=[Diagnostics.Stopwatch]::StartNew()
        Stop-AgentService
        if ($watch.Elapsed.TotalSeconds -ge 20) { throw 'service_stop_deadline_exceeded' }
        if ($Action -eq 'Restart') { Start-Service AegisAgent; Wait-AgentRunning }
        else { Assert-NativeOwnerConflict; Invoke-ClosedInstaller $null }
        Assert-NativeConfiguration
        $status=Read-NativeStatus
        if ($status.device_id -cne $id -or (Get-NativeKeyHash) -cne $keyHash) { throw 'restart_or_reinstall_changed_identity' }
    } elseif ($Action -eq 'Uninstall') {
        Stop-AgentService
        $before=(Get-FileHash -LiteralPath $stateFile -Algorithm SHA256).Hash
        & (Join-Path $PackageRoot 'Uninstall-Agent.ps1') | Out-Null
        if ((Get-Service AegisAgent -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $binaryRoot)) { throw 'uninstall_left_service_or_binary' }
        if ((Get-FileHash -LiteralPath $stateFile -Algorithm SHA256).Hash -cne $before) { throw 'uninstall_changed_identity' }
    }
}
$service=Get-Service AegisAgent -ErrorAction SilentlyContinue
$serviceStatus=if ($service) { [string]$service.Status } else { 'absent' }
[pscustomobject]@{action=$Action;device_id=$status.device_id;state=$status.state;service_status=$serviceStatus;identity_preserved=$true} | ConvertTo-Json -Compress
} catch {
    if ($script:AgentInnerDiagnostic) { Write-AgentDiagnostic $script:AgentInnerDiagnostic }
    else { Write-AgentDiagnostic (Get-AgentErrorDiagnostic $_ 'helper') }
    exit 1
}
