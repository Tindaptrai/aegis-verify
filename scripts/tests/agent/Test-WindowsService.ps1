# Disposable GitHub Windows runner only; invoke with Windows PowerShell 5.1.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Install','Restart','Reinstall','Status','Uninstall')][string]$Action,
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [string]$ManagerOrigin,[string]$ServerCa,[string]$ExpectedDeviceId
)
$ErrorActionPreference = 'Stop'
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
    $start.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PackageRoot 'Install-Agent.ps1') + '"'
    if ($ManagerOrigin) { $start.Arguments += ' -Manager "' + $ManagerOrigin + '"' }
    if ($ServerCa) { $start.Arguments += ' -ServerCa "' + $ServerCa + '"' }
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $process = [Diagnostics.Process]::Start($start)
    $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
    if ($Code) { $process.StandardInput.WriteLine($Code) }
    $process.StandardInput.Close()
    if (!$process.WaitForExit(90000)) { $process.Kill(); throw 'installer_timeout' }
    $output=$stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
    if (($Code -and $output.Contains($Code)) -or $output.Contains('PRIVATE KEY') -or $output.Contains('csr_pem')) { throw 'installer_output_secret_leak' }
    if ($process.ExitCode -ne 0) { throw 'native_installer_failed' }
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
        else { Invoke-ClosedInstaller $null }
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
