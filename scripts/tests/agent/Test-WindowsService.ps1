# Disposable GitHub Windows runner only; invoke with Windows PowerShell 5.1.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Install','Restart','Reinstall','Status','Uninstall','ExecutionUpgrade','MissingVendor','Cleanup')][string]$Action,
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
    # The service can publish an acknowledgement while this helper checks its
    # identity. Share deletion so this reader cannot break atomic replacement.
    $stream = Open-AgentStateSnapshot $stateFile
    $reader = $null
    try {
        $reader = New-Object IO.StreamReader($stream)
        $snapshot = $reader.ReadToEnd() | ConvertFrom-Json
    } finally {
        if ($reader) { $reader.Dispose() }
        $stream.Dispose()
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($snapshot.private_key_pem)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToBase64String($hash.ComputeHash($bytes)) }
    finally { [Array]::Clear($bytes,0,$bytes.Length); $hash.Dispose(); $snapshot=$null }
}
function Assert-NativeConfiguration {
    $service = Get-CimInstance Win32_Service -Filter "Name='AegisAgent'"
    Assert-AgentServiceConfiguration $service $binary $stateDirectory (Get-AgentInstalledExecution)
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
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -File "' + (Join-Path $PSScriptRoot 'Invoke-WindowsInstallerDiagnostic.ps1') + '" -PackageRoot "' + $PackageRoot + '"'
    if ($ManagerOrigin) { $start.Arguments += ' -ManagerOrigin "' + $ManagerOrigin + '"' }
    if ($ServerCa) { $start.Arguments += ' -ServerCa "' + $ServerCa + '"' }
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    # Framework creates/flushes StandardInput using Console.InputEncoding during
    # Start; its UTF8 preamble would become invalid bytes before the pairing code.
    $inputEncoding=[Console]::InputEncoding
    try {
        [Console]::InputEncoding=New-Object Text.UTF8Encoding($false)
        $process = [Diagnostics.Process]::Start($start)
    } finally { [Console]::InputEncoding=$inputEncoding }
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
    $nativeMarker=$null
    if($env:AEGIS_EXECUTION_REQUIRE_NATIVE -eq '1'){
        if($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or (Test-Path -LiteralPath (Get-AgentControlRoot))){throw 'fresh_native_control_required'}
        $control=Initialize-AgentControlRoot (Get-AgentServiceSid)
        $nativeMarker=[pscustomobject]@{schema_version=1;fixture_id=[Guid]::NewGuid().ToString('N');before_absent=$true;device_id='pending';source_commit=$env:AEGIS_CONNECTION_SOURCE_COMMIT}
        Write-AgentControlRecord (Join-Path $control 'native-fixture.json') $nativeMarker
    }
    $code=[Console]::In.ReadLine()
    if ($code -cnotmatch '^[0-9a-f]{64}$') { throw 'synthetic_code_required_on_stdin' }
    try { Invoke-ClosedInstaller $code } finally { $code=$null }
    Assert-NativeConfiguration
    $status=Read-NativeStatus
    if($nativeMarker){$nativeMarker.device_id=$status.device_id;Write-AgentControlRecord (Join-Path (Get-AgentControlRoot) 'native-fixture.json') $nativeMarker}
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
    } elseif ($Action -eq 'MissingVendor') {
        if((Get-Service Sysmon -ErrorAction SilentlyContinue) -or (Get-Service Sysmon64 -ErrorAction SilentlyContinue) -or (Get-Service WazuhSvc -ErrorAction SilentlyContinue)){throw 'vendor_free_fixture_required'}
        $fixtureId=[Guid]::NewGuid().ToString('N')
        $assets=Join-Path $env:ProgramData ('AEGIS/ExecutionFixture-'+$fixtureId)
        $runs=Join-Path $stateDirectory ('runs-'+$fixtureId)
        $sid=Get-AgentServiceSid
        Stop-AgentService
        try {
            Assert-AgentNoLinks $assets;Assert-AgentNoLinks $runs
            if((Test-Path -LiteralPath $assets) -or (Test-Path -LiteralPath $runs)){throw 'fresh_fixture_required'}
            New-Item -ItemType Directory -Path $assets,$runs | Out-Null
            Set-AgentServiceTreeAcl $assets $sid 'Binary';Set-AgentServiceTreeAcl $runs $sid 'State'
            & $env:AEGIS_EXECUTION_NATIVE_TEST_EXE --provisioning-config $stateDirectory $assets $runs 2>$null | Out-Null
            if($LASTEXITCODE -ne 0){throw 'configuration_fixture_failed'}
            Set-AgentServiceTreeAcl $assets $sid 'Binary'
            $paths=Get-AgentExecutionPaths (Join-Path $assets 'profile.json') (Join-Path $assets 'installed-grant.json') (Join-Path $assets 'manager-execution-v2-public.pem')
            Invoke-AgentConfigurationCheck $binary $stateDirectory $paths
            Invoke-AgentSc @('config','AegisAgent','binPath=',(Get-AgentServiceCommand $binary $stateDirectory $paths))
            Start-Service AegisAgent;Wait-AgentRunning
            Start-Sleep -Seconds 17
        } finally {
            Stop-AgentService
            Invoke-AgentSc @('config','AegisAgent','binPath=',(Get-AgentServiceCommand $binary $stateDirectory))
            foreach($pair in @(@($assets,(Join-Path $env:ProgramData 'AEGIS'),('ExecutionFixture-'+$fixtureId)),@($runs,$stateDirectory,('runs-'+$fixtureId)))){
                $target=[IO.Path]::GetFullPath($pair[0]);if($target -cne (Join-Path $pair[1] $pair[2]) -or [IO.Path]::GetDirectoryName($target) -cne $pair[1]){throw 'fixture_cleanup_path_invalid'}
                Assert-AgentNoLinks $target;if(Test-Path -LiteralPath $target){Remove-Item -LiteralPath $target -Recurse -Force}
            }
            Start-Service AegisAgent;Wait-AgentRunning
        }
        $status=Read-NativeStatus
    } elseif ($Action -eq 'ExecutionUpgrade') {
        Stop-AgentService
        $identityBefore=(Get-FileHash -LiteralPath $stateFile -Algorithm SHA256).Hash
        & $env:AEGIS_EXECUTION_NATIVE_TEST_EXE --provisioning-journal $stateDirectory 2>$null | Out-Null
        if($LASTEXITCODE -ne 0){throw 'journal_fixture_failed'}
        Set-AgentServiceTreeAcl $stateDirectory (Get-AgentServiceSid) 'State'
        $journal=Join-Path $stateDirectory 'execution'
        $journalBefore=@{};foreach($file in Get-ChildItem -LiteralPath $journal -File){$journalBefore[$file.Name]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash}
        $sid=Get-AgentServiceSid;$control=Initialize-AgentControlRoot $sid
        foreach($phase in @('prepared','promoted')){
            $transactionId=[Guid]::NewGuid().ToString('N');$backup=$binaryRoot+'.backup-'+$transactionId
            Assert-AgentOwnedSibling $backup $binaryRoot 'backup' $transactionId
            $record=[pscustomobject]@{schema_version=1;id=$transactionId;phase=$phase;had_previous=$true;was_running=$false;command=(Get-AgentServiceCommand $binary $stateDirectory);start_mode='Auto';delayed=$true}
            Write-AgentControlRecord (Join-Path $control 'upgrade.json') $record
            Move-Item -LiteralPath $binaryRoot -Destination $backup
            if($phase -eq 'promoted'){New-Item -ItemType Directory -Path $binaryRoot | Out-Null;Set-AgentServiceTreeAcl $binaryRoot $sid 'Binary';[IO.File]::WriteAllText((Join-Path $binaryRoot 'incomplete'),'synthetic interrupted stage')}
            Restore-AgentUpgrade $binaryRoot $stateDirectory $sid $null
            if(!(Test-Path -LiteralPath $binary -PathType Leaf)){throw 'rollback_binary_missing'}
            if((Get-FileHash -LiteralPath $stateFile -Algorithm SHA256).Hash -cne $identityBefore){throw 'rollback_identity_changed'}
        }
        Invoke-ClosedInstaller $null
        Stop-AgentService
        foreach($file in Get-ChildItem -LiteralPath $journal -File){if(!$journalBefore.ContainsKey($file.Name) -or $journalBefore[$file.Name] -cne (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash){throw 'upgrade_journal_changed'}}
        if(@(Get-ChildItem -LiteralPath $journal -File).Count -ne $journalBefore.Count){throw 'upgrade_journal_lost'}
        if((Read-NativeStatus).device_id -cne $ExpectedDeviceId){throw 'upgrade_identity_changed'}
        Assert-AgentStoppedJournal $binary $stateDirectory
        Start-Service AegisAgent;Wait-AgentRunning
        $status=Read-NativeStatus
    } elseif ($Action -eq 'Uninstall') {
        Stop-AgentService
        $before=(Get-FileHash -LiteralPath $stateFile -Algorithm SHA256).Hash
        & (Join-Path $PackageRoot 'Uninstall-Agent.ps1') | Out-Null
        if ((Get-Service AegisAgent -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $binaryRoot)) { throw 'uninstall_left_service_or_binary' }
        if ((Get-FileHash -LiteralPath $stateFile -Algorithm SHA256).Hash -cne $before) { throw 'uninstall_changed_identity' }
    } elseif ($Action -eq 'Cleanup') {
        if((Get-Service AegisAgent -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $binaryRoot)){throw 'ci_cleanup_requires_uninstalled'}
        $marker=Read-AgentControlRecord (Join-Path (Get-AgentControlRoot) 'native-fixture.json')
        Assert-AgentClosedRecord $marker @('schema_version','fixture_id','before_absent','device_id','source_commit')
        if($env:AEGIS_EXECUTION_REQUIRE_NATIVE -ne '1' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $marker.schema_version -ne 1 -or $marker.fixture_id -cnotmatch '^[0-9a-f]{32}$' -or $marker.before_absent -isnot [bool] -or !$marker.before_absent -or $marker.device_id -cne $ExpectedDeviceId -or $marker.source_commit -cne $env:AEGIS_CONNECTION_SOURCE_COMMIT){throw 'ci_cleanup_ownership_invalid'}
        foreach($target in @($stateDirectory,(Get-AgentControlRoot))){
            if([IO.Path]::GetFullPath($target) -cnotin @((Join-Path $env:ProgramData 'AEGIS/Agent'),(Join-Path $env:ProgramData 'AEGIS/AgentControl'))){throw 'ci_cleanup_path_invalid'}
            Assert-AgentNoLinks $target
            if(Test-Path -LiteralPath $target){Remove-Item -LiteralPath $target -Recurse -Force}
        }
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
