# Closed diagnostic vocabulary shared with the Python native gate. Never echo input.
$script:AgentDiagnosticCodes = [IO.File]::ReadAllLines((Join-Path $PSScriptRoot 'native-diagnostic-codes.txt'))
function Test-AgentDiagnosticCode([string]$Code) {
    if ($script:AgentDiagnosticCodes -ccontains $Code) { return $true }
    $number=0
    if ($Code -cmatch '^win32_(0|[1-9][0-9]{0,4})$') { return [int]::TryParse($Matches[1],[ref]$number) -and $number -le 65535 }
    if ($Code -cmatch '^hresult_(0|-?[1-9][0-9]{0,9})$') { return [int]::TryParse($Matches[1],[ref]$number) }
    return $false
}
function Test-AgentDiagnosticStage([string]$Stage) { return @('preflight','installer','configuration','status','restart','uninstall','owner_conflict','helper') -ccontains $Stage }
function Get-AgentCapturedDiagnostic([string]$Output,[string]$Secret,[string]$Stage) {
    if (!(Test-AgentDiagnosticStage $Stage)) { $Stage='helper' }
    if (($Secret -and $Output.Contains($Secret)) -or $Output.Contains('PRIVATE KEY') -or $Output.Contains('csr_pem')) { return @{stage='helper';code='installer_output_secret_leak'} }
    $result=@{stage=$Stage;code='diagnostic_unknown'}
    if ($Output.Length -gt 65536) { return $result }
    foreach ($line in $Output.Split(@("`r`n","`n"),[StringSplitOptions]::None)) {
        $candidate=$null; $candidateStage=$Stage
        if (Test-AgentDiagnosticCode $line) { $candidate=$line }
        elseif ($line -cmatch '^\{"error":\{"code":"([a-z_]+)"\}\}$') { $candidate=$Matches[1] }
        elseif ($line -cmatch '^\{"stage":"([a-z_]+)","code":"([a-z0-9_-]+)"\}$') { $candidateStage=$Matches[1]; $candidate=$Matches[2] }
        if ($candidate -and (Test-AgentDiagnosticStage $candidateStage) -and (Test-AgentDiagnosticCode $candidate)) { $result=@{stage=$candidateStage;code=$candidate}; break }
    }
    return $result
}
function Get-AgentErrorDiagnostic([Management.Automation.ErrorRecord]$Record,[string]$Stage) {
    if (!(Test-AgentDiagnosticStage $Stage)) { $Stage='helper' }
    $stageMap=@{
        'Get-VerifiedAgentPackage'='preflight'; 'Assert-AgentNoLinks'='preflight';
        'Assert-AgentProtectedTree'='preflight'; 'Assert-AgentServiceConfiguration'='preflight';
        'Assert-AgentNativeServiceAcl'='configuration'; 'Get-AgentNativeServiceSecurity'='configuration';
        'Set-AgentServiceTreeAcl'='configuration'; 'Set-AgentDirectoryAcl'='configuration';
        'Assert-AgentPinnedConfiguration'='configuration'; 'Invoke-AgentSc'='configuration';
        'Invoke-AgentEnrollment'='installer'; 'Wait-AgentRunning'='restart'; 'Stop-AgentService'='restart';
        'Read-NativeStatus'='status'; 'Assert-NativeOwnerConflict'='owner_conflict'
    }
    foreach ($frame in $Record.ScriptStackTrace.Split("`n")) {
        if ($frame -match '^at ([A-Za-z-]+),') { if ($stageMap.ContainsKey($Matches[1])) { $Stage=$stageMap[$Matches[1]]; break } }
    }
    $exception=$Record.Exception; $last=$exception
    while ($exception) {
        if (Test-AgentDiagnosticCode $exception.Message) { return @{stage=$Stage;code=$exception.Message} }
        $messageDiagnostic=Get-AgentCapturedDiagnostic $exception.Message '' $Stage
        if ($messageDiagnostic.code -ne 'diagnostic_unknown') { return $messageDiagnostic }
        $last=$exception; $exception=$exception.InnerException
    }
    if ($last -is [ComponentModel.Win32Exception] -and $last.NativeErrorCode -ge 0 -and $last.NativeErrorCode -le 65535) { return @{stage=$Stage;code=('win32_' + $last.NativeErrorCode)} }
    $types=@{
        'System.UnauthorizedAccessException'='exception_unauthorizedaccess'; 'System.IO.IOException'='exception_io';
        'System.ComponentModel.Win32Exception'='exception_win32'; 'System.InvalidOperationException'='exception_invalidoperation';
        'System.ArgumentException'='exception_argument'; 'System.Security.Cryptography.CryptographicException'='exception_cryptographic';
        'System.Management.Automation.MethodInvocationException'='exception_methodinvocation';
        'System.Management.Automation.RuntimeException'='exception_runtime'
    }
    if ($types.ContainsKey($last.GetType().FullName)) { return @{stage=$Stage;code=('hresult_' + $last.HResult)} }
    return @{stage=$Stage;code='diagnostic_unknown'}
}
function Write-AgentDiagnostic($Diagnostic) {
    # Explicit property order for the cross-platform exact-line parser.
    [Console]::Error.WriteLine('{"stage":"' + $Diagnostic.stage + '","code":"' + $Diagnostic.code + '"}')
}
