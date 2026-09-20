#Requires -Version 5.1
<#
.SYNOPSIS
Start the existing read-only AEGIS dashboard on loopback. No installs or lab actions.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Reports,
    [ValidateRange(1, 65535)]
    [int]$Port = 8766,
    [ValidateNotNullOrEmpty()]
    [string]$PythonPath,
    [ValidateNotNullOrEmpty()]
    [string]$OperationsConfig,
    [ValidateSet('Inventory', 'Collections', 'Both')]
    [string]$PromptCredentials
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('PythonPath')) {
    $PythonPath = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
}

function Stop-AegisLaunch([string]$Code, [string]$Hint) {
    Write-Output "AEGIS: $Code - $Hint"
    exit 1
}

if ($PSBoundParameters.ContainsKey('PromptCredentials') -and -not $PSBoundParameters.ContainsKey('OperationsConfig')) {
    Stop-AegisLaunch 'operations_config_required' 'Credential prompts require -OperationsConfig.'
}

# Reject network/provider syntax before Test-Path can access a remote filesystem.
$localCandidates = @($Reports, $PythonPath)
if ($PSBoundParameters.ContainsKey('OperationsConfig')) { $localCandidates += $OperationsConfig }
foreach ($candidate in $localCandidates) {
    $normalized = $candidate.Replace('\', '/')
    $driveAbsolute = $normalized -match '^[A-Za-z]:/'
    if ($normalized.StartsWith('//') -or $normalized.Contains('::') -or
        ($normalized.Contains(':') -and -not $driveAbsolute)) {
        Stop-AegisLaunch 'local_path_required' 'Use local filesystem paths, not network shares, URLs or provider paths.'
    }
    if ($normalized.IndexOfAny([char[]]'*?[]') -ge 0) {
        Stop-AegisLaunch 'invalid_path' 'Wildcard characters are not accepted in local paths.'
    }
}

if ($PSBoundParameters.ContainsKey('OperationsConfig') -and -not (Test-Path -LiteralPath $OperationsConfig -PathType Leaf)) {
    Stop-AegisLaunch 'operations_config_missing' 'Choose an existing private local JSON file with -OperationsConfig.'
}
if (-not (Test-Path -LiteralPath $Reports -PathType Container)) {
    Stop-AegisLaunch 'reports_missing' 'Choose an existing reviewed report directory with -Reports.'
}
if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    Stop-AegisLaunch 'python_missing' 'Prepare the project .venv or supply -PythonPath with an installed AEGIS Python.'
}
$reportDirectory = $Reports
$pythonExecutable = (Resolve-Path -LiteralPath $PythonPath).ProviderPath
$staticDirectory = Join-Path $PSScriptRoot 'frontend/dist'
if (-not (Test-Path -LiteralPath (Join-Path $staticDirectory 'index.html') -PathType Leaf)) {
    Stop-AegisLaunch 'build_missing' 'In frontend, run npm ci then npm run build. Nothing was installed automatically.'
}

try {
    & $pythonExecutable -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 10)' 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Stop-AegisLaunch 'python_unsupported' 'Python 3.11 or newer is required.'
    }
    & $pythonExecutable -c 'from aegis_verify.dashboard import make_server' 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Stop-AegisLaunch 'package_missing' 'Install the project into the selected Python environment first; see docs/V1_HANDOFF.md.'
    }
} catch {
    Stop-AegisLaunch 'python_environment_invalid' 'Check the selected Python and AEGIS installation; no environment was changed.'
}

$probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
try {
    $probe.ExclusiveAddressUse = $true
    $probe.Start()
} catch {
    Stop-AegisLaunch 'port_unavailable' 'Choose another -Port or stop your own existing dashboard. No process was stopped.'
} finally {
    $probe.Stop()
}

$operationsArguments = @()
if ($PSBoundParameters.ContainsKey('OperationsConfig')) {
    $operationsArguments = @('--operations-config', $OperationsConfig)
    Write-Output "AEGIS: http://127.0.0.1:$Port/ - opt-in operations; Ctrl+C drains active work. No scenario will run."
} else {
    Write-Output "AEGIS: http://127.0.0.1:$Port/ - read-only reports; Ctrl+C to stop. No scenario will run."
}
if (-not $PSBoundParameters.ContainsKey('PromptCredentials')) {
    # Preserve the existing environment-driven path without prompting or changing credentials.
    & $pythonExecutable -u -m aegis_verify dashboard --reports $reportDirectory --static $staticDirectory --host 127.0.0.1 --port $Port @operationsArguments
    exit $LASTEXITCODE
}

$credentialNames = @('WAZUH_API_USERNAME', 'WAZUH_API_PASSWORD', 'WAZUH_INDEXER_USERNAME', 'WAZUH_INDEXER_PASSWORD')
$savedEnvironment = @{}
foreach ($name in $credentialNames) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$securePassword = $null
$credential = $null
$exitCode = 1
$stage = 'credential_input_failed'
try {
    # An unselected source must not inherit an unrelated credential from the caller.
    foreach ($name in $credentialNames) { Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
    $sources = @()
    if ($PromptCredentials -in @('Inventory', 'Both')) {
        $sources += @{ Label = 'Server API (inventory)'; Prefix = 'WAZUH_API' }
    }
    if ($PromptCredentials -in @('Collections', 'Both')) {
        $sources += @{ Label = 'Indexer (collections; separate account)'; Prefix = 'WAZUH_INDEXER' }
    }
    Write-Output 'AEGIS: Enter credentials in this terminal. Password input is hidden; Ctrl+C cancels. No source authentication or collection is performed at startup.'
    foreach ($source in $sources) {
        $username = Read-Host ($source.Label + ' username')
        if ([string]::IsNullOrWhiteSpace($username)) { throw 'Invalid credential input' }
        $securePassword = Read-Host ($source.Label + ' password') -AsSecureString
        if ($null -eq $securePassword -or $securePassword.Length -eq 0) { throw 'Invalid credential input' }
        $credential = [System.Management.Automation.PSCredential]::new($username, $securePassword)
        [Environment]::SetEnvironmentVariable(($source.Prefix + '_USERNAME'), $credential.UserName, 'Process')
        [Environment]::SetEnvironmentVariable(($source.Prefix + '_PASSWORD'), $credential.GetNetworkCredential().Password, 'Process')
        $credential = $null
        $securePassword.Dispose()
        $securePassword = $null
    }
    $stage = 'launcher_start_failed'
    # The server binds again; the existing CLI reports a port race or invalid config.
    & $pythonExecutable -u -m aegis_verify dashboard --reports $reportDirectory --static $staticDirectory --host 127.0.0.1 --port $Port @operationsArguments
    $exitCode = $LASTEXITCODE
} catch {
    # Never print an exception containing credential input or process environment.
    Write-Output "AEGIS: $stage - Input cancelled/invalid or startup failed. No automatic retry; check configuration and retry explicitly."
} finally {
    $credential = $null
    if ($null -ne $securePassword) { $securePassword.Dispose() }
    foreach ($name in $credentialNames) {
        if ($null -eq $savedEnvironment[$name]) {
            Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        } else {
            [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
        }
    }
    $savedEnvironment.Clear()
}
exit $exitCode
