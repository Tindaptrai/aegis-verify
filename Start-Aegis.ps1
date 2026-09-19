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
    [string]$OperationsConfig
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
# The server itself binds the port again; a race is reported by the existing CLI.
& $pythonExecutable -u -m aegis_verify dashboard --reports $reportDirectory --static $staticDirectory --host 127.0.0.1 --port $Port @operationsArguments
exit $LASTEXITCODE
