[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PackageRoot,[string]$ManagerOrigin,[string]$ServerCa)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'InstallerDiagnostics.ps1')
try {
    . (Join-Path $PackageRoot 'Install-Agent.ps1') -Manager $ManagerOrigin -ServerCa $ServerCa
    Install-AegisAgent $PackageRoot $ManagerOrigin $ServerCa
} catch {
    Write-AgentDiagnostic (Get-AgentErrorDiagnostic $_ 'installer')
    exit 1
}
