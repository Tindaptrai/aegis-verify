[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PackageRoot,[string]$ManagerOrigin,[string]$ServerCa)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'InstallerDiagnostics.ps1')
try {
    . (Join-Path $PackageRoot 'Install-Agent.ps1') -Manager $ManagerOrigin -ServerCa $ServerCa
    $Error.Clear()
    Install-AegisAgent $PackageRoot $ManagerOrigin $ServerCa
} catch {
    $failure=$_; $history=@($Error)
    Write-AgentDiagnostic (Get-AgentFirstFailureDiagnostic $history $failure 'installer')
    exit 1
}
