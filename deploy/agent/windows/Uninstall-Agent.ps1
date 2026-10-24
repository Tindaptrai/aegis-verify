[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Install-Agent.ps1')
Assert-AgentAdministrator
$root = Join-Path $env:ProgramFiles 'AEGIS Agent'
$state = Join-Path $env:ProgramData 'AEGIS/Agent'
$service = Get-CimInstance Win32_Service -Filter "Name='AegisAgent'"
Assert-AgentServiceConfiguration $service (Join-Path $root 'bin/aegis-agent.exe') $state
if ($service) { Assert-AgentNativeServiceAcl }
$sid = Get-AgentServiceSid
Assert-AgentProtectedTree $root 'Binary' $sid
Assert-AgentProtectedTree $state 'State' $sid
Stop-AgentService
if ($service) { Invoke-AgentSc @('delete','AegisAgent') }
if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
Write-Output 'Agent service and binaries removed. Protected identity is preserved.'
