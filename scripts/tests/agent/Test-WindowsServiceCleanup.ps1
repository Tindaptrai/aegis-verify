# Run only extracted helper/control flow with inert OS boundaries. No installed paths are touched.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'InstallerDiagnostics.ps1')
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-WindowsService.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'cleanup_contract_parse_failed'}
$read=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Read-NativeStatus'},$false)
. ([scriptblock]::Create($read.Extent.Text))
$realReadStatus=${function:Read-NativeStatus}
$actions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -ceq '$Action -eq ''Install'''},$false))
if($actions.Count -ne 1){throw 'cleanup_contract_actions_missing'}
$actionBlock=[scriptblock]::Create($actions[0].Extent.Text)
$installer=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'deploy/agent/windows/Install-Agent.ps1'),[ref]$tokens,[ref]$errors)
$closed=$installer.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-AgentClosedRecord'},$false)
. ([scriptblock]::Create($closed.Extent.Text))
$PackageRoot=Join-Path $repo 'synthetic-unopened-package'
$binaryRoot=Join-Path $env:ProgramFiles 'AEGIS Agent'
$binary=Join-Path $binaryRoot 'bin/aegis-agent.exe'
$stateDirectory=Join-Path $env:ProgramData 'AEGIS/Agent'
$expectedIdentity='c7e227eb-3bf6-4e49-905b-c1c034b7be46'
function Get-AgentControlRoot { return (Join-Path $env:ProgramData 'AEGIS/AgentControl') }
function Get-Service { if($case -ceq 'service_present'){return [pscustomobject]@{Status='Running'}} }
function Test-Path([string]$LiteralPath) { return ($LiteralPath -cne $binaryRoot -or $case -ceq 'binary_present') }
function Assert-AgentNoLinks {}
function Remove-Item([string]$LiteralPath,[switch]$Recurse,[switch]$Force) {
    if(!$Recurse -or !$Force -or $LiteralPath -cnotin @($stateDirectory,(Get-AgentControlRoot))){throw 'cleanup_contract_unexpected_delete'}
    $script:removed+=@($LiteralPath)
}
function Get-VerifiedAgentPackage([string]$Root) {
    if($Root -cne $PackageRoot){throw 'cleanup_contract_wrong_package'}
    $script:verified++
    if($case -ceq 'package_rejected'){throw 'synthetic_package_rejected'}
    return 'synthetic_verified_entry'
}
function Get-SyntheticStatus {
    if(($args -join '|') -cne ('status|--state-dir|'+$stateDirectory)){throw 'cleanup_contract_wrong_status_arguments'}
    $global:LASTEXITCODE=0
    $identity=if($case -ceq 'identity_conflict'){'6c2d47c2-1dd5-4235-a4ce-114679e0332f'}else{$expectedIdentity}
    [pscustomobject]@{device_id=$identity;state='enrolled'}|ConvertTo-Json -Compress
}
function Invoke-NativeStatusCommand([string]$Executable,[string]$StateDirectory) {
    $json=& $Executable status --state-dir $StateDirectory
    return @{stdout=($json -join "`n");stderr='';exit_code=$global:LASTEXITCODE}
}
function Read-NativeStatus([string]$Executable=$binary) {
    $script:statusReads++
    if($Action -ceq 'Cleanup'){
        if($Executable -cne (Join-Path $PackageRoot 'bin/aegis-agent.exe') -or $script:verified -ne 1){throw 'cleanup_contract_removed_binary_invoked'}
    } elseif($Executable -cne $binary -or $script:verified){throw 'cleanup_contract_status_source_changed'}
    return (& $realReadStatus -Executable 'Get-SyntheticStatus')
}
function Read-AgentControlRecord([string]$Path) {
    if($Path -cne (Join-Path (Get-AgentControlRoot) 'native-fixture.json')){throw 'cleanup_contract_wrong_marker'}
    $source=if($case -ceq 'marker_conflict'){'b'*40}else{'a'*40}
    return [pscustomobject]@{schema_version=1;fixture_id=('c'*32);before_absent=$true;device_id=$expectedIdentity;source_commit=$source}
}
$saved=@{};foreach($name in @('AEGIS_EXECUTION_REQUIRE_NATIVE','RUNNER_ENVIRONMENT','AEGIS_CONNECTION_SOURCE_COMMIT')){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
$checks=0
try {
    $env:AEGIS_EXECUTION_REQUIRE_NATIVE='1';$env:RUNNER_ENVIRONMENT='github-hosted';$env:AEGIS_CONNECTION_SOURCE_COMMIT='a'*40
    foreach($case in @('success','package_rejected','identity_conflict','marker_conflict','service_present','binary_present','missing_identity','status')){
        $Action=if($case -ceq 'status'){'Status'}else{'Cleanup'}
        $ExpectedDeviceId=if($case -ceq 'missing_identity'){$null}else{$expectedIdentity}
        $script:verified=0;$script:statusReads=0;$script:removed=@();$status=$null;$failure=$null
        try {. $actionBlock} catch {$failure=$_.Exception.Message}
        $expectedFailure=switch($case){package_rejected {'synthetic_package_rejected'} identity_conflict {'ci_identity_conflict'} marker_conflict {'ci_cleanup_ownership_invalid'} service_present {'ci_cleanup_requires_uninstalled'} binary_present {'ci_cleanup_requires_uninstalled'} missing_identity {'expected_device_id_required_for_mutation'} default {$null}}
        if($failure -cne $expectedFailure){throw ('cleanup_contract_failed case='+$case+' code='+$failure)}
        if($case -ceq 'success'){
            if($script:removed.Count -ne 2 -or $status.device_id -cne $expectedIdentity -or $status.state -cne 'enrolled'){throw 'cleanup_contract_result_invalid'}
        } elseif($script:removed.Count){throw 'cleanup_contract_refusal_mutated'}
        if($case -ceq 'status' -and ($script:verified -ne 0 -or $status.device_id -cne $expectedIdentity)){throw 'cleanup_contract_existing_status_changed'}
        $checks++
    }
    Write-Output "$checks Windows service cleanup contracts passed"
} finally {foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}}
