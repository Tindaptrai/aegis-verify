[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$StateDirectory,
    [Parameter(Mandatory=$true)][string]$ProfilePath,
    [Parameter(Mandatory=$true)][string]$GrantPath,
    [Parameter(Mandatory=$true)][string]$SigningPublicKeyPath,
    [switch]$VerifyOnly
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Install-Agent.ps1')
function Enable-AegisExecution([string]$StateDirectory,[string]$ProfilePath,[string]$GrantPath,[string]$SigningPublicKeyPath,[switch]$VerifyOnly) {
$controlLock=$null
try {
    Assert-AgentAdministrator
    $state=Join-Path $env:ProgramData 'AEGIS/Agent'
    if ([IO.Path]::GetFullPath($StateDirectory) -cne $state) { throw 'state_directory_mismatch' }
    $paths=Get-AgentExecutionPaths $ProfilePath $GrantPath $SigningPublicKeyPath
    $root=Join-Path $env:ProgramFiles 'AEGIS Agent'; $binary=Join-Path $root 'bin/aegis-agent.exe'
    $sid=Get-AgentServiceSid
    Assert-AgentServiceTreeAcl $root $sid 'Binary'
    Assert-AgentServiceTreeAcl $state $sid 'State'
    Assert-AgentNativeServiceAcl
    if ($VerifyOnly) {
        # Read-only verification intentionally requires a steady configuration;
        # it never creates the control directory, takes a write lock or recovers.
        $old=Get-AgentInstalledExecution
        $service=Get-CimInstance Win32_Service -Filter "Name='AegisAgent'"
        Assert-AgentServiceConfiguration $service $binary $state $old
        Invoke-AgentConfigurationCheck $binary $state $paths
        [Console]::Out.WriteLine('{"schema_version":1,"configuration_valid":true,"service_readiness":"not_evaluated","changed":false}')
        return
    }
    $control=Initialize-AgentControlRoot $sid
    $controlLock=Open-AgentControlLock $control
    $recordPath=Join-Path $control 'provisioning.json'
    $prior=Read-AgentControlRecord $recordPath
    if($prior){
        Assert-AgentProvisionRecord $prior
        if($prior.phase -eq 'prepared') { Restore-AgentProvision $binary $state $prior; throw 'provisioning_recovered_review_required' }
    }
    # A prepared transaction may legitimately have published only one of the
    # execution record and SCM command. Constrained recovery precedes this check.
    $old=Get-AgentInstalledExecution
    $service=Get-CimInstance Win32_Service -Filter "Name='AegisAgent'"
    Assert-AgentServiceConfiguration $service $binary $state $old
    # Reviewed files and their absolute pinned assets are prerequisites. Never
    # retarget paths or rewrite arbitrary source/OS ancestors to make them pass.
    Invoke-AgentConfigurationCheck $binary $state $paths
    if($prior){
        if((Get-AgentServiceCommand $binary $state $prior.new_execution) -cne (Get-AgentServiceCommand $binary $state $paths)){throw 'provisioning_revision_review_required'}
        foreach($entry in $prior.grants){if((Get-AgentSourceDescriptor $entry.kind $entry.name) -cne $entry.after){throw 'source_descriptor_conflict'}}
        [Console]::Out.WriteLine('{"schema_version":1,"configuration_valid":true,"service_readiness":"not_evaluated","changed":false}')
        return
    }
    $sysmon=if(Get-Service Sysmon64 -ErrorAction SilentlyContinue){'Sysmon64'}elseif(Get-Service Sysmon -ErrorAction SilentlyContinue){'Sysmon'}else{throw 'source_service_missing'}
    if(!(Get-Service WazuhSvc -ErrorAction SilentlyContinue)){throw 'source_service_missing'}
    $grants=@()
    foreach($target in @(@('service',$sysmon,4),@('service','WazuhSvc',4),@('channel','Microsoft-Windows-Sysmon/Operational',1),@('channel','Microsoft-Windows-PowerShell/Operational',1))){
        $before=Get-AgentSourceDescriptor $target[0] $target[1]
        $after=Get-AgentProvisionDescriptor $before $sid $target[2]
        $grants += [pscustomobject]@{kind=$target[0];name=$target[1];before=$before;after=$after}
    }
    $record=[pscustomobject]@{schema_version=1;phase='prepared';old_execution=$old;new_execution=$paths;was_running=[bool]($service.State -eq 'Running');grants=$grants}
    Assert-AgentProvisionRecord $record
    foreach($entry in $grants){Assert-AgentSourceMutationSupported $entry.kind $entry.name $entry.before $entry.after}
    Write-AgentControlRecord $recordPath $record
    try {
        Stop-AgentService
        Invoke-AgentSc @('config','AegisAgent','start=','disabled')
        foreach($entry in $grants){if($entry.before -cne $entry.after){Set-AgentSourceDescriptor $entry.kind $entry.name $entry.before $entry.after}}
        Invoke-AgentConfigurationCheck $binary $state $paths
        Write-AgentControlRecord (Join-Path $control 'execution.json') $paths
        Invoke-AgentSc @('config','AegisAgent','binPath=',(Get-AgentServiceCommand $binary $state $paths),'start=','delayed-auto')
        Assert-AgentServiceConfiguration (Get-CimInstance Win32_Service -Filter "Name='AegisAgent'") $binary $state $paths
        Start-Service AegisAgent; Wait-AgentRunning
        $record.phase='committed';Write-AgentControlRecord $recordPath $record
    } catch { Restore-AgentProvision $binary $state $record; throw }
    [Console]::Out.WriteLine('{"schema_version":1,"configuration_valid":true,"service_readiness":"not_evaluated","changed":true}')
} finally {if($controlLock){$controlLock.Dispose()}}
}
if ($MyInvocation.InvocationName -ne '.') {
try { Enable-AegisExecution -StateDirectory $StateDirectory -ProfilePath $ProfilePath -GrantPath $GrantPath -SigningPublicKeyPath $SigningPublicKeyPath -VerifyOnly:$VerifyOnly } catch {
    # The administrative result never publishes private inputs or native errors.
    [Console]::Error.WriteLine('{"schema_version":1,"code":"execution_provisioning_failed"}')
    exit 3
}
}
