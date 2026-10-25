# Run without elevation: these contracts use temporary files and never call SCM.
[CmdletBinding()]
param([switch]$Pure)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$installer = Join-Path $repo 'deploy/agent/windows/Install-Agent.ps1'
if (!(Test-Path -LiteralPath $installer)) { throw 'RED: Windows installer contract is not implemented' }
. $installer
if ($Pure) {
    $checks = 0
    function Check-Pure([bool]$Condition) { if (!$Condition) { throw 'pure_contract_failed' }; $script:checks++ }
    function Reject-Pure([scriptblock]$Action) { $rejected=$false; try { & $Action | Out-Null } catch { $rejected=$true }; Check-Pure $rejected }
    Check-Pure ($null -eq (Get-AgentExecutionPaths $null $null $null))
    Reject-Pure { Get-AgentExecutionPaths 'C:\Reviewed\profile.json' $null $null }
    Reject-Pure { Get-AgentExecutionPaths 'C:\Reviewed\profile.json' 'C:\Reviewed\installed-grant.json' 'C:\Reviewed\private.pem' }
    Reject-Pure { Get-AgentExecutionPaths 'C:\Reviewed\..\profile.json' 'C:\Reviewed\installed-grant.json' 'C:\Reviewed\manager-execution-v2-public.pem' }
    $paths = Get-AgentExecutionPaths 'C:\Reviewed\profile.json' 'C:\Reviewed\installed-grant.json' 'C:\Reviewed\manager-execution-v2-public.pem'
    $command = Get-AgentServiceCommand 'C:\Program Files\AEGIS Agent\bin\aegis-agent.exe' 'C:\ProgramData\AEGIS\Agent' $paths
    Check-Pure ($command -ceq '"C:\Program Files\AEGIS Agent\bin\aegis-agent.exe" service --state-dir "C:\ProgramData\AEGIS\Agent" --execution-profile "C:\Reviewed\profile.json" --execution-grant "C:\Reviewed\installed-grant.json" --execution-key "C:\Reviewed\manager-execution-v2-public.pem"')
    $sid='S-1-5-80-1-2-3-4-5'
    $original='O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;RC;;;AU)'
    $changed=Get-AgentReadDescriptor $original $sid 4
    $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor($changed)
    Check-Pure ($descriptor.Owner.Value -eq 'S-1-5-18' -and $descriptor.Group.Value -eq 'S-1-5-18' -and $descriptor.DiscretionaryAcl.Count -eq 4)
    $ace=$descriptor.DiscretionaryAcl[3]
    Check-Pure ($ace.SecurityIdentifier.Value -eq $sid -and $ace.AccessMask -eq 4)
    Check-Pure ((Get-AgentReadDescriptor $changed $sid 4) -ceq $changed)
    $channel=New-Object Security.AccessControl.RawSecurityDescriptor((Get-AgentReadDescriptor $original $sid 1))
    Check-Pure ($channel.DiscretionaryAcl[3].AccessMask -eq 1)
    Reject-Pure { Get-AgentReadDescriptor $original $sid 0x10 }
    Reject-Pure { Get-AgentReadDescriptor ('O:SYD:(D;;LC;;;' + $sid + ')(A;;GA;;;SY)') $sid 4 }
    Reject-Pure { Get-AgentReadDescriptor 'O:SYD:NO_ACCESS_CONTROL' $sid 4 }
    Check-Pure (!(Test-AgentMutationRights ([Security.AccessControl.FileSystemRights]::ReadAndExecute)))
    foreach($right in @('Delete','ChangePermissions','TakeOwnership','DeleteSubdirectoriesAndFiles')){Check-Pure (Test-AgentMutationRights ([Security.AccessControl.FileSystemRights]::$right))}
    $journal=[pscustomobject]@{schema_version=1;id=('a'*32);phase='prepared';had_previous=$true;was_running=$true;command='approved';start_mode='Auto';delayed=$true}
    Assert-AgentUpgradeRecord $journal; $checks++
    $journal.id='../foreign'; Reject-Pure { Assert-AgentUpgradeRecord $journal }; $journal.id='a'*32
    $journal | Add-Member unexpected 'value'; Reject-Pure { Assert-AgentUpgradeRecord $journal }
    Write-Output "$checks pure installer contracts passed; no files, ACLs or SCM changed"
    return
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('aegis-install-contract-' + [Guid]::NewGuid().ToString('N'))
$passed = 0
function Assert-Rejected([scriptblock]$Action, [string]$Name) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    if (!$rejected) { throw "Expected rejection: $Name" }
    $script:passed++
}
try {
    New-Item -ItemType Directory -Path (Join-Path $testRoot 'bin') -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $testRoot 'bin/aegis-agent.exe'), 'synthetic executable fixture')
    Copy-Item -LiteralPath $installer -Destination (Join-Path $testRoot 'Install-Agent.ps1')
    Copy-Item -LiteralPath (Join-Path $repo 'deploy/agent/windows/Uninstall-Agent.ps1') -Destination (Join-Path $testRoot 'Uninstall-Agent.ps1')
    function Write-Manifest {
        $lines = Get-ChildItem -LiteralPath $testRoot -Recurse -File | Where-Object Name -ne 'SHA256SUMS.txt' | ForEach-Object {
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_.FullName.Substring($testRoot.Length + 1).Replace('\','/')
        }
        [IO.File]::WriteAllLines((Join-Path $testRoot 'SHA256SUMS.txt'), $lines)
    }
    Write-Manifest
    $files = @(Get-VerifiedAgentPackage $testRoot)
    if ($files.Count -ne 3) { throw 'Complete valid package was not accepted' }; $passed++
    [IO.File]::AppendAllText((Join-Path $testRoot 'bin/aegis-agent.exe'), 'tampered')
    Assert-Rejected { Get-VerifiedAgentPackage $testRoot } 'changed executable hash'
    Write-Manifest
    [IO.File]::AppendAllText((Join-Path $testRoot 'SHA256SUMS.txt'), "`n$('0' * 64)  ../escape")
    Assert-Rejected { Get-VerifiedAgentPackage $testRoot } 'manifest traversal'
    Write-Manifest
    [IO.File]::WriteAllText((Join-Path $testRoot 'extra.key'), 'synthetic forbidden extra')
    Assert-Rejected { Get-VerifiedAgentPackage $testRoot } 'unlisted payload'
    Remove-Item -LiteralPath (Join-Path $testRoot 'extra.key')
    $binary = Join-Path $env:ProgramFiles 'AEGIS Agent/bin/aegis-agent.exe'
    $state = Join-Path $env:ProgramData 'AEGIS/Agent'
    $expected = '"' + $binary + '" service --state-dir "' + $state + '"'
    $echoScript = Join-Path $testRoot 'echo-argument.ps1'
    [IO.File]::WriteAllText($echoScript, 'param([string]$Value) [Console]::Out.Write($Value)')
    $processInfo = New-Object Diagnostics.ProcessStartInfo
    $processInfo.FileName = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $processInfo.UseShellExecute=$false; $processInfo.CreateNoWindow=$true; $processInfo.RedirectStandardOutput=$true
    $processInfo.Arguments = (@('-NoProfile','-File',$echoScript,'-Value',$expected) | ForEach-Object { ConvertTo-AgentNativeArgument $_ }) -join ' '
    $child = [Diagnostics.Process]::Start($processInfo)
    $roundTrip = $child.StandardOutput.ReadToEnd(); $child.WaitForExit()
    if ($child.ExitCode -ne 0 -or $roundTrip -cne $expected) { throw 'Quoted service command did not survive native argv' }; $passed++
    Assert-AgentServiceConfiguration ([pscustomobject]@{ StartName='NT SERVICE\AegisAgent'; PathName=$expected }) $binary $state
    $passed++
    Assert-Rejected { Assert-AgentServiceConfiguration ([pscustomobject]@{StartName='LocalSystem';PathName=$expected}) $binary $state } 'wrong account'
    Assert-Rejected { Assert-AgentServiceConfiguration ([pscustomobject]@{StartName='NT SERVICE\AegisAgent';PathName='C:\foreign.exe'}) $binary $state } 'foreign service path'
    Assert-Rejected { Assert-AgentServiceAcl 'O:S-1-5-21-100-200-300-400D:(A;;GA;;;SY)(A;;GA;;;BA)' } 'untrusted owner despite restricted service DACL'
    Assert-Rejected { Assert-AgentServiceAcl 'D:(A;;GA;;;SY)(A;;GA;;;BA)' } 'omitted service owner'
    Assert-AgentServiceAcl 'O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLOCRRC;;;AU)'
    $passed++
    Assert-Rejected { Assert-AgentServiceAcl 'O:SYD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;DC;;;WD)' } 'world change-config service grant'
    $private = Join-Path $testRoot 'private'
    New-Item -ItemType Directory -Path $private | Out-Null
    Set-AgentDirectoryAcl $private $null 'State'
    Assert-AgentProtectedTree $private 'State' $null
    $passed++
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.WindowsIdentity]::GetCurrent().User,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')),'Write','Allow')))
    & "$env:SystemRoot\System32\icacls.exe" $private /grant '*S-1-1-0:(W)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to arrange writable-state fixture' }
    Assert-Rejected { Assert-AgentProtectedTree $private 'State' $null } 'world writable state'
    Set-AgentDirectoryAcl $private $null 'State'
    $identity = Join-Path $private 'state.json'
    [IO.File]::WriteAllText($identity, 'synthetic pending identity')
    $before = (Get-FileHash -LiteralPath $identity).Hash
    Assert-Rejected { Invoke-AgentEnrollment { throw 'synthetic pairing failure' } } 'failed enrollment'
    if ((Get-FileHash -LiteralPath $identity).Hash -ne $before) { throw 'Failed enrollment changed identity' }; $passed++
    $oldRoot = Join-Path $testRoot 'installed'
    $newRoot = Join-Path $testRoot 'staged'
    New-Item -ItemType Directory -Path $oldRoot,$newRoot | Out-Null
    [IO.File]::WriteAllText((Join-Path $oldRoot 'agent'), 'old reviewed payload')
    [IO.File]::WriteAllText((Join-Path $newRoot 'agent'), 'new reviewed payload')
    $script:activated = $false
    Assert-Rejected { Invoke-AgentBinaryPromotion $newRoot $oldRoot {
        if ([IO.File]::ReadAllText((Join-Path $oldRoot 'agent')) -eq 'new reviewed payload') { $script:activated=$true }
        throw 'synthetic service start failure'
    } } 'upgrade failure'
    if (!$script:activated -or [IO.File]::ReadAllText((Join-Path $oldRoot 'agent')) -ne 'old reviewed payload') { throw 'Failed upgrade did not restore prior payload' }
    if ((Get-FileHash -LiteralPath $identity).Hash -ne $before) { throw 'Failed upgrade changed pending identity' }; $passed++
    Write-Output "$passed installer contracts passed; SCM was not invoked"
    & (Join-Path $PSScriptRoot 'Test-NativeStateSnapshot.ps1')
    & (Join-Path $PSScriptRoot 'Test-InstallerDiagnostics.ps1')
    & (Join-Path $PSScriptRoot 'Test-WindowsInstallerInput.ps1')
} finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
