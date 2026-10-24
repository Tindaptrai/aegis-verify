# Run without elevation: these contracts use temporary files and never call SCM.
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$installer = Join-Path $repo 'deploy/agent/windows/Install-Agent.ps1'
if (!(Test-Path -LiteralPath $installer)) { throw 'RED: Windows installer contract is not implemented' }
. $installer
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
    Assert-AgentServiceAcl 'D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLOCRRC;;;AU)'
    $passed++
    Assert-Rejected { Assert-AgentServiceAcl 'D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;DC;;;WD)' } 'world change-config service grant'
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
} finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
