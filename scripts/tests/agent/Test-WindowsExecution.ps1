[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PackageRoot,[Parameter(Mandatory=$true)][string]$OutputRoot,[switch]$RequireNative)
$ErrorActionPreference='Stop'
$names=@('containment','service_identity_acl','service_channel_grants','immutable_default_ancestors','upgrade_rollback_journal','policy_denial','published_presence_mtls_missing_vendor')
$rows=@{};foreach($name in $names){$rows[$name]=[ordered]@{name=$name;executed=0;passed=0;failed=0;skipped=0;result='failed'}}
$source=if($env:AEGIS_CONNECTION_SOURCE_COMMIT -cmatch '^[0-9a-f]{40}$'){$env:AEGIS_CONNECTION_SOURCE_COMMIT}else{$null}
$url=if($env:AEGIS_EXECUTION_GATE_URL -match '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+$'){$env:AEGIS_EXECUTION_GATE_URL}else{$null}
$succeeded=$false;$outputReady=$false
function Invoke-GateProcess([string]$Executable,[string[]]$Arguments,[int]$Seconds=300) {
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Executable
    $start.Arguments=($Arguments|ForEach-Object{ConvertTo-AgentNativeArgument $_}) -join ' '
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($start)
    try {
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(!$process.WaitForExit($Seconds*1000)){try{$process.Kill()}catch{};throw 'gate_timeout'}
        $out=$stdout.GetAwaiter().GetResult();$errorText=$stderr.GetAwaiter().GetResult()
        if($out.Length -gt 1048576 -or $errorText.Length -gt 1048576){throw 'gate_output_invalid'}
        return [pscustomobject]@{code=$process.ExitCode;output=$out}
    }finally{$process.Dispose()}
}
function Add-GateCounts([string]$Name,$Counts) {
    if($Name -notin $names){throw 'gate_category_invalid'}
    foreach($key in @('executed','passed','failed','skipped')){if($Counts.$key -isnot [int] -or $Counts.$key -lt 0 -or $Counts.$key -gt 10000){throw 'gate_counts_invalid'}}
    if($Counts.executed -ne $Counts.passed+$Counts.failed){throw 'gate_counts_invalid'}
    foreach($key in @('executed','passed','failed','skipped')){$rows[$Name][$key]+=$Counts.$key}
}
try {
    if(![IO.Path]::IsPathRooted($OutputRoot) -or [IO.Path]::GetFullPath($OutputRoot) -cne $OutputRoot -or (Test-Path -LiteralPath $OutputRoot)){throw 'fresh_output_required'}
    for($parent=[IO.Path]::GetDirectoryName($OutputRoot);$parent;$parent=[IO.Path]::GetDirectoryName($parent)){
        if((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'output_reparse_refused'}
    }
    # Failure reports are ordinary task files. All OS actions remain below the
    # explicit disposable-runner guard; missing prerequisites never become skips.
    New-Item -ItemType Directory -Path $OutputRoot | Out-Null;$outputReady=$true
    if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or !$source -or !$url){throw 'required_native_prerequisites_missing'}
    . (Join-Path $PackageRoot 'Install-Agent.ps1')
    Assert-AgentAdministrator;Assert-AgentNoLinks $OutputRoot
    $null=Get-VerifiedAgentPackage $PackageRoot
    $metadata=Get-Content -LiteralPath (Join-Path $PackageRoot 'version.json') -Raw|ConvertFrom-Json
    if($metadata.source_commit -cne $source -or $metadata.runtime -cne 'win-x64'){throw 'package_source_mismatch'}
    $harness=$env:AEGIS_EXECUTION_NATIVE_TEST_EXE
    if(!$harness -or !(Test-Path -LiteralPath $harness -PathType Leaf) -or [IO.Path]::GetExtension($harness) -cne '.exe'){throw 'native_harness_required'}
    $core=Invoke-GateProcess $harness @('--execution-native','--require-native')
    $lines=@($core.output.Split("`n")|Where-Object{$_.Trim().StartsWith('{')})
    if($lines.Count -ne 1){throw 'native_gate_result_invalid'}
    $native=$lines[0]|ConvertFrom-Json
    Assert-AgentClosedRecord $native @('kind','required','executed','failed','platform_supported')
    if($native.kind -cne 'execution_native_gate' -or $native.required -ne $true -or $native.platform_supported -ne $true){throw 'native_gate_result_invalid'}
    Add-GateCounts 'containment' ([pscustomobject]@{executed=$native.executed;passed=($native.executed-$native.failed);failed=$native.failed;skipped=0})
    if($core.code -ne 0){throw 'native_containment_failed'}
    $shell=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $fixtureRoot=Join-Path $OutputRoot 'fixtures'
    $fixture=Invoke-GateProcess $shell @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'Test-ExecutionProvisioning.ps1'),'-PackageRoot',$PackageRoot,'-OutputRoot',$fixtureRoot)
    $fixtureReport=Get-Content -LiteralPath (Join-Path $fixtureRoot 'provisioning-results.json') -Raw|ConvertFrom-Json
    Assert-AgentClosedRecord $fixtureReport @('schema_version','kind','categories','failures')
    if($fixtureReport.schema_version -ne 1 -or $fixtureReport.kind -cne 'execution_provisioning_gate'){throw 'fixture_result_invalid'}
    foreach($entry in $fixtureReport.categories.PSObject.Properties){Add-GateCounts $entry.Name $entry.Value}
    if($fixture.code -ne 0 -or @($fixtureReport.failures).Count){throw 'native_provisioning_failed'}
    $env:AEGIS_EXECUTION_REQUIRE_NATIVE='1';$env:AEGIS_EXECUTION_NATIVE_OUTPUT_ROOT=$OutputRoot
    $env:AEGIS_CONNECTION_SERVICE_PACKAGE=$PackageRoot;$env:AEGIS_CONNECTION_TEST_EXE=Join-Path $PackageRoot 'bin/aegis-agent.exe'
    $repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
    $published=Invoke-GateProcess 'python' @((Join-Path $repo 'manager/manage.py'),'test','control.tests.test_execution_native_service.ExecutionPublishedNativeTests','--settings=aegis_manager.test_settings','--verbosity','1') 300
    $publicReport=Get-Content -LiteralPath (Join-Path $OutputRoot 'published-results.json') -Raw|ConvertFrom-Json
    Assert-AgentClosedRecord $publicReport @('schema_version','kind','categories')
    if($publicReport.schema_version -ne 1 -or $publicReport.kind -cne 'execution_published_gate'){throw 'published_result_invalid'}
    foreach($entry in $publicReport.categories.PSObject.Properties){Add-GateCounts $entry.Name $entry.Value}
    if($published.code -ne 0){throw 'published_gate_failed'}
    $succeeded=$true
}catch{[Console]::Error.WriteLine('required_execution_native_gate_failed')}
finally {
    foreach($name in $names){$row=$rows[$name];if($row.executed -gt 0 -and $row.failed -eq 0 -and $row.skipped -eq 0 -and $row.passed -eq $row.executed){$row.result='passed'}else{$succeeded=$false}}
    if($outputReady){
        $report=[ordered]@{schema_version=1;kind='windows_execution_release_gate';source_commit=$source;required=[bool]$RequireNative;platform='win-x64';result=$(if($succeeded){'passed'}else{'failed'});categories=@($names|ForEach-Object{$rows[$_]});lab_gates=[ordered]@{real_vendor_readiness='not_executed';scn001_detection='not_executed';reboot_before_login='not_executed'};run_url=$url}
        $report|ConvertTo-Json -Depth 7|Set-Content -LiteralPath (Join-Path $OutputRoot 'execution-native-results.json') -Encoding UTF8
    }
}
if(!$succeeded){exit 1};exit 0
