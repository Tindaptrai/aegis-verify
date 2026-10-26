# Changes only disposable hosted Windows CI. Never invoke on an owner's workstation.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PackageRoot,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
$categories=@{};$failureCodes=@();$createdService=$false;$fixtureCreated=$false;$userCreated=$false;$installedManifests=@();$ownedRoots=$false
$diagnostics=[ordered]@{stage='prerequisites';exception_type=$null;hresult=$null;line=$null}
$id=[Guid]::NewGuid().ToString('N');$fixtureService='AegisFixture-'+$id;$user='AegisT'+$id.Substring(0,12)
$binaryRoot=Join-Path $env:ProgramFiles ('AEGIS-Test-'+$id)
$dataRoot=Join-Path $env:ProgramData ('AEGIS-Test-'+$id)
$resultPath=Join-Path $OutputRoot 'provisioning-results.json'
function Set-FixtureInternetOrigin([string]$Path) {
    # Windows PowerShell 5.1 uses .NET Framework, whose File.WriteAllText rejects
    # the ADS colon syntax. Its filesystem provider supports named streams.
    $zone="[ZoneTransfer]`r`nZoneId=3`r`n"
    Set-Content -LiteralPath $Path -Stream Zone.Identifier -Value $zone -Encoding ASCII -NoNewline
    if((Get-Content -LiteralPath $Path -Stream Zone.Identifier -Raw) -cne $zone){throw 'fixture_origin_stream_invalid'}
}
function Get-FixtureManifestTools {
    # Existing SDK/VS prerequisites only. The fixture never downloads toolchains.
    try {
        $kits=(Get-ItemProperty -LiteralPath 'HKLM:/SOFTWARE/Microsoft/Windows Kits/Installed Roots' -Name KitsRoot10).KitsRoot10
        $sdk=Get-ChildItem -LiteralPath (Join-Path $kits 'bin') -Directory |
            Where-Object {$_.Name -match '^\d+\.\d+\.\d+\.\d+$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'x64/mc.exe')) -and (Test-Path -LiteralPath (Join-Path $_.FullName 'x64/rc.exe'))} |
            Sort-Object {[version]$_.Name} -Descending | Select-Object -First 1
        $vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
        if(!$sdk -or !(Test-Path -LiteralPath $vswhere -PathType Leaf)){throw 'missing_tools'}
        $installation=@(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null)
        if($LASTEXITCODE -ne 0 -or $installation.Count -ne 1){throw 'missing_tools'}
        $vc=Get-ChildItem -LiteralPath (Join-Path $installation[0] 'VC/Tools/MSVC') -Directory |
            Where-Object {$_.Name -match '^\d+\.\d+\.\d+$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'bin/Hostx64/x64/link.exe'))} |
            Sort-Object {[version]$_.Name} -Descending | Select-Object -First 1
        if(!$vc){throw 'missing_tools'}
        return [pscustomobject]@{mc=Join-Path $sdk.FullName 'x64/mc.exe';rc=Join-Path $sdk.FullName 'x64/rc.exe';link=Join-Path $vc.FullName 'bin/Hostx64/x64/link.exe'}
    } catch { throw 'fixture_metadata_tools_missing' }
}
function Invoke-FixtureCompiler([string]$Executable,[string[]]$Arguments,[string]$Directory) {
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Executable;$start.WorkingDirectory=$Directory
    $start.Arguments=($Arguments|ForEach-Object{ConvertTo-AgentNativeArgument $_}) -join ' '
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($start)
    try {
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(!$process.WaitForExit(30000)){try{$process.Kill()}catch{};throw 'fixture_metadata_compile_timeout'}
        $null=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
        if($process.ExitCode -ne 0){throw 'fixture_metadata_compile_failed'}
    } finally { $process.Dispose() }
}
function New-FixtureEventManifest([string]$Directory,[string]$ProviderName,[guid]$Provider) {
    if($ProviderName -cnotmatch '^AEGIS-Test-[0-9a-f]{32}-(Read|Denied)$' -or $Provider -eq [guid]::Empty -or (Test-Path -LiteralPath $Directory)){throw 'fixture_metadata_input_invalid'}
    $tools=Get-FixtureManifestTools
    New-Item -ItemType Directory -Path $Directory | Out-Null
    $manifest=Join-Path $Directory 'fixture.man';$resource=Join-Path $Directory 'fixture.dll'
    $resourceXml=[Security.SecurityElement]::Escape($resource);$channelName=$ProviderName+'/Operational'
    $xml=@"
<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events" xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events"><instrumentation><events><provider name="$ProviderName" guid="{$Provider}" symbol="Fixture" resourceFileName="$resourceXml" messageFileName="$resourceXml"><channels><channel chid="Operational" name="$channelName" type="Operational" value="16" enabled="true" access="O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)"/></channels><events><event value="1" version="0" symbol="FixtureEvent" channel="Operational" level="win:Informational"/></events></provider></events></instrumentation></instrumentationManifest>
"@
    [IO.File]::WriteAllText($manifest,$xml)
    # Event Log needs the compiled WEVT_TEMPLATE, not merely a registered XML
    # file pointing at the unrelated test apphost. This DLL has no entry point.
    Invoke-FixtureCompiler $tools.mc @('-um','-h',$Directory,'-r',$Directory,$manifest) $Directory
    Invoke-FixtureCompiler $tools.rc @('/nologo','/fo','fixture.res','fixture.rc') $Directory
    Invoke-FixtureCompiler $tools.link @('/NOLOGO','/DLL','/NOENTRY','/MACHINE:X64','/OUT:fixture.dll','fixture.res') $Directory
    if(!(Test-Path -LiteralPath $resource -PathType Leaf)){throw 'fixture_metadata_compile_failed'}
    return [pscustomobject]@{manifest=$manifest;resource=$resource}
}
function Get-FixtureMetadataReadAcl([Security.AccessControl.DirectorySecurity]$Existing,[Security.Principal.SecurityIdentifier]$EventLogSid,[bool]$TraverseOnly) {
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorBinaryForm($Existing.GetSecurityDescriptorBinaryForm())
    $rights=if($TraverseOnly){[Security.AccessControl.FileSystemRights]::Traverse}else{[Security.AccessControl.FileSystemRights]::ReadAndExecute}
    $inheritance=if($TraverseOnly){[Security.AccessControl.InheritanceFlags]::None}else{[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($EventLogSid,$rights,$inheritance,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    return $acl
}
function Assert-FixtureChannelMetadata([string]$ProviderName,[guid]$Provider,[string]$ChannelName,[string]$Resource) {
    try {
        $metadata=[Diagnostics.Eventing.Reader.ProviderMetadata]::new($ProviderName)
        try {
            $events=@($metadata.Events)
            if($metadata.Id -ne $Provider -or ![string]::Equals($metadata.ResourceFilePath,$Resource,[StringComparison]::OrdinalIgnoreCase) -or
                $events.Count -ne 1 -or $events[0].Id -ne 1 -or $events[0].Version -ne 0 -or $events[0].LogLink.LogName -cne $ChannelName){throw 'invalid_metadata'}
        } finally { $metadata.Dispose() }
    } catch { throw 'fixture_provider_metadata_invalid' }
    try {
        $configuration=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($ChannelName)
        try {
            if(!$configuration.IsEnabled -or $configuration.OwningProviderName -cne $ProviderName -or $configuration.LogName -cne $ChannelName){throw 'invalid_channel'}
        } finally { $configuration.Dispose() }
    } catch { throw 'fixture_channel_configuration_invalid' }
}
function Get-FixtureSetupFailure($Record) {
    $known=@('fixture_metadata_tools_missing','fixture_metadata_input_invalid','fixture_metadata_compile_timeout','fixture_metadata_compile_failed','fixture_metadata_acl_failed','fixture_channel_registration_failed','fixture_provider_metadata_invalid','fixture_channel_configuration_invalid','fixture_event_write_failed','fixture_event_not_observed',
        'fixture_event_registration_failed','fixture_event_not_enabled','fixture_event_query_failed','fixture_event_read_failed','fixture_event_read_timeout','fixture_event_writer_failed')
    if($Record.Exception.Message -cin $known){return $Record.Exception.Message}
    return $null
}
function Assert-FixtureSeedExit([int]$Code) {
    # Only exit zero proves the TEST writer observed its exact seed. Never copy
    # child output or native messages into the public result.
    switch($Code){
        0 {return}
        20 {throw 'fixture_event_registration_failed'}
        21 {throw 'fixture_event_not_enabled'}
        22 {throw 'fixture_event_write_failed'}
        23 {throw 'fixture_event_not_observed'}
        24 {throw 'fixture_event_query_failed'}
        25 {throw 'fixture_event_read_failed'}
        26 {throw 'fixture_event_read_timeout'}
        default {throw 'fixture_event_writer_failed'}
    }
}
function Record-Check([string]$Category,[scriptblock]$Action) {
    if(!$categories.ContainsKey($Category)){$categories[$Category]=[ordered]@{executed=0;passed=0;failed=0;skipped=0}}
    $item=$categories[$Category];$item.executed++
    try{& $Action;$item.passed++}catch{$item.failed++;$script:failureCodes+='native_fixture_assertion_failed'}
}
function Wait-ServiceResult([string]$Path,[bool]$Complete) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($watch.Elapsed.TotalSeconds -lt 30){
        if(Test-Path -LiteralPath $Path){try{$stream=Open-AgentStateSnapshot $Path;$reader=[IO.StreamReader]::new($stream);try{$value=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose();$stream.Dispose()};if($value.complete -eq $Complete){return $value}}catch{}}
        Start-Sleep -Milliseconds 100
    }
    throw 'native_fixture_timeout'
}
try {
    if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows'){throw 'disposable_ci_required'}
    $diagnostics.stage='import'
    . (Join-Path $PackageRoot 'Install-Agent.ps1')
    Assert-AgentAdministrator
    $diagnostics.stage='target_validation'
    if((Get-Service AegisAgent -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'AEGIS Agent')) -or (Test-Path -LiteralPath (Join-Path $env:ProgramData 'AEGIS/Agent'))){throw 'ci_target_already_exists'}
    foreach($path in @($OutputRoot,$binaryRoot,$dataRoot)){Assert-AgentNoLinks $path}
    if(!(Test-Path -LiteralPath $OutputRoot)){New-Item -ItemType Directory -Path $OutputRoot | Out-Null}
    if(Test-Path -LiteralPath $resultPath){throw 'fresh_output_required'}
    $testExe=$env:AEGIS_EXECUTION_NATIVE_TEST_EXE
    if(!$testExe -or !(Test-Path -LiteralPath $testExe -PathType Leaf) -or [IO.Path]::GetExtension($testExe) -cne '.exe'){throw 'native_test_apphost_required'}
    $sid=Get-AgentServiceSid
    $diagnostics.stage='fixture_roots'
    if((Test-Path -LiteralPath $binaryRoot) -or (Test-Path -LiteralPath $dataRoot)){throw 'fresh_fixture_required'}
    New-Item -ItemType Directory -Path $binaryRoot,$dataRoot | Out-Null
    Set-AgentServiceTreeAcl $binaryRoot $sid 'Binary';Set-AgentServiceTreeAcl $dataRoot $sid 'Binary'
    $marker=Join-Path $dataRoot 'fixture-owner.txt';$markerBytes=[Text.Encoding]::ASCII.GetBytes($id)
    $markerStream=[IO.FileStream]::new($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try{$markerStream.Write($markerBytes,0,$markerBytes.Length);$markerStream.Flush($true)}finally{$markerStream.Dispose()};$ownedRoots=$true
    # The private CI fixture copies only the built test harness directory, never
    # contributes this tree to the public agent archive.
    $diagnostics.stage='harness_copy'
    Copy-Item -LiteralPath ([IO.Path]::GetDirectoryName($testExe)) -Destination (Join-Path $binaryRoot 'harness') -Recurse
    Set-AgentServiceTreeAcl $binaryRoot $sid 'Binary'
    $hostExe=Join-Path $binaryRoot ('harness/'+[IO.Path]::GetFileName($testExe))
    $diagnostics.stage='fixture_assets'
    $programAsset=Join-Path $binaryRoot 'immutable.txt';$dataAsset=Join-Path $dataRoot 'immutable.txt'
    [IO.File]::WriteAllText($programAsset,'synthetic immutable');[IO.File]::WriteAllText($dataAsset,'synthetic immutable')
    $state=Join-Path $dataRoot 'state';New-Item -ItemType Directory -Path $state | Out-Null;Set-AgentServiceTreeAcl $state $sid 'State'
    $zone=Join-Path $dataRoot 'origin.ps1';[IO.File]::WriteAllText($zone,'# inert policy-origin fixture');Set-FixtureInternetOrigin $zone
    $password=[Guid]::NewGuid().ToString('N')+'aA!4'
    $diagnostics.stage='local_user'
    $secure=ConvertTo-SecureString $password -AsPlainText -Force
    New-LocalUser -Name $user -Password $secure -AccountNeverExpires -Description 'Disposable AEGIS native ACL fixture' | Out-Null;$userCreated=$true
    $diagnostics.stage='fixture_service'
    $fixtureCommand=(ConvertTo-AgentNativeArgument $hostExe)+' --provisioning-idle '+$fixtureService
    Invoke-AgentSc @('create',$fixtureService,'binPath=',$fixtureCommand,'start=','demand');$fixtureCreated=$true
    Invoke-AgentSc @('sdset',$fixtureService,'O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)')
    Invoke-AgentSc @('start',$fixtureService)
    (Get-Service $fixtureService).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    $channels=@();$providers=@()
    $diagnostics.stage='channels'
    $channelRoot=Join-Path $dataRoot 'channels';New-Item -ItemType Directory -Path $channelRoot | Out-Null
    try {
        $eventLogSid=[Security.Principal.NTAccount]::new('NT SERVICE','EventLog').Translate([Security.Principal.SecurityIdentifier])
        # Only this generated root is traversable. Read access inherits solely
        # under channels; private state/input/identity siblings stay unchanged.
        (Get-Item -LiteralPath $dataRoot).SetAccessControl((Get-FixtureMetadataReadAcl (Get-Acl -LiteralPath $dataRoot) $eventLogSid $true))
        (Get-Item -LiteralPath $channelRoot).SetAccessControl((Get-FixtureMetadataReadAcl (Get-Acl -LiteralPath $channelRoot) $eventLogSid $false))
    } catch { throw 'fixture_metadata_acl_failed' }
    foreach($suffix in @('Read','Denied')){
        $provider=[Guid]::NewGuid().ToString();$channelName='AEGIS-Test-'+$id+'-'+$suffix+'/Operational';$providerName='AEGIS-Test-'+$id+'-'+$suffix
        $compiled=New-FixtureEventManifest (Join-Path $channelRoot $suffix) $providerName ([guid]$provider)
        $manifest=$compiled.manifest
        & "$env:SystemRoot/System32/wevtutil.exe" im $manifest 2>$null | Out-Null;if($LASTEXITCODE -ne 0){throw 'fixture_channel_registration_failed'}
        $installedManifests+=$manifest;$channels+=$channelName;$providers+=$provider
        Assert-FixtureChannelMetadata $providerName ([guid]$provider) $channelName $compiled.resource
        & $hostExe --provisioning-event $provider 1 $channelName 2>$null | Out-Null
        Assert-FixtureSeedExit $LASTEXITCODE
        # Independently read the writer's observed seed as administrator before
        # evaluating service ACLs. EventWrite success alone is never seed proof.
        # Do not inspect, emit or clear a real vendor channel here.
        $seeded=$false;$seedWatch=[Diagnostics.Stopwatch]::StartNew()
        while(!$seeded -and $seedWatch.Elapsed.TotalSeconds -lt 5){
            $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new($channelName,[Diagnostics.Eventing.Reader.PathType]::LogName,'*[System[(EventID=1)]]')
            $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query)
            try{$event=$reader.ReadEvent();if($event){try{$seeded=$event.Id -eq 1 -and $event.Version -eq 0 -and $event.ProviderId -eq [guid]$provider -and $event.LogName -ceq $channelName}finally{$event.Dispose()}}}finally{$reader.Dispose()}
            if(!$seeded){Start-Sleep -Milliseconds 100}
        }
        if(!$seeded){throw 'fixture_event_not_observed'}
    }
    $diagnostics.stage='source_descriptors'
    $beforeService=Get-AgentSourceDescriptor 'service' $fixtureService;$beforeChannel=Get-AgentSourceDescriptor 'channel' $channels[0]
    $afterService=Get-AgentReadDescriptor $beforeService $sid 4;$afterChannel=Get-AgentReadDescriptor $beforeChannel $sid 1
    foreach($mode in @('denied','allowed')){
        if($mode -eq 'allowed'){
            $diagnostics.stage='allowed_grants'
            Set-AgentSourceDescriptor 'service' $fixtureService $beforeService $afterService
            Set-AgentSourceDescriptor 'channel' $channels[0] $beforeChannel $afterChannel
        }
        $diagnostics.stage=if($mode -eq 'denied'){'denied_service'}else{'allowed_service'}
        $output=Join-Path $state ($mode+'.json');$input=Join-Path $dataRoot ($mode+'-input.json')
        $inputJson=[ordered]@{Output=$output;ProgramFilesAsset=$programAsset;ProgramDataAsset=$dataAsset;State=$state;FixtureService=$fixtureService;FixtureChannel=$channels[0];DeniedChannel=$channels[1];Mode=$mode;User=$user;Password=$password;ZoneFile=$zone}|ConvertTo-Json -Compress
        [IO.File]::WriteAllText($input,$inputJson,[Text.UTF8Encoding]::new($false))
        # Reapply only the exact generated input's ACL; no ancestor changes.
        $info=Get-Item -LiteralPath $input;$acl=New-Object Security.AccessControl.FileSecurity;$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        foreach($identity in @('S-1-5-18','S-1-5-32-544',$sid)){$rights=if($identity -eq $sid){'Read'}else{'FullControl'};$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($identity)),$rights,'Allow')))};$info.SetAccessControl($acl)
        $command=(ConvertTo-AgentNativeArgument $hostExe)+' --provisioning-service '+(ConvertTo-AgentNativeArgument $input)
        if(!$createdService){Invoke-AgentSc @('create','AegisAgent','binPath=',$command,'start=','demand','obj=','NT SERVICE\AegisAgent');$createdService=$true;Invoke-AgentSc @('sidtype','AegisAgent','unrestricted')}
        else{Invoke-AgentSc @('config','AegisAgent','binPath=',$command)}
        Start-Service AegisAgent;Wait-AgentRunning
        $null=Wait-ServiceResult $output $false
        $watch=[Diagnostics.Stopwatch]::StartNew();Stop-AgentService
        $final=Wait-ServiceResult $output $true
        Record-Check 'service_identity_acl' {if($watch.Elapsed.TotalSeconds -ge 20){throw 'stop_deadline'}}
        if($final.schema_version -ne 1 -or $final.kind -cne 'execution_provisioning_service'){throw 'invalid_service_result'}
        foreach($property in $final.categories.PSObject.Properties){
            $name=$property.Name;$count=$property.Value
            if($name -notin @('service_identity_acl','service_channel_grants','immutable_default_ancestors','policy_denial') -or $count.executed -lt 1 -or $count.passed+$count.failed -ne $count.executed -or $count.skipped -ne 0){throw 'invalid_service_counts'}
            if(!$categories.ContainsKey($name)){$categories[$name]=[ordered]@{executed=0;passed=0;failed=0;skipped=0}}
            foreach($field in @('executed','passed','failed','skipped')){$categories[$name][$field]+=$count.$field}
        }
        $failureCodes+=@($final.failures)
    }
    $diagnostics.stage='restore_grants'
    Record-Check 'service_channel_grants' {
        Set-AgentSourceDescriptor 'service' $fixtureService $afterService $beforeService
        Set-AgentSourceDescriptor 'channel' $channels[0] $afterChannel $beforeChannel
        if((Get-AgentSourceDescriptor 'service' $fixtureService) -cne $beforeService -or (Get-AgentSourceDescriptor 'channel' $channels[0]) -cne $beforeChannel){throw 'restore_failed'}
    }
    $diagnostics.stage='complete'
} catch {
    $failureCodes+='native_fixture_setup_failed'
    $setupCode=Get-FixtureSetupFailure $_;if($setupCode){$failureCodes+=$setupCode}
    $type=$_.Exception.GetType().Name
    if($type -cnotin @('RuntimeException','ArgumentException','InvalidOperationException','UnauthorizedAccessException','Win32Exception','IOException','ItemNotFoundException','ParameterBindingException','CommandNotFoundException')){$type='OtherException'}
    $diagnostics.exception_type=$type;$diagnostics.hresult=$_.Exception.HResult;$diagnostics.line=$_.InvocationInfo.ScriptLineNumber
}
finally {
    try{
        if($createdService){$actual=Get-CimInstance Win32_Service -Filter "Name='AegisAgent'";if(!$ownedRoots -or $actual.PathName -cne $command){throw 'fixture_service_ownership_invalid'};Stop-AgentService;Invoke-AgentSc @('delete','AegisAgent')}
        if($fixtureCreated){$actual=Get-CimInstance Win32_Service -Filter "Name='$fixtureService'";if(!$ownedRoots -or $actual.PathName -cne $fixtureCommand){throw 'fixture_service_ownership_invalid'};$svc=Get-Service $fixtureService;if($svc.Status -ne 'Stopped'){Stop-Service $fixtureService;$svc.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))};$svc.Dispose();Invoke-AgentSc @('delete',$fixtureService)}
        foreach($manifest in $installedManifests){& "$env:SystemRoot/System32/wevtutil.exe" um $manifest 2>$null|Out-Null;if($LASTEXITCODE -ne 0){throw 'fixture_channel_cleanup_failed'}}
        if($userCreated){Remove-LocalUser -Name $user}
        if($ownedRoots -and [IO.File]::ReadAllText((Join-Path $dataRoot 'fixture-owner.txt')) -cne $id){throw 'fixture_root_ownership_invalid'}
        foreach($pair in @(@($binaryRoot,$env:ProgramFiles),@($dataRoot,$env:ProgramData))){
            $target=[IO.Path]::GetFullPath($pair[0]);$expected=Join-Path $pair[1] ('AEGIS-Test-'+$id)
            if($target -cne $expected -or [IO.Path]::GetDirectoryName($target) -cne $pair[1]){throw 'fixture_cleanup_path_invalid'}
            Assert-AgentNoLinks $target
            if($ownedRoots -and (Test-Path -LiteralPath $target)){Remove-Item -LiteralPath $target -Recurse -Force}
        }
    }catch{$failureCodes+='native_fixture_cleanup_failed'}
    $password=$null;$secure=$null
    if(Test-Path -LiteralPath $OutputRoot){[ordered]@{schema_version=1;kind='execution_provisioning_gate';categories=$categories;failures=$failureCodes;diagnostics=$diagnostics}|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $resultPath -Encoding UTF8}
}
if($failureCodes.Count -or !$categories.Count -or @($categories.Values|Where-Object{$_.failed -gt 0}).Count){exit 1}
exit 0
