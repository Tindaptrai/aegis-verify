# Diagnostic-only comparison. Never contributes release-gate pass counts.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PackageRoot,[Parameter(Mandatory=$true)][string]$OutputRoot)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows'){throw 'disposable_ci_required'}
function Import-SeedDiagnosticFunctions([string]$Path,[string[]]$Names) {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'seed_helper_invalid'}
    foreach($name in $Names){
        $nodes=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
        if($nodes.Count -ne 1){throw 'seed_helper_invalid'}
        # Import named definitions only; the fixture's top-level actions never run.
        Invoke-Expression ([regex]::Replace($nodes[0].Extent.Text,'^function\s+','function script:'))
    }
}
function Invoke-SeedDiagnosticProcess([string]$Executable,[string[]]$Arguments,[string]$Directory,[int]$TimeoutMilliseconds=25000) {
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$Executable;$start.WorkingDirectory=$Directory
    $start.Arguments=($Arguments|ForEach-Object{ConvertTo-AgentNativeArgument $_}) -join ' '
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($start)
    try {
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(!$process.WaitForExit($TimeoutMilliseconds)){try{$process.Kill();$null=$process.WaitForExit(5000)}catch{};throw 'seed_process_timeout'}
        $text=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
        return [pscustomobject]@{exit_code=$process.ExitCode;output=$text}
    } finally {$process.Dispose()}
}
function Get-SeedSdkSource([string]$ProviderName,[string]$Channel) {
    if($ProviderName -cnotmatch '^AEGIS-Test-[0-9a-f]{32}-(Read|Denied)$' -or $Channel -cne ($ProviderName+'/Operational')){throw 'seed_sdk_input_invalid'}
    $source=@'
#include <windows.h>
#include <winevt.h>
#include <objbase.h>
#include <cstdio>
#include "fixture.h"
static bool EnvEquals(const wchar_t* name, const wchar_t* expected) {
    wchar_t value[32] = {};
    DWORD length = GetEnvironmentVariableW(name, value, 32);
    return length > 0 && length < 32 && wcscmp(value, expected) == 0;
}
int wmain() {
    if (!EnvEquals(L"GITHUB_ACTIONS", L"true") || !EnvEquals(L"RUNNER_ENVIRONMENT", L"github-hosted") || !EnvEquals(L"RUNNER_OS", L"Windows")) return 3;
    const ULONGLONG start = GetTickCount64();
    ULONG registration = EventRegister@@PROVIDER@@();
    ULONG write = 0, queryError = 0;
    bool generatedEnabled = false, nativeEnabled = false, wrote = false, observed = false;
    wchar_t guid[40] = {}, query[512] = {};
    StringFromGUID2(Fixture, guid, 40);
    swprintf_s(query, L"*[System[Provider[@Guid='%ls'] and (EventID=1) and (Version=0) and (Channel='@@CHANNEL@@')]]", guid);
    if (registration == ERROR_SUCCESS) {
        while (GetTickCount64() - start < 15000) {
            if (!wrote) {
                generatedEnabled = EventEnabledFixtureEvent();
                nativeEnabled = EventEnabled(Fixture_Context.RegistrationHandle, &FixtureEvent) != FALSE;
                if (generatedEnabled) {
                    write = EventWriteFixtureEvent_AssumeEnabled();
                    wrote = true;
                    if (write != ERROR_SUCCESS) break;
                }
            }
            if (wrote) {
                EVT_HANDLE results = EvtQuery(NULL, L"@@CHANNEL@@", query, EvtQueryChannelPath | EvtQueryReverseDirection);
                if (!results) { queryError = GetLastError(); break; }
                EVT_HANDLE event = NULL; DWORD returned = 0;
                BOOL success = EvtNext(results, 1, &event, 0, 0, &returned);
                DWORD error = success ? ERROR_SUCCESS : GetLastError();
                bool exact = success && returned == 1 && event != NULL;
                if (event) EvtClose(event);
                EvtClose(results);
                if (exact && GetTickCount64() - start < 15000) { observed = true; break; }
                if (!exact && error != ERROR_NO_MORE_ITEMS && error != ERROR_TIMEOUT) { queryError = error ? error : ERROR_INVALID_DATA; break; }
            }
            Sleep(50);
        }
        EventUnregister@@PROVIDER@@();
    }
    char writeText[32] = "null";
    if (wrote) sprintf_s(writeText, "%lu", write);
    printf("{\"registration_status\":%lu,\"generated_enabled\":%s,\"event_enabled\":%s,\"write_status\":%s,\"query_error\":%lu,\"exact_observed\":%s,\"elapsed_ms\":%llu}\n",
        registration, generatedEnabled ? "true" : "false", nativeEnabled ? "true" : "false", writeText, queryError, observed ? "true" : "false", GetTickCount64() - start);
    return observed ? 0 : registration != 0 ? 20 : !wrote ? 21 : write != 0 ? 22 : queryError != 0 ? 24 : 23;
}
'@
    return $source.Replace('@@PROVIDER@@',$ProviderName.Replace('-','_')).Replace('@@CHANNEL@@',$Channel)
}
function New-SeedReferenceWriter([string]$Directory,[string]$ProviderName,[string]$Channel) {
    $source=Get-SeedSdkSource $ProviderName $Channel
    $tools=Get-FixtureManifestTools
    $sdkBin=Split-Path (Split-Path $tools.mc -Parent) -Parent;$sdkVersion=Split-Path $sdkBin -Leaf
    $kits=Split-Path (Split-Path $sdkBin -Parent) -Parent
    $vcBin=Split-Path $tools.link -Parent;$vcRoot=[IO.Path]::GetFullPath((Join-Path $vcBin '../../..'))
    $compiler=Join-Path $vcBin 'cl.exe';$exe=Join-Path $Directory 'writer.exe'
    if(!(Test-Path -LiteralPath $compiler -PathType Leaf)){throw 'seed_sdk_tools_missing'}
    [IO.File]::WriteAllText((Join-Path $Directory 'writer.cpp'),$source,[Text.Encoding]::ASCII)
    $arguments=@('/nologo','/std:c++17','/EHsc','/MT','/W3','/DUNICODE','/D_UNICODE','/DWINVER=0x0A00','/D_WIN32_WINNT=0x0A00')
    foreach($include in @((Join-Path $vcRoot 'include'),(Join-Path $kits "Include/$sdkVersion/ucrt"),(Join-Path $kits "Include/$sdkVersion/shared"),(Join-Path $kits "Include/$sdkVersion/um"))){$arguments+=('/I'+$include)}
    $arguments+=@('writer.cpp','/Fewriter.exe','/Fowriter.obj','/link','/NOLOGO',('/LIBPATH:'+(Join-Path $vcRoot 'lib/x64')),('/LIBPATH:'+(Join-Path $kits "Lib/$sdkVersion/um/x64")),('/LIBPATH:'+(Join-Path $kits "Lib/$sdkVersion/ucrt/x64")),'advapi32.lib','wevtapi.lib','ole32.lib')
    Invoke-FixtureCompiler $compiler $arguments $Directory
    if(!(Test-Path -LiteralPath $exe -PathType Leaf)){throw 'seed_sdk_compile_failed'}
    return $exe
}
function ConvertFrom-SeedSdkResult([string]$Text) {
    try {
        if(!$Text -or $Text.Length -gt 1024){throw 'invalid'}
        $value=$Text|ConvertFrom-Json
        $fields=@('registration_status','generated_enabled','event_enabled','write_status','query_error','exact_observed','elapsed_ms')
        if($value -isnot [pscustomobject] -or @($value.PSObject.Properties).Count -ne $fields.Count -or @($value.PSObject.Properties.Name|Where-Object{$_ -cnotin $fields}).Count){throw 'invalid'}
        foreach($name in @('registration_status','query_error','elapsed_ms','write_status')){
            $number=$value.$name
            if($name -eq 'write_status' -and $null -eq $number){continue}
            if(($number -isnot [int] -and $number -isnot [long]) -or $number -lt 0 -or $number -gt [uint32]::MaxValue){throw 'invalid'}
        }
        if($value.elapsed_ms -gt 25000){throw 'invalid'}
        foreach($name in @('generated_enabled','event_enabled','exact_observed')){if($value.$name -isnot [bool]){throw 'invalid'}}
        $clean=[ordered]@{};foreach($name in $fields){$clean[$name]=$value.$name};return $clean
    } catch {throw 'seed_sdk_output_invalid'}
}
function Get-SeedChannelSample([guid]$Provider,[string]$Channel) {
    $reader=$null;$watch=[Diagnostics.Stopwatch]::StartNew()
    try {
        $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new($Channel,[Diagnostics.Eventing.Reader.PathType]::LogName,'*');$query.ReverseDirection=$true
        $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query)
        return Read-FixtureSeedDiagnosticSample $reader $Provider $Channel {$watch.Elapsed.TotalSeconds -ge 3}
    } finally {if($null -ne $reader){$reader.Dispose()}}
}
function ConvertTo-SeedEventLogError([string]$Xml,[guid]$Provider,[string]$Channel,[int]$EventId) {
    if(!$Xml -or $Xml.Length -gt 65536 -or $EventId -lt 20 -or $EventId -gt 31){return $null}
    try {
        $document=[xml]$Xml;$channelMatch=$false;$providerMatch=$false;$errorCode=$null
        foreach($node in $document.SelectNodes('/*[local-name()="Event"]/*[local-name()="EventData"]/*[local-name()="Data"]')){
            $field=$node.GetAttribute('Name')
            if($field -cin @('Path','ChannelPath')){$channelMatch=$channelMatch -or $node.InnerText -ceq $Channel}
            if($field -ceq 'PublisherGuid'){$candidate=[guid]::Empty;$providerMatch=[guid]::TryParse($node.InnerText,[ref]$candidate) -and $candidate -eq $Provider}
            if($field -ceq 'ErrorCode'){
                $number=[uint32]0
                if($node.InnerText -cmatch '^0x[0-9a-fA-F]{1,8}$'){$errorCode=[Convert]::ToUInt32($node.InnerText.Substring(2),16)}
                elseif([uint32]::TryParse($node.InnerText,[ref]$number)){$errorCode=$number}
            }
        }
        if(!$channelMatch -and !$providerMatch){return $null}
        return [ordered]@{event_id=$EventId;error_code=$errorCode;channel_match=$channelMatch;provider_match=$providerMatch}
    } catch {return $null}
}
function Get-SeedEventLogErrors([guid]$Provider,[string]$Channel) {
    $result=[ordered]@{events=@();reader_error_code=$null};$reader=$null;$watch=[Diagnostics.Stopwatch]::StartNew()
    try {
        $filter="*[System[Provider[@Name='Microsoft-Windows-Eventlog'] and (EventID>=20 and EventID<=31) and TimeCreated[timediff(@SystemTime)<=120000]]]"
        $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new('System',[Diagnostics.Eventing.Reader.PathType]::LogName,$filter);$query.ReverseDirection=$true
        $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query)
        for($i=0;$i -lt 64 -and $watch.Elapsed.TotalSeconds -lt 3;$i++){
            $record=$reader.ReadEvent([TimeSpan]::FromMilliseconds(250));if($null -eq $record){break}
            try {
                if($watch.Elapsed.TotalSeconds -ge 3){break}
                $entry=ConvertTo-SeedEventLogError $record.ToXml() $Provider $Channel $record.Id
                if($null -ne $entry){$result.events+=@($entry)}
            } finally {$record.Dispose()}
        }
    } catch {$result.reader_error_code=[int]$_.Exception.GetBaseException().HResult}
    finally {if($null -ne $reader){$reader.Dispose()}}
    return $result
}
$source=if($env:AEGIS_CONNECTION_SOURCE_COMMIT -cmatch '^[0-9a-f]{40}$'){$env:AEGIS_CONNECTION_SOURCE_COMMIT}else{$null}
$result=[ordered]@{schema_version=1;kind='windows_event_seed_differential';source_commit=$source;completed=$false;stage='prerequisites';error_code=$null;cleanup_succeeded=$true;arms=[ordered]@{csharp=$null;sdk=$null}}
$installed=@();$owned=$false;$outputReady=$false;$root=$null;$id=[guid]::NewGuid().ToString('N')
try {
    Import-SeedDiagnosticFunctions (Join-Path $PackageRoot 'Install-Agent.ps1') @('Assert-AgentAdministrator','Assert-AgentNoLinks','ConvertTo-AgentNativeArgument','Get-AgentServiceSid','Set-AgentServiceTreeAcl')
    Import-SeedDiagnosticFunctions (Join-Path $PSScriptRoot 'Test-ExecutionProvisioning.ps1') @('Get-FixtureManifestTools','Invoke-FixtureCompiler','New-FixtureEventManifest','Get-FixtureMetadataReadAcl','Assert-FixtureChannelMetadata','ConvertTo-FixtureSeedIdentity','Read-FixtureSeedDiagnosticSample')
    Assert-AgentAdministrator;Assert-AgentNoLinks $OutputRoot
    if([IO.Path]::GetFullPath($OutputRoot) -cne $OutputRoot -or (Test-Path -LiteralPath $OutputRoot)){throw 'seed_fresh_output_required'}
    $testExe=$env:AEGIS_EXECUTION_NATIVE_TEST_EXE
    if(!$testExe -or !(Test-Path -LiteralPath $testExe -PathType Leaf) -or [IO.Path]::GetExtension($testExe) -cne '.exe'){throw 'seed_harness_required'}
    New-Item -ItemType Directory -Path $OutputRoot|Out-Null;$outputReady=$true
    $root=Join-Path $env:ProgramData ('AEGIS-SeedDiag-'+$id);Assert-AgentNoLinks $root
    if(Test-Path -LiteralPath $root){throw 'seed_fresh_root_required'}
    New-Item -ItemType Directory -Path $root|Out-Null;$owned=$true
    Set-AgentServiceTreeAcl $root (Get-AgentServiceSid) 'Binary'
    [IO.File]::WriteAllText((Join-Path $root 'owner.txt'),$id)
    $channels=Join-Path $root 'channels';New-Item -ItemType Directory -Path $channels|Out-Null
    $eventLogSid=[Security.Principal.NTAccount]::new('NT SERVICE','EventLog').Translate([Security.Principal.SecurityIdentifier])
    (Get-Item -LiteralPath $root).SetAccessControl((Get-FixtureMetadataReadAcl (Get-Acl -LiteralPath $root) $eventLogSid $true))
    (Get-Item -LiteralPath $channels).SetAccessControl((Get-FixtureMetadataReadAcl (Get-Acl -LiteralPath $channels) $eventLogSid $false))
    foreach($mode in @('csharp','sdk')){
        $result.stage=$mode
        $provider=[guid]::NewGuid();$name='AEGIS-Test-'+[guid]::NewGuid().ToString('N')+'-Read';$channel=$name+'/Operational'
        $directory=Join-Path $channels $mode
        $compiled=New-FixtureEventManifest $directory $name $provider
        $writer=if($mode -eq 'sdk'){New-SeedReferenceWriter $directory $name $channel}else{$testExe}
        # Include attempted installs: a timeout/nonzero exit can still mutate registration.
        $installed+=@($compiled.manifest)
        $install=Invoke-SeedDiagnosticProcess "$env:SystemRoot/System32/wevtutil.exe" @('im',$compiled.manifest) $directory 15000
        if($install.exit_code -ne 0){throw 'seed_manifest_install_failed'}
        Assert-FixtureChannelMetadata $name $provider $channel $compiled.resource
        $configuration=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($channel)
        try {$latency=$configuration.ProviderLatency;$enabled=$configuration.IsEnabled;$isolation=[int]$configuration.LogIsolation}
        finally {$configuration.Dispose()}
        $arguments=if($mode -eq 'csharp'){@('--provisioning-event',$provider.ToString('D'),'1',$channel)}else{@()}
        $process=Invoke-SeedDiagnosticProcess $writer $arguments $directory 25000
        $sdk=if($mode -eq 'sdk'){ConvertFrom-SeedSdkResult $process.output}else{$null}
        $result.arms[$mode]=[ordered]@{child_exit_code=$process.exit_code;sdk_writer=$sdk;channel_enabled=$enabled;isolation=$isolation;latency_ms=$latency;sample=(Get-SeedChannelSample $provider $channel);eventlog_errors=(Get-SeedEventLogErrors $provider $channel)}
    }
    $result.completed=$true;$result.stage='complete'
} catch {$result.error_code=[int]$_.Exception.GetBaseException().HResult}
finally {
    foreach($manifest in $installed){try{$removed=Invoke-SeedDiagnosticProcess "$env:SystemRoot/System32/wevtutil.exe" @('um',$manifest) ([IO.Path]::GetDirectoryName($manifest)) 15000;if($removed.exit_code -ne 0){throw 'seed_uninstall_failed'}}catch{$result.cleanup_succeeded=$false}}
    if($owned -and $result.cleanup_succeeded){
        try {
            $full=[IO.Path]::GetFullPath($root)
            if([IO.Path]::GetDirectoryName($full) -cne [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') -or [IO.Path]::GetFileName($full) -cne ('AEGIS-SeedDiag-'+$id) -or [IO.File]::ReadAllText((Join-Path $full 'owner.txt')) -cne $id){throw 'seed_cleanup_ownership_invalid'}
            Assert-AgentNoLinks $full;foreach($entry in Get-ChildItem -LiteralPath $full -Recurse -Force){Assert-AgentNoLinks $entry.FullName}
            Remove-Item -LiteralPath $full -Recurse -Force
        } catch {$result.cleanup_succeeded=$false}
    }
    if($outputReady){$result|ConvertTo-Json -Depth 9|Set-Content -LiteralPath (Join-Path $OutputRoot 'event-seed-differential.json') -Encoding UTF8}
}
if(!$result.completed -or !$result.cleanup_succeeded){exit 1};exit 0
