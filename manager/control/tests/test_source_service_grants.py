"""Installer planning contracts. Synthetic descriptors are never lab evidence."""
import json
import os
from pathlib import Path
import subprocess
import unittest

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[3]


@unittest.skipUnless(os.name == 'nt', 'Native Windows PowerShell descriptor contracts')
class SourceServiceGrantTests(SimpleTestCase):
    def ps(self, command):
        env = {k: v for k, v in os.environ.items() if k.casefold() != 'psmodulepath'}
        env['AEGIS_TEST_INSTALL'] = str(ROOT / 'deploy/agent/windows/Install-Agent.ps1')
        env['AEGIS_TEST_ENABLE'] = str(ROOT / 'deploy/agent/windows/Enable-Execution.ps1')
        script = r'''
$ErrorActionPreference='Stop'
. $env:AEGIS_TEST_INSTALL
$sid='S-1-5-80-1-2-3-4-5'
$before='O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;LC;;;AU)'
function Expect-Code([scriptblock]$Action,[string]$Code){
    try{& $Action|Out-Null}catch{if($_.Exception.Message -ceq $Code){return};throw}
    throw 'expected_refusal_missing'
}
''' + command
        result = subprocess.run([
            str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'),
            '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script,
        ], env=env, capture_output=True, text=True, timeout=25)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-3000:])
        return json.loads(result.stdout)

    def test_enable_preserves_existing_shared_service_read_before_any_write(self):
        result = self.ps(r'''
$assets=Join-Path $env:ProgramFiles 'AEGIS-Test-Only'
$state=Join-Path $env:ProgramData 'AEGIS/Agent'
. $env:AEGIS_TEST_ENABLE -StateDirectory $state -ProfilePath (Join-Path $assets 'profile.json') -GrantPath (Join-Path $assets 'installed-grant.json') -SigningPublicKeyPath (Join-Path $assets 'manager-execution-v2-public.pem')
function Assert-AgentAdministrator {}
function Get-AgentServiceSid {return 'S-1-5-80-1-2-3-4-5'}
function Assert-AgentServiceTreeAcl {}
function Assert-AgentNativeServiceAcl {}
function Initialize-AgentControlRoot {return 'C:\AEGIS-Test-Control'}
function Open-AgentControlLock {return [IO.MemoryStream]::new()}
function Read-AgentControlRecord {return $null}
function Get-AgentInstalledExecution {return $null}
function Get-CimInstance {return [pscustomobject]@{State='Running'}}
function Assert-AgentServiceConfiguration {}
function Invoke-AgentConfigurationCheck {}
function Get-Service {return [pscustomobject]@{Status='Running'}}
function Get-AgentSourceDescriptor([string]$Kind,[string]$Name){if($Kind -ceq 'service'){return $before};return 'O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)'}
function Get-AgentSourceProtection {throw 'shared_read_must_not_require_protection_mutation'}
function Write-AgentControlRecord($Path,$Value){$script:planned=$Value;throw 'test_plan_boundary'}
function Stop-AgentService {throw 'unexpected_service_mutation'}
try{Enable-AegisExecution -StateDirectory $state -ProfilePath (Join-Path $assets 'profile.json') -GrantPath (Join-Path $assets 'installed-grant.json') -SigningPublicKeyPath (Join-Path $assets 'manager-execution-v2-public.pem')}
catch{if($_.Exception.Message -cne 'test_plan_boundary'){throw}}
if(!$script:planned -or $script:planned.grants[0].after -cne $before -or $script:planned.grants[1].after -cne $before){throw 'unnecessary_source_mutation'}
@{grant_count=@($script:planned.grants).Count;unchanged_services=$true}|ConvertTo-Json -Compress
''')
        self.assertEqual(result, {'grant_count': 4, 'unchanged_services': True})

    def test_read_proof_is_limited_to_applicable_closed_sids_and_service_mask(self):
        result = self.ps(r'''
$count=0
foreach($reader in @('WD','AU','SU',$sid)){
    foreach($right in @('LC','GR','GA')){
        $sddl='O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;'+$right+';;;'+$reader+')'
        if((Get-AgentProvisionDescriptor $sddl $sid 4) -cne $sddl){throw 'existing_read_not_preserved'}
        $count++
    }
}
foreach($sddl in @('O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;LC;;;BU)', 'O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)(A;IO;LC;;;AU)')){
    $after=Get-AgentProvisionDescriptor $sddl $sid 4
    if($after -ceq $sddl){throw 'unproved_shared_access_accepted'}
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($after)
    $added=@($descriptor.DiscretionaryAcl|Where-Object{$_.SecurityIdentifier.Value -ceq $sid})
    if($added.Count -ne 1 -or $added[0].AccessMask -ne 4 -or [int]$added[0].AceFlags -ne 0){throw 'grant_scope_changed'}
}
$channel='O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x1;;;AU)'
if((Get-AgentProvisionDescriptor $channel $sid 1) -cne (Get-AgentReadDescriptor $channel $sid 1)){throw 'channel_contract_changed'}
@{existing_service_cases=$count;closed_read_proof=$true}|ConvertTo-Json -Compress
''')
        self.assertEqual(result, {'existing_service_cases': 12, 'closed_read_proof': True})

    def test_generic_and_ambiguous_denies_and_inherit_only_sid_are_refused(self):
        result = self.ps(r'''
foreach($deny in @('LC','GR','GA')){
    foreach($who in @('AU','S-1-5-32-545')){
        $sddl='O:BAD:(D;;'+$deny+';;;'+$who+')(A;;GA;;;SY)(A;;GA;;;BA)(A;;LC;;;AU)'
        Expect-Code {Get-AgentProvisionDescriptor $sddl $sid 4} 'source_access_denied'
    }
}
$sddl='O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)(A;IO;LC;;;'+$sid+')'
Expect-Code {Get-AgentProvisionDescriptor $sddl $sid 4} 'source_descriptor_unsupported'
@{denies_refused=$true;inherit_only_not_credited=$true}|ConvertTo-Json -Compress
''')
        self.assertTrue(result['denies_refused'] and result['inherit_only_not_credited'])

    def test_legacy_records_and_justified_noops_validate_and_forged_noops_fail(self):
        result = self.ps(r'''
function Get-AgentServiceSid {return 'S-1-5-80-1-2-3-4-5'}
$channel='O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)'
$grants=@()
foreach($row in @(@('service','Sysmon64',$before,4),@('service','WazuhSvc',$before,4),@('channel','Microsoft-Windows-Sysmon/Operational',$channel,1),@('channel','Microsoft-Windows-PowerShell/Operational',$channel,1))){
    $grants+=,[pscustomobject]@{kind=$row[0];name=$row[1];before=$row[2];after=(Get-AgentReadDescriptor $row[2] $sid $row[3])}
}
$r=[pscustomobject]@{schema_version=1;phase='prepared';old_execution=$null;new_execution=$null;was_running=$true;grants=$grants}
Assert-AgentProvisionRecord $r
$r.phase='committed';Assert-AgentProvisionRecord $r
foreach($g in $r.grants){if($g.kind -ceq 'service'){$g.after=$g.before}}
$r.phase='prepared';Assert-AgentProvisionRecord $r
$r.phase='committed';Assert-AgentProvisionRecord $r
$r.grants[0].before=$channel;$r.grants[0].after=$channel
Expect-Code {Assert-AgentProvisionRecord $r} 'provision_record_invalid'
@{legacy_valid=$true;noop_valid=$true;forged_noop_refused=$true}|ConvertTo-Json -Compress
''')
        self.assertTrue(all(result.values()))

    def test_protected_or_unknown_service_mutation_is_refused_without_a_setter(self):
        result = self.ps(r'''
$script:queries=0
function Get-AgentSourceProtection {param($Name);$script:queries++;return [uint32]3}
Assert-AgentSourceMutationSupported 'service' 'SyntheticProtected' $before $before
if($script:queries -ne 0){throw 'noop_queried_mutation_rights'}
Expect-Code {Assert-AgentSourceMutationSupported 'service' 'SyntheticProtected' 'before' 'after'} 'source_service_protected'
function Get-AgentSourceProtection {param($Name);throw 'source_protection_query_failed'}
Expect-Code {Assert-AgentSourceMutationSupported 'service' 'SyntheticUnreadable' 'before' 'after'} 'source_protection_query_failed'
function Get-AgentSourceProtection {param($Name);return [uint32]9}
Expect-Code {Assert-AgentSourceMutationSupported 'service' 'SyntheticUnknown' 'before' 'after'} 'source_protection_query_failed'
@{protected_refused=$true;unknown_refused=$true;noops_unchanged=$true}|ConvertTo-Json -Compress
''')
        self.assertTrue(all(result.values()))

    def test_forward_refuses_protected_missing_read_before_journal_or_stop(self):
        result = self.ps(r'''
$assets=Join-Path $env:ProgramFiles 'AEGIS-Test-Only';$state=Join-Path $env:ProgramData 'AEGIS/Agent'
. $env:AEGIS_TEST_ENABLE -StateDirectory $state -ProfilePath (Join-Path $assets 'profile.json') -GrantPath (Join-Path $assets 'installed-grant.json') -SigningPublicKeyPath (Join-Path $assets 'manager-execution-v2-public.pem')
function Assert-AgentAdministrator {}
function Get-AgentServiceSid {return 'S-1-5-80-1-2-3-4-5'}
function Assert-AgentServiceTreeAcl {}
function Assert-AgentNativeServiceAcl {}
function Initialize-AgentControlRoot {return 'C:\AEGIS-Test-Control'}
function Open-AgentControlLock {return [IO.MemoryStream]::new()}
function Read-AgentControlRecord {return $null}
function Get-AgentInstalledExecution {return $null}
function Get-CimInstance {return [pscustomobject]@{State='Running'}}
function Assert-AgentServiceConfiguration {}
function Invoke-AgentConfigurationCheck {}
function Get-Service {return [pscustomobject]@{Status='Running'}}
function Get-AgentSourceDescriptor {return 'O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)'}
function Get-AgentSourceProtection {return [uint32]3}
$script:mutations=0
function Write-AgentControlRecord {$script:mutations++;throw 'unexpected_journal'}
function Stop-AgentService {$script:mutations++;throw 'unexpected_stop'}
function Set-AgentSourceDescriptor {$script:mutations++;throw 'unexpected_setter'}
Expect-Code {Enable-AegisExecution -StateDirectory $state -ProfilePath (Join-Path $assets 'profile.json') -GrantPath (Join-Path $assets 'installed-grant.json') -SigningPublicKeyPath (Join-Path $assets 'manager-execution-v2-public.pem')} 'source_service_protected'
if($script:mutations){throw 'forward_mutated_before_protection_check'}
@{protected_forward_refused=$true;mutations=0}|ConvertTo-Json -Compress
''')
        self.assertEqual(result, {'protected_forward_refused': True, 'mutations': 0})

    def test_native_protection_query_preserves_missing_service_error(self):
        result = self.ps(r'''
Initialize-AgentServiceSecurity
$caught=$null
try{[Aegis.Agent.ServiceSecurity]::ReadProtection('AEGIS-Test-Missing-'+[guid]::NewGuid().ToString('N'))|Out-Null}
catch{$caught=$_.Exception}
$code=$null;$hasFixedCode=$false
for($i=0;$caught -and $i -lt 5;$i++){
    if($caught -is [ComponentModel.Win32Exception]){$code=$caught.NativeErrorCode}
    if($caught.Message -ceq 'source_protection_query_failed'){$hasFixedCode=$true}
    $caught=$caught.InnerException
}
if($code -ne 1060 -or !$hasFixedCode){throw 'native_query_error_lost'}
@{missing_service_error=$code;fixed_code=$hasFixedCode}|ConvertTo-Json -Compress
''')
        self.assertEqual(result, {'missing_service_error': 1060, 'fixed_code': True})

    def test_recovery_refuses_protected_pending_restore_before_stopping_agent(self):
        result = self.ps(r'''
function Get-AgentServiceSid {return 'S-1-5-80-1-2-3-4-5'}
function Get-AgentServiceCommand {param($Binary,$State,$ExecutionPaths);return 'synthetic-command'}
function Get-CimInstance {return [pscustomobject]@{StartName='NT SERVICE\AegisAgent';PathName='synthetic-command'}}
function Get-AgentInstalledExecution {return $null}
$channel='O:BAD:(A;;GA;;;SY)(A;;GA;;;BA)';$grants=@()
foreach($row in @(@('service','Sysmon64',$before,4),@('service','WazuhSvc',$before,4),@('channel','Microsoft-Windows-Sysmon/Operational',$channel,1),@('channel','Microsoft-Windows-PowerShell/Operational',$channel,1))){$grants+=,[pscustomobject]@{kind=$row[0];name=$row[1];before=$row[2];after=(Get-AgentReadDescriptor $row[2] $sid $row[3])}}
$r=[pscustomobject]@{schema_version=1;phase='prepared';old_execution=$null;new_execution=$null;was_running=$true;grants=$grants}
function Get-AgentSourceDescriptor {param($Kind,$Name);return @($grants|Where-Object{$_.name -ceq $Name})[0].after}
function Get-AgentSourceProtection {return [uint32]3}
$script:mutations=0
function Stop-AgentService {$script:mutations++;throw 'unexpected_stop'}
function Set-AgentSourceDescriptor {$script:mutations++;throw 'unexpected_setter'}
function Write-AgentControlRecord {$script:mutations++;throw 'unexpected_record_write'}
foreach($kind in @('service','Service','SERVICE')){
    $r.grants[0].kind=$kind;$r.grants[1].kind=$kind
    Expect-Code {Restore-AgentProvision 'synthetic-binary' 'synthetic-state' $r} 'source_service_protected'
    if($script:mutations){throw 'recovery_mutated_before_protection_check'}
}
@{protected_recovery_refused=$true;mutations=0}|ConvertTo-Json -Compress
''')
        self.assertEqual(result, {'protected_recovery_refused': True, 'mutations': 0})
