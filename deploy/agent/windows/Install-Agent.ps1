[CmdletBinding()]
param([string]$Manager, [string]$ServerCa)
$ErrorActionPreference = 'Stop'

function Assert-AgentAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'administrator_required' }
}
function Get-AgentExecutionPaths([string]$Profile,[string]$Grant,[string]$Key) {
    $values=@($Profile,$Grant,$Key)
    if (@($values | Where-Object { $_ }).Count -eq 0) { return $null }
    if (@($values | Where-Object { $_ }).Count -ne 3) { throw 'execution_paths_required' }
    $names=@('profile.json','installed-grant.json','manager-execution-v2-public.pem')
    for ($i=0; $i -lt 3; $i++) {
        $path=$values[$i]
        if ($path.Length -gt 230 -or $path -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9 _.''+&\\-]+$' -or [IO.Path]::GetFullPath($path) -cne $path -or [IO.Path]::GetFileName($path) -cne $names[$i]) { throw 'execution_path_invalid' }
        foreach ($part in $path.Substring(3).Split('\')) {
            if (!$part -or $part -ne $part.Trim() -or $part.EndsWith('.') -or $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') { throw 'execution_path_invalid' }
        }
    }
    return [pscustomobject]@{profile=$Profile;grant=$Grant;key=$Key}
}
function Get-AgentServiceCommand([string]$Binary,[string]$State,$ExecutionPaths=$null) {
    $command=(ConvertTo-AgentNativeArgument $Binary) + ' service --state-dir ' + (ConvertTo-AgentNativeArgument $State)
    if ($ExecutionPaths) {
        $paths=Get-AgentExecutionPaths $ExecutionPaths.profile $ExecutionPaths.grant $ExecutionPaths.key
        $command += ' --execution-profile ' + (ConvertTo-AgentNativeArgument $paths.profile) + ' --execution-grant ' + (ConvertTo-AgentNativeArgument $paths.grant) + ' --execution-key ' + (ConvertTo-AgentNativeArgument $paths.key)
    }
    return $command
}
function Get-AgentReadDescriptor([string]$Sddl,[string]$ServiceSid,[int]$Mask) {
    # SERVICE_QUERY_STATUS=4 or Event Log READ=1. Never generic or mutation rights.
    if ($Mask -notin @(1,4) -or $ServiceSid -notmatch '^S-1-5-80-(?:[0-9]+-){4}[0-9]+$') { throw 'source_access_invalid' }
    $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    if (!$descriptor.DiscretionaryAcl -or ($Mask -eq 4 -and (!$descriptor.Owner -or $descriptor.Owner.Value -notin @('S-1-5-18','S-1-5-32-544')))) { throw 'source_descriptor_invalid' }
    $allowed=0
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback) { throw 'source_descriptor_unsupported' }
        if ($ace.AceQualifier -eq 'AccessDenied' -and ($ace.AccessMask -band $Mask) -and $ace.SecurityIdentifier.Value -in @($ServiceSid,'S-1-1-0','S-1-5-11','S-1-5-6')) { throw 'source_access_denied' }
        if ($ace.AceQualifier -eq 'AccessAllowed' -and $ace.SecurityIdentifier.Value -eq $ServiceSid) { $allowed=$allowed -bor $ace.AccessMask }
    }
    $missing=$Mask -band (-bnot $allowed)
    if ($missing) {
        $identity=New-Object Security.Principal.SecurityIdentifier($ServiceSid)
        $ace=New-Object Security.AccessControl.CommonAce([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,$missing,$identity,$false,$null)
        $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count,$ace)
    }
    return $descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
}
function Assert-AgentClosedRecord($Value,[string[]]$Names) {
    if (!$Value -or @($Value.PSObject.Properties.Name).Count -ne $Names.Count -or @(Compare-Object @($Value.PSObject.Properties.Name | Sort-Object) @($Names | Sort-Object)).Count) { throw 'control_record_invalid' }
}
function Assert-AgentUpgradeRecord($Record) {
    Assert-AgentClosedRecord $Record @('schema_version','id','phase','had_previous','was_running','command','start_mode','delayed')
    if ($Record.schema_version -isnot [int] -or $Record.schema_version -ne 1 -or $Record.id -isnot [string] -or $Record.id -cnotmatch '^[0-9a-f]{32}$' -or $Record.phase -notin @('prepared','promoted','committed') -or $Record.had_previous -isnot [bool] -or $Record.was_running -isnot [bool] -or $Record.delayed -isnot [bool] -or $Record.command -isnot [string] -or $Record.command.Length -gt 2048 -or $Record.start_mode -notin @('Auto','Manual','Disabled')) { throw 'upgrade_record_invalid' }
}
function Get-AgentControlRoot { return (Join-Path $env:ProgramData 'AEGIS/AgentControl') }
function Initialize-AgentControlRoot([string]$Sid) {
    $parent=Join-Path $env:ProgramData 'AEGIS'; $root=Get-AgentControlRoot
    Assert-AgentNoLinks $root
    if (!(Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null; Set-AgentServiceTreeAcl $parent $Sid 'Binary' -RootOnly }
    Assert-AgentProtectedTree $parent 'Binary' $Sid -RootOnly
    if (!(Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root | Out-Null; Set-AgentServiceTreeAcl $root $Sid 'Binary' }
    Assert-AgentServiceTreeAcl $root $Sid 'Binary'
    return $root
}
function Open-AgentControlLock([string]$Root) {
    $path=Join-Path $Root 'installer.lock';Assert-AgentNoLinks $path
    return [IO.File]::Open($path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
function Write-AgentControlRecord([string]$Path,$Value) {
    Assert-AgentNoLinks $Path
    $root=Get-AgentControlRoot
    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path)) -cne $root) { throw 'control_path_invalid' }
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Compress -Depth 10))
    if ($bytes.Length -gt 65536) { throw 'control_record_invalid' }
    $temporary=Join-Path $root ('.control-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $stream=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    # PowerShell 5.1 coerces $null to an empty string; File.Replace requires a CLR null to omit the backup.
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary,$Path,[System.Management.Automation.Language.NullString]::Value) } else { [IO.File]::Move($temporary,$Path) }
}
function Read-AgentControlRecord([string]$Path) {
    Assert-AgentNoLinks $Path
    if (!(Test-Path -LiteralPath $Path)) { return $null }
    Assert-AgentServiceTreeAcl (Get-AgentControlRoot) (Get-AgentServiceSid) 'Binary'
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 65536) { throw 'control_record_invalid' }
        $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true))
        try { return ($reader.ReadToEnd() | ConvertFrom-Json) } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}
function Get-AgentInstalledExecution {
    $value=Read-AgentControlRecord (Join-Path (Get-AgentControlRoot) 'execution.json')
    if (!$value) { return $null }
    Assert-AgentClosedRecord $value @('profile','grant','key')
    return (Get-AgentExecutionPaths $value.profile $value.grant $value.key)
}
function Assert-AgentOwnedSibling([string]$Path,[string]$Root,[string]$Kind,[string]$Id) {
    if ($Id -cnotmatch '^[0-9a-f]{32}$' -or $Kind -notin @('stage','backup','failed') -or [IO.Path]::GetFullPath($Path) -cne ($Root + '.' + $Kind + '-' + $Id) -or [IO.Path]::GetDirectoryName($Path) -cne [IO.Path]::GetDirectoryName($Root)) { throw 'upgrade_path_invalid' }
    Assert-AgentNoLinks $Path
}
function Restore-AgentUpgrade([string]$Root,[string]$State,[string]$Sid,$Paths) {
    $path=Join-Path (Get-AgentControlRoot) 'upgrade.json'; $record=Read-AgentControlRecord $path
    if (!$record) { return }
    Assert-AgentUpgradeRecord $record
    $binary=Join-Path $Root 'bin/aegis-agent.exe'
    if ($record.command -cne (Get-AgentServiceCommand $binary $State $Paths)) { throw 'upgrade_configuration_conflict' }
    $stage=$Root+'.stage-'+$record.id; $backup=$Root+'.backup-'+$record.id; $failed=$Root+'.failed-'+$record.id
    foreach ($pair in @(@($stage,'stage'),@($backup,'backup'),@($failed,'failed'))) { Assert-AgentOwnedSibling $pair[0] $Root $pair[1] $record.id }
    if ($record.phase -eq 'committed') {
        # Leave the verified old binary backup for administrator review; state was never copied.
        Remove-Item -LiteralPath $path -Force
        return
    }
    Stop-AgentService
    $service=Get-CimInstance Win32_Service -Filter "Name='AegisAgent'"
    if ($service) { Assert-AgentServiceConfiguration $service $binary $State $Paths; Invoke-AgentSc @('config','AegisAgent','start=','disabled') }
    if (Test-Path -LiteralPath $backup) {
        Assert-AgentServiceTreeAcl $backup $Sid 'Binary'
        if (Test-Path -LiteralPath $Root) {
            Assert-AgentServiceTreeAcl $Root $Sid 'Binary'
            if (Test-Path -LiteralPath $failed) { throw 'upgrade_recovery_conflict' }
            Move-Item -LiteralPath $Root -Destination $failed
        }
        Move-Item -LiteralPath $backup -Destination $Root
    } elseif ($record.had_previous -and $record.phase -eq 'promoted') { throw 'upgrade_backup_missing' }
    if (!$record.had_previous) {
        # Preserve staged/new files, identity and all journal records after failed first install.
        Remove-Item -LiteralPath $path -Force
        return
    }
    Assert-AgentServiceTreeAcl $Root $Sid 'Binary'
    if ($service) {
        $start=if ($record.start_mode -eq 'Disabled') {'disabled'} elseif ($record.start_mode -eq 'Manual') {'demand'} elseif ($record.delayed) {'delayed-auto'} else {'auto'}
        Invoke-AgentSc @('config','AegisAgent','binPath=',$record.command,'start=',$start)
        if ($record.was_running) { Start-Service AegisAgent; Wait-AgentRunning }
    }
    Remove-Item -LiteralPath $path -Force
}
function Invoke-AgentConfigurationCheck([string]$Binary,[string]$State,$Paths) {
    $result=& $Binary execution-validate --state-dir $State --execution-profile $Paths.profile --execution-grant $Paths.grant --execution-key $Paths.key 2>$null
    if ($LASTEXITCODE -ne 0 -or ($result -join '').Length -gt 4096) { throw 'execution_configuration_invalid' }
    try { $value=($result -join '') | ConvertFrom-Json } catch { throw 'execution_configuration_invalid' }
    Assert-AgentClosedRecord $value @('schema_version','configuration_valid','service_readiness','blocking_codes')
    if ($value.schema_version -ne 1 -or $value.configuration_valid -isnot [bool] -or !$value.configuration_valid -or $value.service_readiness -cne 'not_evaluated' -or @($value.blocking_codes).Count) { throw 'execution_configuration_invalid' }
}
function Assert-AgentStoppedJournal([string]$Binary,[string]$State) {
    if(!(Test-Path -LiteralPath (Join-Path $State 'state.json'))){return}
    $text=& $Binary execution-status --state-dir $State 2>$null
    $exit=$LASTEXITCODE
    if(($text -join '').Length -gt 4096){throw 'journal_status_invalid'}
    try{$value=($text -join '')|ConvertFrom-Json}catch{throw 'journal_status_invalid'}
    Assert-AgentClosedRecord $value @('schema_version','journal_state','supervisor_state','drain_state','pending_start_count','pending_receipt_count','unknown_count')
    if($value.schema_version -ne 1 -or $value.supervisor_state -cne 'stopped'){throw 'journal_status_invalid'}
    if($exit -eq 3 -and $value.journal_state -ceq 'absent' -and !(Test-Path -LiteralPath (Join-Path $State 'execution'))){return}
    if($exit -ne 0 -or $value.journal_state -cne 'valid' -or $value.drain_state -notin @('drained','pending_receipt','recovery_required')){throw 'journal_status_invalid'}
    foreach($count in @($value.pending_start_count,$value.pending_receipt_count,$value.unknown_count)){if($count -isnot [int] -or $count -lt 0 -or $count -gt 64){throw 'journal_status_invalid'}}
    # Pending/unknown entries are preserved, not resolved or treated as cleanup.
}
function Get-AgentSourceDescriptor([string]$Kind,[string]$Name) {
    if ($Kind -eq 'service') { Initialize-AgentServiceSecurity; return [Aegis.Agent.ServiceSecurity]::Read($Name) }
    if ($Kind -ne 'channel') { throw 'source_kind_invalid' }
    $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($Name)
    try { return $channel.SecurityDescriptor } finally { $channel.Dispose() }
}
function Set-AgentSourceDescriptor([string]$Kind,[string]$Name,[string]$Expected,[string]$Replacement) {
    if ((Get-AgentSourceDescriptor $Kind $Name) -cne $Expected) { throw 'source_descriptor_conflict' }
    if ($Kind -eq 'service') { [Aegis.Agent.ServiceSecurity]::WriteDacl($Name,$Expected,$Replacement) }
    elseif ($Kind -eq 'channel') {
        $channel=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($Name)
        try {
            if ($channel.SecurityDescriptor -cne $Expected) { throw 'source_descriptor_conflict' }
            $channel.SecurityDescriptor=$Replacement; $channel.SaveChanges()
        } finally { $channel.Dispose() }
    } else { throw 'source_kind_invalid' }
    if ((Get-AgentSourceDescriptor $Kind $Name) -cne $Replacement) { throw 'source_descriptor_verify_failed' }
}
function Assert-AgentProvisionRecord($Record) {
    Assert-AgentClosedRecord $Record @('schema_version','phase','old_execution','new_execution','was_running','grants')
    if ($Record.schema_version -ne 1 -or $Record.phase -notin @('prepared','committed') -or $Record.was_running -isnot [bool] -or @($Record.grants).Count -ne 4) { throw 'provision_record_invalid' }
    foreach ($paths in @($Record.old_execution,$Record.new_execution)) { if($paths){ Assert-AgentClosedRecord $paths @('profile','grant','key'); $null=Get-AgentExecutionPaths $paths.profile $paths.grant $paths.key } }
    $seen=@{}
    foreach ($entry in $Record.grants) {
        Assert-AgentClosedRecord $entry @('kind','name','before','after')
        if (($entry.kind -eq 'service' -and $entry.name -notin @('Sysmon','Sysmon64','WazuhSvc')) -or ($entry.kind -eq 'channel' -and $entry.name -notin @('Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational')) -or $entry.kind -notin @('service','channel') -or $seen.ContainsKey($entry.name)) { throw 'provision_record_invalid' }
        $seen[$entry.name]=$true
        $mask=if($entry.kind -eq 'service'){4}else{1}
        if ((Get-AgentReadDescriptor $entry.before (Get-AgentServiceSid) $mask) -cne $entry.after) { throw 'provision_record_invalid' }
    }
}
function Restore-AgentProvision([string]$Binary,[string]$State,$Record) {
    Assert-AgentProvisionRecord $Record
    $service=Get-CimInstance Win32_Service -Filter "Name='AegisAgent'"
    $commands=@((Get-AgentServiceCommand $Binary $State $Record.old_execution),(Get-AgentServiceCommand $Binary $State $Record.new_execution))
    if (!$service -or $service.StartName -ine 'NT SERVICE\AegisAgent' -or $service.PathName -cnotin $commands) { throw 'service_configuration_conflict' }
    if((Get-AgentServiceCommand $Binary $State (Get-AgentInstalledExecution)) -cnotin $commands){throw 'provision_configuration_conflict'}
    # Validate every source before any recovery mutation. A later descriptor
    # conflict must not stop an unrelated service or partially undo other grants.
    foreach($entry in $Record.grants){if((Get-AgentSourceDescriptor $entry.kind $entry.name) -cnotin @($entry.before,$entry.after)){throw 'source_descriptor_conflict'}}
    Stop-AgentService
    Invoke-AgentSc @('config','AegisAgent','start=','disabled')
    foreach ($entry in @($Record.grants)[3..0]) {
        $current=Get-AgentSourceDescriptor $entry.kind $entry.name
        if ($current -ceq $entry.before) { continue }
        if ($current -cne $entry.after) { throw 'source_descriptor_conflict' }
        Set-AgentSourceDescriptor $entry.kind $entry.name $entry.after $entry.before
    }
    $config=Join-Path (Get-AgentControlRoot) 'execution.json'
    if($Record.old_execution){Write-AgentControlRecord $config $Record.old_execution}
    elseif(Test-Path -LiteralPath $config){Remove-Item -LiteralPath $config -Force}
    Invoke-AgentSc @('config','AegisAgent','binPath=',(Get-AgentServiceCommand $Binary $State $Record.old_execution),'start=','delayed-auto')
    if($Record.was_running){Start-Service AegisAgent;Wait-AgentRunning}
    Remove-Item -LiteralPath (Join-Path (Get-AgentControlRoot) 'provisioning.json') -Force
}
function Assert-AgentNoLinks([string]$Path) {
    if (![IO.Path]::IsPathRooted($Path)) { throw 'absolute_path_required' }
    $item = [IO.Path]::GetFullPath($Path)
    while ($item) {
        if (Test-Path -LiteralPath $item) {
            if ((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_path_refused' }
        }
        $item = [IO.Path]::GetDirectoryName($item)
    }
}
function Get-VerifiedAgentPackage([string]$Root) {
    Assert-AgentNoLinks $Root
    $Root = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $manifest = Join-Path $Root 'SHA256SUMS.txt'
    Assert-AgentNoLinks $manifest
    if (!(Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'manifest_missing' }
    $seen = @{}
    foreach ($line in [IO.File]::ReadAllLines($manifest)) {
        if ($line -notmatch '^([0-9a-fA-F]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)$') { throw 'manifest_invalid' }
        $hash = $Matches[1]; $relative = $Matches[2]
        if ($relative.Split('/') -contains '..' -or $relative.Split('/') -contains '.' -or $relative.Contains('//') -or $seen.ContainsKey($relative) -or $relative -eq 'SHA256SUMS.txt') { throw 'manifest_path_invalid' }
        $path = Join-Path $Root $relative
        Assert-AgentNoLinks $path
        if (!(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $hash) { throw 'package_hash_mismatch' }
        $seen[$relative] = $hash
    }
    foreach ($required in @('bin/aegis-agent.exe','Install-Agent.ps1','Uninstall-Agent.ps1')) {
        if (!$seen.ContainsKey($required)) { throw 'package_incomplete' }
    }
    foreach ($entry in Get-ChildItem -LiteralPath $Root -Recurse -Force) {
        Assert-AgentNoLinks $entry.FullName
        if (!$entry.PSIsContainer) {
            $relative = $entry.FullName.Substring($Root.Length + 1).Replace('\','/')
            if ($relative -ne 'SHA256SUMS.txt' -and !$seen.ContainsKey($relative)) { throw 'package_unlisted_file' }
        }
    }
    foreach ($relative in $seen.Keys) { [pscustomobject]@{ RelativePath=$relative; Hash=$seen[$relative] } }
}
function Get-AgentServiceSid {
    $result = & "$env:SystemRoot\System32\sc.exe" showsid AegisAgent
    if ($LASTEXITCODE -ne 0) { throw 'service_sid_unavailable' }
    $match = [regex]::Match(($result -join ' '),'S-1-5-80-(?:[0-9]+-){4}[0-9]+')
    if (!$match.Success) { throw 'service_sid_unavailable' }
    return $match.Value
}
function Get-AgentAllowedSids([string]$ServiceSid) {
    $ids = @('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    if ($ServiceSid) { $ids += $ServiceSid }
    return $ids
}
function Test-AgentMutationRights([Security.AccessControl.FileSystemRights]$Rights) {
    $mutations=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    return (($Rights -band $mutations) -ne 0)
}
function Set-AgentDirectoryAcl([string]$Path,[string]$ServiceSid,[ValidateSet('Binary','State')]$Kind) {
    Assert-AgentNoLinks $Path
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @(Get-AgentAllowedSids $null | Select-Object -Unique)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    if ($ServiceSid) {
        $rights = if ($Kind -eq 'Binary') { 'ReadAndExecute' } else { 'Modify' }
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($ServiceSid)),$rights,'ContainerInherit,ObjectInherit','None','Allow')))
    }
    $directory = New-Object IO.DirectoryInfo($Path)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [IO.FileSystemAclExtensions]::SetAccessControl($directory,$acl)
    } else { $directory.SetAccessControl($acl) }
}
function Assert-AgentProtectedTree([string]$Path,[ValidateSet('Binary','State')]$Kind,[string]$ServiceSid,[switch]$RootOnly) {
    Assert-AgentNoLinks $Path
    if (!(Test-Path -LiteralPath $Path)) { return }
    $allowed = @(Get-AgentAllowedSids $ServiceSid)
    $entries = @((Get-Item -LiteralPath $Path -Force))
    if (!$RootOnly) { $entries += @(Get-ChildItem -LiteralPath $Path -Recurse -Force) }
    foreach ($entry in $entries) {
        Assert-AgentNoLinks $entry.FullName
        $acl = Get-Acl -LiteralPath $entry.FullName
        if ($allowed -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'path_owner_invalid' }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne 'Allow') { continue }
            if ($allowed -notcontains $rule.IdentityReference.Value) { throw 'path_permissions_invalid' }
            if ($Kind -eq 'Binary' -and $ServiceSid -and $rule.IdentityReference.Value -eq $ServiceSid -and (Test-AgentMutationRights $rule.FileSystemRights)) { throw 'binary_service_writable' }
        }
    }
}
function Set-AgentServiceTreeAcl([string]$Path,[string]$ServiceSid,[ValidateSet('Binary','State')]$Kind,[switch]$RootOnly) {
    Assert-AgentAdministrator
    Assert-AgentNoLinks $Path
    $owner = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $entries = @((Get-Item -LiteralPath $Path -Force))
    if (!$RootOnly) { $entries += @(Get-ChildItem -LiteralPath $Path -Recurse -Force) }
    foreach ($entry in $entries) {
        Assert-AgentNoLinks $entry.FullName
        $acl = if ($entry.PSIsContainer) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
        $acl.SetAccessRuleProtection($true,$false); $acl.SetOwner($owner)
        foreach ($sid in @('S-1-5-18','S-1-5-32-544',$ServiceSid)) {
            $rights = if ($sid -ne $ServiceSid) { 'FullControl' } elseif ($Kind -eq 'State') { 'Modify' } else { 'ReadAndExecute' }
            $identity = New-Object Security.Principal.SecurityIdentifier($sid)
            if ($entry.PSIsContainer) { $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity,$rights,'ContainerInherit,ObjectInherit','None','Allow') }
            else { $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity,$rights,'Allow') }
            $acl.AddAccessRule($rule)
        }
        if ($PSVersionTable.PSEdition -eq 'Core') { [IO.FileSystemAclExtensions]::SetAccessControl($entry,$acl) }
        else { $entry.SetAccessControl($acl) }
    }
}
function Assert-AgentServiceTreeAcl([string]$Path,[string]$ServiceSid,[ValidateSet('Binary','State')]$Kind) {
    Assert-AgentProtectedTree $Path $Kind $ServiceSid
    $allowed = @('S-1-5-18','S-1-5-32-544',$ServiceSid)
    foreach ($entry in @((Get-Item -LiteralPath $Path -Force)) + @(Get-ChildItem -LiteralPath $Path -Recurse -Force)) {
        $acl = Get-Acl -LiteralPath $entry.FullName
        $owners=if($Kind -eq 'Binary'){@('S-1-5-18','S-1-5-32-544')}else{$allowed}
        if ($owners -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'service_tree_owner_invalid' }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $allowed -notcontains $rule.IdentityReference.Value) { throw 'service_tree_permissions_invalid' }
        }
    }
}
function Assert-AgentServiceConfiguration($Service,[string]$Binary,[string]$State,$ExecutionPaths=$null) {
    if (!$Service) { return }
    $expected = Get-AgentServiceCommand $Binary $State $ExecutionPaths
    if ($Service.StartName -ine 'NT SERVICE\AegisAgent' -or $Service.PathName -cne $expected) { throw 'service_configuration_conflict' }
}
function Assert-AgentServiceAcl([string]$Sddl) {
    $descriptor = New-Object Security.AccessControl.CommonSecurityDescriptor($false,$false,$Sddl)
    $trusted = @('S-1-5-18','S-1-5-32-544')
    if (!$descriptor.Owner -or $trusted -notcontains $descriptor.Owner.Value) { throw 'service_owner_invalid' }
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace.AceQualifier -eq 'AccessAllowed' -and $trusted -notcontains $ace.SecurityIdentifier.Value -and ($ace.AccessMask -band 0x500D0002)) { throw 'service_permissions_invalid' }
    }
}
function Initialize-AgentServiceSecurity {
    if ('Aegis.Agent.ServiceSecurity' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
namespace Aegis.Agent {
    public static class ServiceSecurity {
        [DllImport("advapi32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
        [DllImport("advapi32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);
        [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceObjectSecurity(IntPtr service, uint information, byte[] descriptor, uint length, out uint needed);
        [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetServiceObjectSecurity(IntPtr service, uint information, byte[] descriptor);
        [DllImport("advapi32.dll", ExactSpelling=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);
        public static string Read() { return Read("AegisAgent"); }
        public static string Read(string name) {
            IntPtr manager=IntPtr.Zero, service=IntPtr.Zero;
            try {
                manager=OpenSCManagerW(null,null,1); // SC_MANAGER_CONNECT
                if (manager==IntPtr.Zero) throw new InvalidOperationException("service_security_query_failed");
                service=OpenServiceW(manager,name,0x20000); // READ_CONTROL
                if (service==IntPtr.Zero) throw new InvalidOperationException("service_security_query_failed");
                uint needed;
                // Request OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION explicitly.
                bool queried=QueryServiceObjectSecurity(service,5,null,0,out needed);
                if (queried || Marshal.GetLastWin32Error()!=122 || needed==0 || needed>8192)
                    throw new InvalidOperationException("service_security_query_failed");
                byte[] buffer=new byte[needed];
                if (!QueryServiceObjectSecurity(service,5,buffer,(uint)buffer.Length,out needed))
                    throw new InvalidOperationException("service_security_query_failed");
                return new RawSecurityDescriptor(buffer,0).GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
            } finally {
                if (service!=IntPtr.Zero) CloseServiceHandle(service);
                if (manager!=IntPtr.Zero) CloseServiceHandle(manager);
            }
        }
        public static void WriteDacl(string name, string expected, string replacement) {
            // Optimistic compare avoids overwriting an unrelated administrator edit.
            if (Read(name) != expected) throw new InvalidOperationException("source_descriptor_conflict");
            IntPtr manager=IntPtr.Zero, service=IntPtr.Zero;
            try {
                manager=OpenSCManagerW(null,null,1);
                if(manager==IntPtr.Zero) throw new InvalidOperationException("source_descriptor_unavailable");
                service=OpenServiceW(manager,name,0x40000);
                if(service==IntPtr.Zero) throw new InvalidOperationException("source_descriptor_unavailable");
                RawSecurityDescriptor descriptor=new RawSecurityDescriptor(replacement);
                byte[] buffer=new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(buffer,0);
                if(!SetServiceObjectSecurity(service,4,buffer)) throw new InvalidOperationException("source_descriptor_write_failed");
            } finally {
                if(service!=IntPtr.Zero) CloseServiceHandle(service);
                if(manager!=IntPtr.Zero) CloseServiceHandle(manager);
            }
        }
        public static void SetAdministrativeOwner() {
            IntPtr manager=IntPtr.Zero, service=IntPtr.Zero;
            try {
                manager=OpenSCManagerW(null,null,1);
                if (manager==IntPtr.Zero) throw new InvalidOperationException("service_owner_setup_failed");
                service=OpenServiceW(manager,"AegisAgent",0x80000); // WRITE_OWNER
                if (service==IntPtr.Zero) throw new InvalidOperationException("service_owner_setup_failed");
                RawSecurityDescriptor descriptor=new RawSecurityDescriptor("O:BA");
                byte[] buffer=new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(buffer,0);
                if (!SetServiceObjectSecurity(service,1,buffer)) throw new InvalidOperationException("service_owner_setup_failed");
            } finally {
                if (service!=IntPtr.Zero) CloseServiceHandle(service);
                if (manager!=IntPtr.Zero) CloseServiceHandle(manager);
            }
        }
    }
}
'@
}
function Get-AgentNativeServiceSecurity {
    Initialize-AgentServiceSecurity
    return [Aegis.Agent.ServiceSecurity]::Read()
}
function Assert-AgentNativeServiceAcl {
    Assert-AgentServiceAcl (Get-AgentNativeServiceSecurity)
}
function ConvertTo-AgentNativeArgument([string]$Argument) {
    # Windows CRT argv rules, including embedded quotes and trailing backslashes.
    $escaped = [regex]::Replace($Argument,'(\\*)"','$1$1\"')
    $escaped = [regex]::Replace($escaped,'(\\+)$','$1$1')
    return '"' + $escaped + '"'
}
function Invoke-AgentSc([string[]]$Arguments) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = "$env:SystemRoot\System32\sc.exe"
    $start.Arguments = ($Arguments | ForEach-Object { ConvertTo-AgentNativeArgument $_ }) -join ' '
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $process = [Diagnostics.Process]::Start($start)
    $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
    $process.WaitForExit(); $null=$stdout.GetAwaiter().GetResult(); $null=$stderr.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw 'service_operation_failed' }
}
function Stop-AgentService {
    $service = Get-Service -Name AegisAgent -ErrorAction SilentlyContinue
    try {
        if ($service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name AegisAgent
            $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
        }
    } finally { if ($service) { $service.Dispose() } }
}
function Wait-AgentRunning {
    $service = Get-Service -Name AegisAgent
    try { $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(20)) }
    finally { $service.Dispose() }
}
function Invoke-AgentEnrollment([scriptblock]$Connect) {
    & $Connect
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw 'enrollment_requires_action' }
}
function Invoke-AgentBinaryPromotion([string]$Stage,[string]$Root,[scriptblock]$Activate,[scriptblock]$Deactivate) {
    Assert-AgentNoLinks $Stage; Assert-AgentNoLinks $Root
    if([IO.Path]::GetFullPath($Root) -cne $Root -or ![IO.Path]::GetDirectoryName($Root)){throw 'upgrade_path_invalid'}
    $id=[Guid]::NewGuid().ToString('N');$backup = $Root + '.backup-' + $id
    Assert-AgentOwnedSibling $backup $Root 'backup' $id
    $backedUp = $false; $promoted = $false
    try {
        if (Test-Path -LiteralPath $Root) { Move-Item -LiteralPath $Root -Destination $backup; $backedUp=$true }
        Move-Item -LiteralPath $Stage -Destination $Root; $promoted=$true
        & $Activate
        if ($backedUp) { Assert-AgentOwnedSibling $backup $Root 'backup' $id; Remove-Item -LiteralPath $backup -Recurse -Force }
    } catch {
        if ($Deactivate) { & $Deactivate }
        if ($backedUp) {
            if ($promoted) { Assert-AgentNoLinks $Root; if([IO.Path]::GetFullPath($Root) -cne $Root -or [IO.Path]::GetDirectoryName($Root) -cne [IO.Path]::GetDirectoryName($backup)){throw 'upgrade_path_invalid'};Remove-Item -LiteralPath $Root -Recurse -Force }
            Move-Item -LiteralPath $backup -Destination $Root
        }
        throw
    }
}
function Open-AgentStateSnapshot([string]$Path) {
    Assert-AgentNoLinks $Path
    # An upgrade validates configuration before stopping the service. A reader
    # must allow atomic state publication while retaining its old snapshot.
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 65536) { throw 'state_invalid' }
        return $stream
    } catch { $stream.Dispose(); throw }
}
function Assert-AgentPinnedConfiguration([string]$State,[string]$Origin,[string]$CaPath) {
    $path = Join-Path $State 'state.json'
    if (!(Test-Path -LiteralPath $path)) { return }
    # The CLI validates the complete bounded snapshot before this comparison.
    $stream = Open-AgentStateSnapshot $path
    $reader = $null
    try {
        $reader = New-Object IO.StreamReader($stream)
        $config = $reader.ReadToEnd() | ConvertFrom-Json
    } finally {
        if ($reader) { $reader.Dispose() }
        $stream.Dispose()
    }
    if ($Origin -and $Origin -cne $config.manager_origin) { throw 'configuration_mismatch' }
    if ($CaPath) {
        Assert-AgentNoLinks $CaPath
        $provided = ([IO.File]::ReadAllText($CaPath) -replace '\s','')
        if ($provided -cne ($config.server_ca_pem -replace '\s','')) { throw 'configuration_mismatch' }
    }
}
function Install-AegisAgent([string]$PackageRoot,[string]$Origin,[string]$CaPath) {
    Assert-AgentAdministrator
    $control=Initialize-AgentControlRoot (Get-AgentServiceSid)
    $held=Open-AgentControlLock $control
    try{Install-AegisAgentCore $PackageRoot $Origin $CaPath}finally{$held.Dispose()}
}
function Install-AegisAgentCore([string]$PackageRoot,[string]$Origin,[string]$CaPath) {
    Assert-AgentAdministrator
    $verified = @(Get-VerifiedAgentPackage $PackageRoot)
    $root = Join-Path $env:ProgramFiles 'AEGIS Agent'
    $stateParent = Join-Path $env:ProgramData 'AEGIS'
    $state = Join-Path $env:ProgramData 'AEGIS/Agent'
    $binary = Join-Path $root 'bin/aegis-agent.exe'
    Assert-AgentNoLinks $root; Assert-AgentNoLinks $state
    $sid = Get-AgentServiceSid
    $control=Initialize-AgentControlRoot $sid
    $execution=Get-AgentInstalledExecution
    Restore-AgentUpgrade $root $state $sid $execution
    $existing = Get-CimInstance Win32_Service -Filter "Name='AegisAgent'"
    Assert-AgentServiceConfiguration $existing $binary $state $execution
    if ($existing) { Assert-AgentNativeServiceAcl }
    Assert-AgentProtectedTree $root 'Binary' $sid
    Assert-AgentProtectedTree $state 'State' $sid
    # A pre-existing dedicated parent must not permit replacement of the protected child.
    if (Test-Path -LiteralPath $stateParent) { Assert-AgentProtectedTree $stateParent 'Binary' $sid -RootOnly }
    if (!(Test-Path -LiteralPath (Join-Path $state 'state.json')) -and (!$Origin -or !$CaPath)) { throw 'manager_and_server_ca_required' }
    if ($CaPath) { Assert-AgentNoLinks $CaPath; if (!(Test-Path -LiteralPath $CaPath -PathType Leaf)) { throw 'server_ca_missing' } }
    $upgradeId=[Guid]::NewGuid().ToString('N')
    $stage = $root + '.stage-' + $upgradeId
    $backup = $root + '.backup-' + $upgradeId
    Assert-AgentOwnedSibling $stage $root 'stage' $upgradeId
    Assert-AgentOwnedSibling $backup $root 'backup' $upgradeId
    $upgradePath=Join-Path $control 'upgrade.json'
    $upgradeWritten=$false
    try {
        New-Item -ItemType Directory -Path $stage | Out-Null
        Set-AgentDirectoryAcl $stage $null 'Binary'
        Copy-Item -LiteralPath (Join-Path $PackageRoot 'bin') -Destination $stage -Recurse
        $expectedBinaries = @($verified | Where-Object { $_.RelativePath.StartsWith('bin/') })
        $actualBinaries = @(Get-ChildItem -LiteralPath (Join-Path $stage 'bin') -Recurse -File -Force)
        if ($actualBinaries.Count -ne $expectedBinaries.Count) { throw 'staged_package_invalid' }
        foreach ($file in $expectedBinaries) {
            $stagedFile = Join-Path $stage $file.RelativePath
            Assert-AgentNoLinks $stagedFile
            if ((Get-FileHash -LiteralPath $stagedFile -Algorithm SHA256).Hash -ne $file.Hash) { throw 'staged_package_invalid' }
        }
        Assert-AgentProtectedTree $stage 'Binary' $null
        if (Test-Path -LiteralPath (Join-Path $state 'state.json')) {
            $preflight = & (Join-Path $stage 'bin/aegis-agent.exe') status --state-dir $state
            if ($LASTEXITCODE -ne 0) { throw 'state_invalid' }
            Assert-AgentPinnedConfiguration $state $Origin $CaPath
            if (!($preflight | ConvertFrom-Json).device_id -and (!$Origin -or !$CaPath)) { throw 'manager_and_server_ca_required' }
        }
        Set-AgentServiceTreeAcl $stage $sid 'Binary'
        $command=Get-AgentServiceCommand $binary $state $execution
        $delayed=$false
        if ($existing) { $delayed=[bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AegisAgent').DelayedAutoStart }
        $record=[pscustomobject]@{schema_version=1;id=$upgradeId;phase='prepared';had_previous=[bool](Test-Path -LiteralPath $root);was_running=[bool]($existing -and $existing.State -eq 'Running');command=$command;start_mode=$(if($existing){$existing.StartMode}else{'Disabled'});delayed=$delayed}
        Write-AgentControlRecord $upgradePath $record; $upgradeWritten=$true
        Stop-AgentService
        if ($existing) { Invoke-AgentSc @('config','AegisAgent','start=','disabled') }
        Assert-AgentStoppedJournal (Join-Path $stage 'bin/aegis-agent.exe') $state
        # Status is diagnostic, not a lease. Hold the existing process lock during
        # promotion, with SCM stopped/disabled. Never create or replace journal data.
        $held=$null
        try {
            if (Test-Path -LiteralPath (Join-Path $state 'process.lock')) {
                $held=[IO.File]::Open((Join-Path $state 'process.lock'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
            }
            if ((Get-Service AegisAgent -ErrorAction SilentlyContinue) -and (Get-Service AegisAgent).Status -ne 'Stopped') { throw 'upgrade_service_not_stopped' }
            if (Test-Path -LiteralPath $root) { Move-Item -LiteralPath $root -Destination $backup }
            Move-Item -LiteralPath $stage -Destination $root
            $record.phase='promoted'; Write-AgentControlRecord $upgradePath $record
        } finally { if($held){$held.Dispose()} }
        if (!$existing) {
            Invoke-AgentSc @('create','AegisAgent','binPath=',$command,'start=','disabled','obj=','NT SERVICE\AegisAgent')
            Initialize-AgentServiceSecurity
            [Aegis.Agent.ServiceSecurity]::SetAdministrativeOwner()
            Assert-AgentNativeServiceAcl
        }
        Invoke-AgentSc @('sidtype','AegisAgent','unrestricted')
        Set-AgentServiceTreeAcl $root $sid 'Binary'
        if (!(Test-Path -LiteralPath $stateParent)) { New-Item -ItemType Directory -Path $stateParent | Out-Null; Set-AgentDirectoryAcl $stateParent $sid 'Binary' }
        if (!(Test-Path -LiteralPath $state)) { New-Item -ItemType Directory -Path $state | Out-Null }
        Set-AgentDirectoryAcl $state $sid 'State'
        $statusText = & $binary status --state-dir $state
        if ($LASTEXITCODE -ne 0) { throw 'state_invalid' }
        $status = $statusText | ConvertFrom-Json
        Assert-AgentPinnedConfiguration $state $Origin $CaPath
        if (!$status.device_id) {
            if (!$Origin -or !$CaPath) { throw 'manager_and_server_ca_required' }
            try { Invoke-AgentEnrollment { & $binary connect --manager $Origin --server-ca $CaPath --state-dir $state } }
            finally { Set-AgentServiceTreeAcl $state $sid 'State' }
            $statusText = & $binary status --state-dir $state
            if ($LASTEXITCODE -ne 0) { throw 'state_invalid' }
            $status = $statusText | ConvertFrom-Json
        }
        if (!$status.device_id -or $status.state -ne 'enrolled') { throw 'identity_requires_action' }
        if ($execution) { Invoke-AgentConfigurationCheck $binary $state $execution }
        Set-AgentServiceTreeAcl $state $sid 'State'
        Set-AgentServiceTreeAcl $stateParent $sid 'Binary' -RootOnly
        Assert-AgentServiceTreeAcl $root $sid 'Binary'
        Assert-AgentServiceTreeAcl $state $sid 'State'
        Invoke-AgentSc @('config','AegisAgent','start=','delayed-auto')
        Invoke-AgentSc @('failure','AegisAgent','reset=','86400','actions=','restart/15000/restart/30000/restart/60000')
        Start-Service -Name AegisAgent
        Wait-AgentRunning
        Assert-AgentServiceConfiguration (Get-CimInstance Win32_Service -Filter "Name='AegisAgent'") $binary $state $execution
        $record.phase='committed'; Write-AgentControlRecord $upgradePath $record
        Remove-Item -LiteralPath $upgradePath -Force
    } catch {
        if ($upgradeWritten) { Restore-AgentUpgrade $root $state $sid $execution }
        throw
    } finally {
        # Failed staging and previous binaries are kept for administrator review;
        # identity, journal, logs and unknown files are never replaced from backup.
    }
}
if ($MyInvocation.InvocationName -ne '.') { Install-AegisAgent $PSScriptRoot $Manager $ServerCa }
