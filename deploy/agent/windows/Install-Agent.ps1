[CmdletBinding()]
param([string]$Manager, [string]$ServerCa)
$ErrorActionPreference = 'Stop'

function Assert-AgentAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'administrator_required' }
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
            if ($Kind -eq 'Binary' -and $ServiceSid -and $rule.IdentityReference.Value -eq $ServiceSid -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write)) { throw 'binary_service_writable' }
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
        if ($allowed -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'service_tree_owner_invalid' }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $allowed -notcontains $rule.IdentityReference.Value) { throw 'service_tree_permissions_invalid' }
        }
    }
}
function Assert-AgentServiceConfiguration($Service,[string]$Binary,[string]$State) {
    if (!$Service) { return }
    $expected = '"' + $Binary + '" service --state-dir "' + $State + '"'
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
        public static string Read() {
            IntPtr manager=IntPtr.Zero, service=IntPtr.Zero;
            try {
                manager=OpenSCManagerW(null,null,1); // SC_MANAGER_CONNECT
                if (manager==IntPtr.Zero) throw new InvalidOperationException("service_security_query_failed");
                service=OpenServiceW(manager,"AegisAgent",0x20000); // READ_CONTROL
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
    $backup = $Root + '.backup-' + [Guid]::NewGuid().ToString('N')
    $backedUp = $false; $promoted = $false
    try {
        if (Test-Path -LiteralPath $Root) { Move-Item -LiteralPath $Root -Destination $backup; $backedUp=$true }
        Move-Item -LiteralPath $Stage -Destination $Root; $promoted=$true
        & $Activate
        if ($backedUp) { Assert-AgentNoLinks $backup; Remove-Item -LiteralPath $backup -Recurse -Force }
    } catch {
        if ($Deactivate) { & $Deactivate }
        if ($backedUp) {
            if ($promoted) { Assert-AgentNoLinks $Root; Remove-Item -LiteralPath $Root -Recurse -Force }
            Move-Item -LiteralPath $backup -Destination $Root
        }
        throw
    }
}
function Assert-AgentPinnedConfiguration([string]$State,[string]$Origin,[string]$CaPath) {
    $path = Join-Path $State 'state.json'
    if (!(Test-Path -LiteralPath $path)) { return }
    # The CLI validates the complete bounded snapshot before this comparison.
    if ((Get-Item -LiteralPath $path).Length -gt 65536) { throw 'state_invalid' }
    $config = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    if ($Origin -and $Origin -cne $config.manager_origin) { throw 'configuration_mismatch' }
    if ($CaPath) {
        Assert-AgentNoLinks $CaPath
        $provided = ([IO.File]::ReadAllText($CaPath) -replace '\s','')
        if ($provided -cne ($config.server_ca_pem -replace '\s','')) { throw 'configuration_mismatch' }
    }
}
function Install-AegisAgent([string]$PackageRoot,[string]$Origin,[string]$CaPath) {
    Assert-AgentAdministrator
    $verified = @(Get-VerifiedAgentPackage $PackageRoot)
    $root = Join-Path $env:ProgramFiles 'AEGIS Agent'
    $stateParent = Join-Path $env:ProgramData 'AEGIS'
    $state = Join-Path $env:ProgramData 'AEGIS/Agent'
    $binary = Join-Path $root 'bin/aegis-agent.exe'
    Assert-AgentNoLinks $root; Assert-AgentNoLinks $state
    $existing = Get-CimInstance Win32_Service -Filter "Name='AegisAgent'"
    Assert-AgentServiceConfiguration $existing $binary $state
    if ($existing) { Assert-AgentNativeServiceAcl }
    $sid = Get-AgentServiceSid
    Assert-AgentProtectedTree $root 'Binary' $sid
    Assert-AgentProtectedTree $state 'State' $sid
    # A pre-existing dedicated parent must not permit replacement of the protected child.
    if (Test-Path -LiteralPath $stateParent) { Assert-AgentProtectedTree $stateParent 'Binary' $sid -RootOnly }
    if (!(Test-Path -LiteralPath (Join-Path $state 'state.json')) -and (!$Origin -or !$CaPath)) { throw 'manager_and_server_ca_required' }
    if ($CaPath) { Assert-AgentNoLinks $CaPath; if (!(Test-Path -LiteralPath $CaPath -PathType Leaf)) { throw 'server_ca_missing' } }
    $stage = $root + '.stage-' + [Guid]::NewGuid().ToString('N')
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
        Stop-AgentService
        if ($existing) { Invoke-AgentSc @('config','AegisAgent','start=','disabled') }
        Invoke-AgentBinaryPromotion $stage $root {
        if (!$existing) {
            $command = '"' + $binary + '" service --state-dir "' + $state + '"'
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
        Set-AgentServiceTreeAcl $state $sid 'State'
        Set-AgentServiceTreeAcl $stateParent $sid 'Binary' -RootOnly
        Assert-AgentServiceTreeAcl $root $sid 'Binary'
        Assert-AgentServiceTreeAcl $state $sid 'State'
        Invoke-AgentSc @('config','AegisAgent','start=','delayed-auto')
        Invoke-AgentSc @('failure','AegisAgent','reset=','86400','actions=','restart/15000/restart/30000/restart/60000')
        Start-Service -Name AegisAgent
        Wait-AgentRunning
        } {
            if (Get-Service -Name AegisAgent -ErrorAction SilentlyContinue) { Stop-AgentService; Invoke-AgentSc @('config','AegisAgent','start=','disabled') }
        }
    } catch {
        if (Get-Service -Name AegisAgent -ErrorAction SilentlyContinue) { Stop-AgentService; Invoke-AgentSc @('config','AegisAgent','start=','disabled') }
        throw
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    }
}
if ($MyInvocation.InvocationName -ne '.') { Install-AegisAgent $PSScriptRoot $Manager $ServerCa }
