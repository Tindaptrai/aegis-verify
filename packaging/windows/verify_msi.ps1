# Default mode opens the MSI database read-only. Installation is CI-only and opt-in.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Msi,
    [string]$Release,
    [string]$ExtractTo,
    [switch]$InstallTest,
    [switch]$AcknowledgeDisposableRunner,
    [string]$BaselineMsi,
    [string]$LogDirectory,
    [string]$Python,
    [string]$SmokeScript,
    [string]$Result,
    [string]$ExpectedVersion = '0.4.0'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$checkout = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')).TrimEnd('\')
$upgradeCode = '{B68E2F81-6D3D-5CED-A16E-875DD032A752}'
$script:installer = $null
$script:database = $null
$script:steps = [Collections.Generic.List[object]]::new()
$script:logsCreated = $false

function Require([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function New-OutputPath([string]$Value) {
    $full = [IO.Path]::GetFullPath($Value).TrimEnd('\')
    Require (-not (Test-Path -LiteralPath $full)) 'output_exists'
    Require (-not ($full -eq $checkout -or $full.StartsWith($checkout + '\', [StringComparison]::OrdinalIgnoreCase))) 'output_inside_checkout'
    Require (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($full)) -PathType Container) 'output_parent_missing'
    # Reject reparse points in every existing ancestor before allocating output.
    $ancestor = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($full))
    while ($null -ne $ancestor) {
        Require (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'output_reparse_point'
        $ancestor = $ancestor.Parent
    }
    return $full
}

function Query-Msi([string]$Sql, [string[]]$Columns) {
    $view = $script:database.OpenView($Sql)
    try {
        [void]$view.Execute()
        while ($null -ne ($record = $view.Fetch())) {
            try {
                $row = [ordered]@{}
                for ($index = 0; $index -lt $Columns.Length; $index++) {
                    $row[$Columns[$index]] = [string]$record.StringData($index + 1)
                }
                [pscustomobject]$row
            } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
        }
    } finally {
        [void]$view.Close()
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
}

function Table([string]$Name, [string[]]$Columns) {
    $quoted = @($Columns | ForEach-Object { '`' + $_ + '`' }) -join ', '
    return @(Query-Msi ('SELECT ' + $quoted + ' FROM `' + $Name + '`') $Columns)
}

function Properties {
    $properties = @{}
    foreach ($row in (Table 'Property' @('Property', 'Value'))) { $properties[$row.Property] = $row.Value }
    return $properties
}

function Long-Name([string]$Value) { return (($Value.Split(':')[0]).Split('|')[-1]) }

function Directory-Relative([string]$Id, [hashtable]$Directories, [string]$Root) {
    $parts = [Collections.Generic.List[string]]::new()
    $seen = @{}
    while ($Id -ne $Root) {
        Require ($Directories.ContainsKey($Id) -and -not $seen.ContainsKey($Id)) 'invalid_directory_tree'
        $seen[$Id] = $true
        $row = $Directories[$Id]
        $name = Long-Name $row.DefaultDir
        if ($name -ne '.') { $parts.Insert(0, $name) }
        $Id = $row.Directory_Parent
        Require (-not [string]::IsNullOrEmpty($Id)) 'directory_outside_expected_root'
    }
    return ($parts -join '/')
}

function Read-Contract {
    $properties = Properties
    Require ($properties.ProductVersion -eq $ExpectedVersion) 'product_version_mismatch'
    Require ($properties.ALLUSERS -eq '1') 'per_machine_required'
    Require ($properties.UpgradeCode -eq $upgradeCode) 'upgrade_code_mismatch'
    $summary = $script:database.SummaryInformation(0)
    try { Require ($summary.Property(7) -match '^x64;') 'x64_package_required' }
    finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary) }
    $tableNames = @(Query-Msi 'SELECT `Name` FROM `_Tables`' @('Name') | ForEach-Object { $_.Name })
    foreach ($forbidden in @('CustomAction', 'ServiceInstall', 'ServiceControl', 'Environment', 'WixFirewallException')) {
        if ($tableNames -contains $forbidden) {
            $count = @(Query-Msi ('SELECT * FROM `' + $forbidden + '`') @('first')).Count
            Require ($count -eq 0) ('forbidden_table_' + $forbidden)
        }
    }
    $directories = @{}
    foreach ($row in (Table 'Directory' @('Directory', 'Directory_Parent', 'DefaultDir'))) {
        Require ($row.Directory -notmatch '^(AppDataFolder|LocalAppDataFolder|PersonalFolder|UserProfileFolder|StartupFolder|DesktopFolder)$') 'user_data_directory_forbidden'
        $directories[$row.Directory] = $row
    }
    Require ($directories.ContainsKey('INSTALLFOLDER')) 'install_directory_missing'
    Require ($directories.INSTALLFOLDER.Directory_Parent -eq 'ProgramFiles64Folder') 'program_files_64_required'
    Require ((Long-Name $directories.INSTALLFOLDER.DefaultDir) -eq 'AEGIS Verify') 'install_directory_name_mismatch'
    $components = @{}
    foreach ($row in (Table 'Component' @('Component', 'ComponentId', 'Directory_', 'Attributes', 'Condition', 'KeyPath'))) {
        Require (([int]$row.Attributes -band 256) -ne 0) 'component_must_be_64_bit'
        Require (([int]$row.Attributes -band 16) -eq 0) 'permanent_component_forbidden'
        $components[$row.Component] = $row
    }
    $files = @{}
    $fileRows = @(Table 'File' @('File', 'Component_', 'FileName', 'FileSize', 'Version', 'Language', 'Attributes', 'Sequence'))
    foreach ($row in $fileRows) {
        Require (([int]$row.Attributes -band 8192) -eq 0) 'external_uncompressed_file_forbidden'
        $component = $components[$row.Component_]
        $directory = Directory-Relative $component.Directory_ $directories 'INSTALLFOLDER'
        $relative = @($directory, (Long-Name $row.FileName)) | Where-Object { $_ -ne '' }
        $relative = $relative -join '/'
        Require (-not $files.ContainsKey($relative)) 'duplicate_payload_path'
        $files[$relative] = $row
    }
    Require ($files.ContainsKey('aegis/aegis.exe')) 'application_executable_missing'
    Require ($files['aegis/aegis.exe'].Version -eq ($ExpectedVersion + '.0')) 'executable_file_version_mismatch'
    Require ($files.ContainsKey('QUICKSTART.md') -and $files.ContainsKey('SHA256SUMS.txt')) 'release_metadata_missing'
    $registry = @{}
    foreach ($row in (Table 'Registry' @('Registry', 'Root', 'Key', 'Name', 'Value', 'Component_'))) {
        Require ($row.Root -in @('2', '-1') -and $row.Key -eq 'Software\AEGIS Verify') 'registry_scope_mismatch'
        $registry[$row.Registry] = $row
    }
    Require (@($registry.Values | Where-Object { $_.Root -eq '2' -and $_.Name -eq 'Version' -and $_.Value -eq $ExpectedVersion }).Count -eq 1) 'machine_registration_version_missing'
    Require (@($registry.Values | Where-Object { $_.Root -eq '2' -and $_.Name -eq 'InstallDir' -and $_.Value -eq '[INSTALLFOLDER]' }).Count -eq 1) 'machine_registration_directory_missing'
    $shortcuts = @(Table 'Shortcut' @('Shortcut', 'Directory_', 'Name', 'Component_', 'Target', 'Arguments', 'WkDir'))
    Require ($shortcuts.Count -eq 2) 'two_common_shortcuts_required'
    foreach ($row in $shortcuts) {
        [void](Directory-Relative $row.Directory_ $directories 'ProgramMenuFolder')
        Require ($row.Target -match '^\[(System64Folder|#F_[a-f0-9]+)\]') 'shortcut_must_be_non_advertised'
        $component = $components[$row.Component_]
        Require (([int]$component.Attributes -band 4) -ne 0 -and $registry.ContainsKey($component.KeyPath)) 'shortcut_registry_keypath_required'
        $key = $registry[$component.KeyPath]
        Require ($key.Root -eq '-1' -and $key.Name -eq 'ShortcutsInstalled' -and $key.Value -eq '#1') 'shortcut_keypath_mismatch'
    }
    Require (@($shortcuts | Where-Object { $_.Target -eq '[System64Folder]cmd.exe' -and $_.Arguments -match '--help' }).Count -eq 1) 'console_shortcut_missing'
    $upgrades = @(Table 'Upgrade' @('UpgradeCode', 'VersionMin', 'VersionMax', 'Attributes', 'ActionProperty'))
    Require (@($upgrades | Where-Object { $_.UpgradeCode -eq $upgradeCode -and $_.ActionProperty -eq 'WIX_UPGRADE_DETECTED' -and $_.VersionMax -eq $ExpectedVersion }).Count -eq 1) 'upgrade_detection_missing'
    Require (@($upgrades | Where-Object { $_.UpgradeCode -eq $upgradeCode -and $_.ActionProperty -eq 'WIX_DOWNGRADE_DETECTED' -and $_.VersionMin -eq $ExpectedVersion -and (([int]$_.Attributes -band 2) -ne 0) }).Count -eq 1) 'downgrade_detection_missing'
    $launch = @(Table 'LaunchCondition' @('Condition', 'Description'))
    Require (@($launch | Where-Object { $_.Condition -match 'WIX_DOWNGRADE_DETECTED' }).Count -ge 1) 'downgrade_rejection_missing'
    Require (@($launch | Where-Object { $_.Condition -match '^ALLUSERS\s*=\s*1$' }).Count -eq 1) 'per_machine_launch_condition_required'
    $sequence = @{}
    foreach ($row in (Table 'InstallExecuteSequence' @('Action', 'Condition', 'Sequence'))) { $sequence[$row.Action] = [int]$row.Sequence }
    Require ($sequence.ContainsKey('RemoveExistingProducts') -and $sequence.ContainsKey('InstallInitialize') -and $sequence.ContainsKey('ProcessComponents')) 'upgrade_action_missing'
    Require ($sequence.RemoveExistingProducts -gt $sequence.InstallInitialize -and $sequence.RemoveExistingProducts -lt $sequence.ProcessComponents) 'upgrade_removal_schedule_mismatch'
    $media = @(Table 'Media' @('DiskId', 'LastSequence', 'Cabinet'))
    Require ($media.Count -ge 1) 'cabinet_missing'
    $streams = @(Query-Msi 'SELECT `Name` FROM `_Streams`' @('Name') | ForEach-Object { $_.Name })
    foreach ($row in $media) {
        Require ($row.Cabinet.StartsWith('#') -and $streams -contains $row.Cabinet.Substring(1)) 'embedded_cabinet_required'
    }
    return @{ properties = $properties; files = $files; file_count = $files.Count; shortcuts = $shortcuts.Count }
}

function Compare-Payload([string]$Root, [hashtable]$Files) {
    $actual = @(Get-ChildItem -LiteralPath $Root -Recurse -File | ForEach-Object { $_.FullName.Substring($Root.TrimEnd('\').Length + 1).Replace('\', '/') })
    Require (@(Compare-Object @($Files.Keys | Sort-Object) @($actual | Sort-Object)).Count -eq 0) 'payload_file_set_mismatch'
    foreach ($relative in $Files.Keys) {
        $expected = Join-Path $Release $relative
        $observed = Join-Path $Root $relative
        Require ((Get-FileHash -LiteralPath $expected -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $observed -Algorithm SHA256).Hash) ('payload_bytes_mismatch: ' + $relative)
    }
}

function Invoke-Installer([string]$Label, [string[]]$Arguments, [int[]]$ExpectedCodes = @(0, 3010)) {
    $log = Join-Path $LogDirectory ($Label + '.log')
    $arguments = @($Arguments) + @('/qn', '/norestart', 'REBOOT=ReallySuppress', '/L*V', ('"' + $log + '"'))
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32/msiexec.exe') -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    $step = [ordered]@{ step = $Label; exit_code = $process.ExitCode; reboot_required = ($process.ExitCode -eq 3010); log = $log }
    $script:steps.Add($step)
    Require ($ExpectedCodes -contains $process.ExitCode) ('installer_failed_' + $Label + '_' + $process.ExitCode)
    return $process.ExitCode
}

function Run-Smoke([string]$Root, [string]$Label) {
    $exe = Join-Path $Root 'aegis/aegis.exe'
    $version = & $exe --version
    Require ($LASTEXITCODE -eq 0 -and $version -eq ('AEGIS Verify ' + $ExpectedVersion)) 'runtime_version_mismatch'
    & $Python -I -X utf8 $SmokeScript --exe $exe --result (Join-Path $LogDirectory ($Label + '-smoke.json'))
    Require ($LASTEXITCODE -eq 0) ('artifact_smoke_failed_' + $Label)
}

try {
    # These guards execute before reading any package or allocating output.
    if ($InstallTest) {
        Require ([bool]$AcknowledgeDisposableRunner) 'install_test_acknowledgement_required'
        Require ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted') 'install_test_requires_disposable_github_runner'
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        Require ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'install_test_requires_administrator'
        Require (-not [string]::IsNullOrEmpty($BaselineMsi)) 'synthetic_baseline_required'
    }
    if ($Result) { Require (-not (Test-Path -LiteralPath $Result)) 'result_exists' }
    if ($ExtractTo) { $ExtractTo = New-OutputPath $ExtractTo }
    if ($InstallTest -or $ExtractTo) {
        Require ($Release -and $LogDirectory -and $Python -and $SmokeScript) 'runtime_verification_arguments_required'
        $LogDirectory = New-OutputPath $LogDirectory
        $Release = (Resolve-Path -LiteralPath $Release).Path.TrimEnd('\')
        $Python = (Resolve-Path -LiteralPath $Python).Path
        $SmokeScript = (Resolve-Path -LiteralPath $SmokeScript).Path
    }
    $Msi = (Resolve-Path -LiteralPath $Msi).Path
    $script:installer = New-Object -ComObject WindowsInstaller.Installer
    $script:database = $script:installer.OpenDatabase($Msi, 0)
    $contract = Read-Contract
    $productCode = $contract.properties.ProductCode
    if ($Release) {
        $Release = (Resolve-Path -LiteralPath $Release).Path.TrimEnd('\')
        $releaseFiles = @(Get-ChildItem -LiteralPath $Release -Recurse -File | ForEach-Object { $_.FullName.Substring($Release.Length + 1).Replace('\', '/') })
        Require (@(Compare-Object @($contract.files.Keys | Sort-Object) @($releaseFiles | Sort-Object)).Count -eq 0) 'release_file_set_mismatch'
    }
    $report = [ordered]@{ passed = $false; msi = $Msi; sha256 = (Get-FileHash -LiteralPath $Msi -Algorithm SHA256).Hash.ToLower(); version = $ExpectedVersion; product_code = $productCode; upgrade_code = $upgradeCode; tables_read_only = $true; payload_files = $contract.file_count; shortcuts = $contract.shortcuts; extracted = $false; installed = $false; steps = $script:steps }
    if ($ExtractTo -or $InstallTest) {
        [void](New-Item -ItemType Directory -Path $LogDirectory)
        $script:logsCreated = $true
    }
    if ($ExtractTo) {
        [void](New-Item -ItemType Directory -Path $ExtractTo)
        [void](Invoke-Installer 'administrative-extraction' @('/a', ('"' + $Msi + '"'), ('TARGETDIR="' + $ExtractTo + '"')))
        $executables = @(Get-ChildItem -LiteralPath $ExtractTo -Filter aegis.exe -File -Recurse)
        Require ($executables.Count -eq 1) 'extracted_executable_ambiguous'
        $root = $executables[0].Directory.Parent.FullName
        Compare-Payload $root $contract.files
        Run-Smoke $root 'extracted'
        $report.extracted = $true
    }
    if ($InstallTest) {
        $BaselineMsi = (Resolve-Path -LiteralPath $BaselineMsi).Path
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($script:database)
        $script:database = $script:installer.OpenDatabase($BaselineMsi, 0)
        $baseline = Properties
        Require ($baseline.AEGIS_SYNTHETIC_UPGRADE_FIXTURE -eq '1' -and $baseline.ProductVersion -eq '0.3.99' -and $baseline.UpgradeCode -eq $upgradeCode -and $baseline.ProductCode -ne $productCode) 'invalid_synthetic_baseline'
        $installRoot = Join-Path $env:ProgramFiles 'AEGIS Verify'
        $menuRoot = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'AEGIS Verify'
        Require (-not (Test-Path -LiteralPath $installRoot) -and -not (Test-Path -LiteralPath $menuRoot)) 'existing_installation_forbidden'
        Require (@($script:installer.RelatedProducts($upgradeCode)).Count -eq 0) 'related_product_already_installed'
        $sentinelRoot = Join-Path $LogDirectory 'external-user-data'
        [void](New-Item -ItemType Directory -Path $sentinelRoot)
        $sentinel = Join-Path $sentinelRoot 'keep.txt'
        [IO.File]::WriteAllText($sentinel, 'AEGIS installer must preserve this external user data.')
        $sentinelHash = (Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash
        $owned = $false
        try {
            $owned = $true
            [void](Invoke-Installer 'install-current' @('/i', ('"' + $Msi + '"')))
            Compare-Payload $installRoot $contract.files
            Require (@(Get-ChildItem -LiteralPath $menuRoot -Filter '*.lnk').Count -eq 2) 'installed_shortcuts_missing'
            Require ((Get-ItemProperty -LiteralPath 'HKLM:\Software\AEGIS Verify').Version -eq $ExpectedVersion) 'installed_registry_version_mismatch'
            Run-Smoke $installRoot 'installed'
            Remove-Item -LiteralPath (Join-Path $installRoot 'QUICKSTART.md')
            [void](Invoke-Installer 'repair-current' @('/fa', $productCode))
            Compare-Payload $installRoot $contract.files
            [void](Invoke-Installer 'uninstall-current' @('/x', $productCode))
            Require (-not (Test-Path -LiteralPath $installRoot) -and -not (Test-Path -LiteralPath $menuRoot) -and -not (Test-Path -LiteralPath 'HKLM:\Software\AEGIS Verify')) 'uninstall_residue'
            [void](Invoke-Installer 'install-synthetic-baseline' @('/i', ('"' + $BaselineMsi + '"')))
            Require (Test-Path -LiteralPath (Join-Path $installRoot 'CI_SYNTHETIC_OLDER_ONLY.txt')) 'synthetic_removed_marker_missing'
            Require ((Get-FileHash -LiteralPath (Join-Path $installRoot 'QUICKSTART.md')).Hash -ne (Get-FileHash -LiteralPath (Join-Path $Release 'QUICKSTART.md')).Hash) 'synthetic_changed_marker_missing'
            [void](Invoke-Installer 'upgrade-to-current' @('/i', ('"' + $Msi + '"')))
            Require (-not (Test-Path -LiteralPath (Join-Path $installRoot 'CI_SYNTHETIC_OLDER_ONLY.txt'))) 'upgrade_left_removed_file'
            Require ($script:installer.ProductState($baseline.ProductCode) -eq -1) 'upgraded_baseline_still_registered'
            Require ((Get-ItemProperty -LiteralPath 'HKLM:\Software\AEGIS Verify').Version -eq $ExpectedVersion) 'upgraded_registry_version_mismatch'
            Compare-Payload $installRoot $contract.files
            Run-Smoke $installRoot 'upgraded'
            [void](Invoke-Installer 'reject-synthetic-downgrade' @('/i', ('"' + $BaselineMsi + '"')) @(1603))
            $downgradeLog = Get-Content -LiteralPath (Join-Path $LogDirectory 'reject-synthetic-downgrade.log') -Raw
            Require ($downgradeLog -match 'WIX_DOWNGRADE_DETECTED' -and $downgradeLog -match 'newer version') 'downgrade_reason_not_confirmed'
            Compare-Payload $installRoot $contract.files
            Require ((Get-ItemProperty -LiteralPath 'HKLM:\Software\AEGIS Verify').Version -eq $ExpectedVersion) 'downgrade_changed_registry_version'
            [void](Invoke-Installer 'uninstall-upgraded' @('/x', $productCode))
            Require (-not (Test-Path -LiteralPath $installRoot) -and -not (Test-Path -LiteralPath $menuRoot) -and -not (Test-Path -LiteralPath 'HKLM:\Software\AEGIS Verify')) 'upgraded_uninstall_residue'
            Require (@($script:installer.RelatedProducts($upgradeCode)).Count -eq 0) 'uninstalled_product_still_registered'
            Require ((Get-FileHash -LiteralPath $sentinel).Hash -eq $sentinelHash) 'external_user_data_changed'
            $report.installed = $true
        } finally {
            if ($owned) {
                foreach ($code in @($productCode, $baseline.ProductCode)) {
                    if ($script:installer.ProductState($code) -ne -1) {
                        [void](Invoke-Installer ('cleanup-' + $code.Trim('{}')) @('/x', $code) @(0, 3010, 1605))
                    }
                }
            }
            Require ((Get-FileHash -LiteralPath $sentinel).Hash -eq $sentinelHash) 'external_user_data_changed'
        }
    }
    $report.passed = $true
    if ($Result) {
        Require (-not (Test-Path -LiteralPath $Result)) 'result_exists'
        $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Result -Encoding utf8
    }
    $report | ConvertTo-Json -Depth 8
    exit 0
} catch {
    if ($script:logsCreated) {
        $script:steps | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $LogDirectory 'installer-steps.json') -Encoding utf8
    }
    [Console]::Error.WriteLine('AEGIS MSI verification: ' + $_.Exception.Message)
    exit 2
} finally {
    if ($null -ne $script:database) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($script:database) }
    if ($null -ne $script:installer) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($script:installer) }
}
