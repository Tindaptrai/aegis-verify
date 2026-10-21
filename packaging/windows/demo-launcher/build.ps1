[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CoreRelease,
    [Parameter(Mandatory=$true)][string]$Out,
    [string]$Compiler = (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not [IO.Path]::IsPathRooted($Out)) { throw 'output_must_be_absolute' }
$destination = [IO.Path]::GetFullPath($Out).TrimEnd('\')
if (Test-Path -LiteralPath $destination) { throw 'output_already_exists' }
$checkout = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..')).TrimEnd('\')
if ($destination.StartsWith($checkout + '\', [StringComparison]::OrdinalIgnoreCase) -or $destination -eq $checkout) { throw 'output_inside_checkout' }
if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($destination)) -PathType Container)) { throw 'output_parent_missing' }
$ancestor = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($destination))
while ($null -ne $ancestor) {
    if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'output_reparse_point' }
    $ancestor = $ancestor.Parent
}
$release = (Resolve-Path -LiteralPath $CoreRelease).Path.TrimEnd('\')
if ($destination.StartsWith($release + '\', [StringComparison]::OrdinalIgnoreCase) -or $destination -eq $release) { throw 'output_inside_core_release' }
$manifest = Join-Path $release 'SHA256SUMS.txt'
$inventory = @{}
foreach ($line in [IO.File]::ReadAllLines($manifest)) {
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw 'invalid_core_manifest' }
    $expected = $Matches[1]; $relative = $Matches[2]
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('\') -or @($relative.Split('/') | Where-Object { $_ -eq '..' -or $_ -eq '.' -or $_ -eq '' }).Count -ne 0 -or $inventory.ContainsKey($relative)) { throw 'unsafe_core_path' }
    $path = Join-Path $release $relative
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'core_hash_mismatch' }
    $inventory[$relative] = $expected
}
$files = @(Get-ChildItem -LiteralPath $release -Recurse -File)
foreach ($item in @(Get-Item -LiteralPath $release) + @(Get-ChildItem -LiteralPath $release -Recurse)) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'core_reparse_point' }
}
$actual = @($files | ForEach-Object { $_.FullName.Substring($release.Length + 1).Replace('\','/') } | Where-Object { $_ -ne 'SHA256SUMS.txt' })
if (@(Compare-Object @($inventory.Keys | Sort-Object) @($actual | Sort-Object)).Count -ne 0 -or -not $inventory.ContainsKey('aegis.exe')) { throw 'core_inventory_mismatch' }
foreach ($reserved in @('AEGIS-Demo.exe','AEGIS-Logo.png','AEGIS-Logo.ico','LOGO-PROMPT.md','HUONG-DAN.txt','LAUNCHER-BUILD-INFO.json')) {
    if ($inventory.ContainsKey($reserved)) { throw 'generated_file_collides_with_core' }
}
$coreInfo = Get-Content -LiteralPath (Join-Path $release 'BUILD-INFO.json') -Raw | ConvertFrom-Json
if ($coreInfo.application_version -ne '0.4.0' -or $coreInfo.mode -ne 'onefile' -or $coreInfo.architecture_bits -ne 64) { throw 'unsupported_core_release' }
$source = Join-Path $PSScriptRoot 'Launcher.cs'
$icon = Join-Path $PSScriptRoot 'assets/aegis-demo.ico'
$logo = Join-Path $PSScriptRoot 'assets/aegis-demo-logo.png'
$prompt = Join-Path $PSScriptRoot 'assets/LOGO-PROMPT.md'
$guide = Join-Path $PSScriptRoot 'HUONG-DAN.txt'
foreach ($required in @($source,$icon,$logo,$prompt,$guide,$Compiler)) { if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw 'build_input_missing' } }
[void][IO.Directory]::CreateDirectory($destination)
foreach ($file in $files) {
    $relative = $file.FullName.Substring($release.Length + 1)
    $target = Join-Path $destination $relative
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    [IO.File]::Copy($file.FullName,$target,$false)
}
$launcher = Join-Path $destination 'AEGIS-Demo.exe'
$arguments = @('/nologo','/target:winexe','/platform:x64','/optimize+','/codepage:65001',('/out:' + $launcher),('/win32icon:' + $icon),'/reference:System.Windows.Forms.dll,System.Drawing.dll,System.Web.Extensions.dll',$source)
& $Compiler @arguments
if ($LASTEXITCODE -ne 0) { throw 'launcher_compile_failed_output_retained' }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'assets/aegis-demo-logo.png') -Destination (Join-Path $destination 'AEGIS-Logo.png')
Copy-Item -LiteralPath $icon -Destination (Join-Path $destination 'AEGIS-Logo.ico')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'assets/LOGO-PROMPT.md') -Destination (Join-Path $destination 'LOGO-PROMPT.md')
Copy-Item -LiteralPath $guide -Destination (Join-Path $destination 'HUONG-DAN.txt')
$information = [ordered]@{
    kind='aegis_local_demo_launcher'; launcher_file_version=[Diagnostics.FileVersionInfo]::GetVersionInfo($launcher).FileVersion;
    core_version='0.4.0'; core_exe_sha256=$inventory['aegis.exe']; signed=$false;
    launcher_source_sha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant();
    icon_sha256=(Get-FileHash -LiteralPath $icon -Algorithm SHA256).Hash.ToLowerInvariant();
    compiler_file_version=[Diagnostics.FileVersionInfo]::GetVersionInfo($Compiler).FileVersion;
    runtime='Windows x64 with .NET Framework 4.8; Python and Node are not required';
    scope='Local offline demo launcher; the core executable and evidence contracts are unchanged'
}
$information | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $destination 'LAUNCHER-BUILD-INFO.json') -Encoding utf8
foreach ($relative in $inventory.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $destination $relative) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $inventory[$relative]) { throw 'copied_core_hash_mismatch' }
}
[pscustomobject]@{launcher=$launcher;output=$destination;core_files_verified=$inventory.Count;icon_frames=7} | ConvertTo-Json
