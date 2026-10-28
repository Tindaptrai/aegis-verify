# Ordinary temporary files only: no service, registry, ACL or installed-state changes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
. (Join-Path $repo 'deploy/agent/windows/Install-Agent.ps1')
$temporaryParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$controlRoot=Join-Path $temporaryParent ('aegis-control-record-'+[Guid]::NewGuid().ToString('N'))
function Get-AgentControlRoot { return $controlRoot }
$phase='prepared';$checks=0
try {
    New-Item -ItemType Directory -Path $controlRoot | Out-Null
    $path=Join-Path $controlRoot 'upgrade.json'
    foreach($phase in @('prepared','promoted','committed')){
        Write-AgentControlRecord $path ([pscustomobject]@{schema_version=1;phase=$phase})
        $actual=[IO.File]::ReadAllText($path)|ConvertFrom-Json
        if($actual.schema_version -ne 1 -or $actual.phase -cne $phase){throw 'control_record_roundtrip_failed'}
        $checks++
    }
    if(@(Get-ChildItem -LiteralPath $controlRoot -Force).Count -ne 1){throw 'control_record_left_backup_or_temporary'}
    $checks++
    $phase='replacement_denied'
    $before=[IO.File]::ReadAllText($path)
    $held=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $rejected=$false
        try { Write-AgentControlRecord $path ([pscustomobject]@{schema_version=1;phase='prepared'}) }
        catch { $rejected=$true }
        if(!$rejected -or [IO.File]::ReadAllText($path) -cne $before){throw 'control_record_failed_replace_changed_destination'}
        $checks++
    } finally { $held.Dispose() }
    Write-Output "$checks control record contracts passed"
} catch {
    $exception=$_.Exception
    while($exception.InnerException){$exception=$exception.InnerException}
    [Console]::Error.WriteLine(('control_record_contract_failed phase={0} hresult={1}' -f $phase,$exception.HResult))
    exit 1
} finally {
    if([IO.Path]::GetFullPath($controlRoot) -cne $controlRoot -or [IO.Path]::GetDirectoryName($controlRoot) -cne $temporaryParent -or [IO.Path]::GetFileName($controlRoot) -cnotmatch '^aegis-control-record-[0-9a-f]{32}$'){throw 'control_record_cleanup_path_invalid'}
    if(Test-Path -LiteralPath $controlRoot){Remove-Item -LiteralPath $controlRoot -Recurse -Force}
}
