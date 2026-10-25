# Runs without elevation against synthetic temporary files only.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../../../deploy/agent/windows/Install-Agent.ps1')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('aegis-state-reader-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$state = Join-Path $testRoot 'state.json'
$replacement = Join-Path $testRoot 'replacement.json'
$backup = Join-Path $testRoot 'backup.json'
$held=$null; $reader=$null
try {
    [IO.File]::WriteAllText($state, 'synthetic-old-snapshot')
    [IO.File]::WriteAllText($replacement, 'synthetic-new-snapshot')
    $held = Open-AgentStateSnapshot $state
    # Deterministic barrier: the real helper reader stays open throughout the
    # writer's atomic replacement. No retries or timing assumptions.
    [IO.File]::Replace($replacement, $state, $backup)
    $reader = New-Object IO.StreamReader($held)
    if ($reader.ReadToEnd() -cne 'synthetic-old-snapshot') { throw 'reader_lost_complete_snapshot' }
    if ([IO.File]::ReadAllText($state) -cne 'synthetic-new-snapshot') { throw 'writer_did_not_publish_snapshot' }
    $reader.Dispose(); $reader=$null; $held.Dispose(); $held=$null
    [IO.File]::WriteAllText($state, '{"manager_origin":"https://manager.invalid","server_ca_pem":"synthetic-public-ca"}')
    Assert-AgentPinnedConfiguration $testRoot 'https://manager.invalid' $null
    $refused=$false
    try { Assert-AgentPinnedConfiguration $testRoot 'https://other.invalid' $null } catch { if ($_.Exception.Message -eq 'configuration_mismatch') { $refused=$true } else { throw } }
    if (!$refused) { throw 'changed_origin_accepted' }
    [IO.File]::WriteAllText($state, ('x' * 65537))
    $refused=$false
    try { $oversized = Open-AgentStateSnapshot $state; $oversized.Dispose() } catch { if ($_.Exception.Message -eq 'state_invalid') { $refused=$true } else { throw } }
    if (!$refused) { throw 'oversized_state_accepted' }
    Write-Output '5 active-state sharing and pinned configuration contracts passed; no SCM call made'
} finally {
    if ($reader) { $reader.Dispose() }
    if ($held) { $held.Dispose() }
    foreach ($file in @($state, $replacement, $backup)) {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
    }
    Remove-Item -LiteralPath $testRoot
}
