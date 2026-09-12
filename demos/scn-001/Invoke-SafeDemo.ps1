# Reviewed SCN-001 lab runner. Default: read-only preflight. No policy override.
[CmdletBinding()]
param(
    [string]$KitDirectory,
    [string]$RunDirectory,
    [string]$RunId,
    [string]$RunLabel,
    [string]$ExpectedComputerName,
    [string]$AppliedRuleRevision,
    [string]$AppliedRuleSha256,
    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-AegisPath([string]$Value) {
    if ($Value.Length -gt 230 -or $Value -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9 _\.\\-]+$') {
        throw 'AEGIS_INVALID_LOCAL_PATH'
    }
    foreach ($part in $Value.Substring(3).Split('\')) {
        if (-not $part -or $part -in @('.', '..') -or $part -ne $part.Trim() -or
            $part.EndsWith('.') -or $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
            throw 'AEGIS_INVALID_LOCAL_PATH'
        }
    }
    $cursor = $Value
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'AEGIS_REPARSE_PATH'
            }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}

function Read-AegisBytes([string]$Path) {
    Assert-AegisPath $Path
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or $item.Length -gt 65536) { throw 'AEGIS_INVALID_KIT_FILE' }
    return ,([IO.File]::ReadAllBytes($Path))
}

function Get-AegisHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Assert-AegisRunDirectory([string]$Path) {
    Assert-AegisPath $Path
    $cursor = $Path
    while ($cursor) {
        if (Test-Path -LiteralPath (Join-Path $cursor '.git')) { throw 'AEGIS_RUN_OUTPUT_IN_REPOSITORY' }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    if (Test-Path -LiteralPath $Path) { throw 'AEGIS_RUN_OUTPUT_EXISTS' }
    if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($Path)) -PathType Container)) {
        throw 'AEGIS_RUN_PARENT_MISSING'
    }
}

function Write-AegisNewFile([string]$Path, [string]$Text) {
    Assert-AegisPath $Path
    $bytes = ([Text.UTF8Encoding]::new($false)).GetBytes($Text)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) }
    finally { $stream.Dispose() }
}

function Assert-AegisTelemetry {
    $sysmon = @(Get-Service -Name 'Sysmon', 'Sysmon64' -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Running' })
    $agent = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
    if ($sysmon.Count -eq 0 -or -not $agent -or $agent.Status -ne 'Running') {
        throw 'AEGIS_TELEMETRY_SERVICE_NOT_RUNNING'
    }
    foreach ($entry in @(
        @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1},
        @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104}
    )) {
        try {
            $channel = Get-WinEvent -ListLog $entry.LogName
            if (-not $channel.IsEnabled) { throw 'disabled' }
            # Read access plus at least one prior event; not proof of future collection.
            $record = Get-WinEvent -FilterHashtable $entry -MaxEvents 1
            if (-not $record) { throw 'no record' }
        } catch { throw 'AEGIS_TELEMETRY_LOG_UNAVAILABLE' }
    }
}

function Get-AegisPreflight {
    if (-not $ExpectedComputerName -or $ExpectedComputerName -cne [Environment]::MachineName) {
        throw 'AEGIS_WRONG_HOST'
    }
    if ($RunLabel -cnotin @('A', 'B', 'C', 'Rehearsal') -or
        $AppliedRuleRevision -cnotin @('baseline', 'fixed') -or
        ($RunLabel -cin @('A', 'B') -and $AppliedRuleRevision -cne 'baseline') -or
        ($RunLabel -ceq 'C' -and $AppliedRuleRevision -cne 'fixed')) {
        throw 'AEGIS_INVALID_RUN_SELECTION'
    }
    if ($RunId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { throw 'AEGIS_INVALID_RUN_ID' }
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or
        -not [Environment]::Is64BitProcess) { throw 'AEGIS_WINDOWS_POWERSHELL_51_REQUIRED' }
    $systemExe = Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ((Get-Process -Id $PID).Path -ine $systemExe) { throw 'AEGIS_UNEXPECTED_POWERSHELL_HOST' }
    Assert-AegisPath $KitDirectory
    $kitBytes = Read-AegisBytes (Join-Path $KitDirectory 'kit.json')
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $kit = $utf8.GetString($kitBytes) | ConvertFrom-Json
    if ($kit -isnot [pscustomobject]) { throw 'AEGIS_INVALID_KIT_MANIFEST' }
    foreach ($field in @('kind', 'kit_version', 'scenario_id', 'scenario_version',
                        'target_host', 'lab_directory', 'payload_sha256')) {
        if ($kit.$field -isnot [string]) { throw 'AEGIS_INVALID_KIT_MANIFEST' }
    }
    if ($kit.filenames -isnot [array] -or $kit.artifact_sha256 -isnot [pscustomobject]) {
        throw 'AEGIS_INVALID_KIT_MANIFEST'
    }
    foreach ($name in @('lab_update.ps1', 'maintenance_check.ps1', 'baseline.xml', 'fixed.xml')) {
        if ($kit.artifact_sha256.$name -isnot [string] -or
            $kit.artifact_sha256.$name -cnotmatch '^[0-9a-f]{64}$') { throw 'AEGIS_INVALID_KIT_MANIFEST' }
    }
    if ($kit.kind -cne 'safe_demo_kit' -or $kit.kit_version -cne '0.1.0' -or
        $kit.scenario_id -cne 'SCN-001' -or $kit.scenario_version -cne '0.1.0' -or
        $kit.target_host -cne $ExpectedComputerName -or $kit.lab_directory -cne $KitDirectory -or
        $kit.filenames.Count -ne 2 -or $kit.filenames[0] -cne 'lab_update.ps1' -or
        $kit.filenames[1] -cne 'maintenance_check.ps1') { throw 'AEGIS_INVALID_KIT_MANIFEST' }
    if ($kit.rule_id -isnot [int] -or $kit.rule_id -lt 100000 -or $kit.rule_id -gt 120000 -or
        $kit.parent_sid -isnot [int] -or $kit.parent_sid -lt 1 -or $kit.parent_sid -gt 999999 -or
        $kit.parent_sid -eq $kit.rule_id) { throw 'AEGIS_INVALID_KIT_MANIFEST' }
    # Do not trust a mutable manifest to authorize arbitrary payload bytes.
    $reviewed = [Text.Encoding]::ASCII.GetBytes("Write-Output 'AEGIS_SAFE_DEMO_V1'`nWrite-Output ('AEGIS_PID=' + `$PID)`n")
    $reviewedHash = Get-AegisHash $reviewed
    foreach ($name in @('lab_update.ps1', 'maintenance_check.ps1')) {
        $bytes = Read-AegisBytes (Join-Path $KitDirectory $name)
        if ([Convert]::ToBase64String($bytes) -cne [Convert]::ToBase64String($reviewed)) {
            throw 'AEGIS_UNREVIEWED_PAYLOAD'
        }
        if ($kit.payload_sha256 -cne $reviewedHash -or $kit.artifact_sha256.$name -cne $reviewedHash) {
            throw 'AEGIS_PAYLOAD_HASH_MISMATCH'
        }
    }
    foreach ($name in @('baseline.xml', 'fixed.xml')) {
        $hash = Get-AegisHash (Read-AegisBytes (Join-Path $KitDirectory $name))
        if ($kit.artifact_sha256.$name -cne $hash) { throw 'AEGIS_RULE_HASH_MISMATCH' }
    }
    $ruleName = $AppliedRuleRevision + '.xml'
    if ($AppliedRuleSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $AppliedRuleSha256 -cne $kit.artifact_sha256.$ruleName) { throw 'AEGIS_RULE_HASH_MISMATCH' }
    Assert-AegisRunDirectory $RunDirectory
    Assert-AegisTelemetry
    $filename = if ($RunLabel -ceq 'A') { 'lab_update.ps1' } else { 'maintenance_check.ps1' }
    return @{ Kit=$kit; Exe=$systemExe; PayloadHash=$reviewedHash;
        PayloadPath=(Join-Path $KitDirectory $filename) }
}

function Assert-AegisChildResult([int]$ExitCode, [bool]$TimedOut, [int]$ChildId,
                                [string]$OutputText, [string]$ErrorText) {
    $expected = "AEGIS_SAFE_DEMO_V1`nAEGIS_PID=$ChildId`n"
    if ($ExitCode -ne 0 -or $TimedOut -or $ErrorText.Length -ne 0 -or
        $OutputText.Replace("`r`n", "`n") -cne $expected) { throw 'AEGIS_EXECUTION_FAILED' }
}

function Invoke-AegisExecution($Checked) {
    Assert-AegisRunDirectory $RunDirectory
    # Never resume/overwrite a partial run. Operator must choose a fresh RunId/directory.
    $null = New-Item -ItemType Directory -Path $RunDirectory -ErrorAction Stop
    $windowStart = [DateTimeOffset]::UtcNow
    $windowEnd = $windowStart.AddSeconds(120)
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    $arguments = '-NoLogo -NoProfile -NonInteractive -File "' + $Checked.PayloadPath + '"'
    $report = [ordered]@{
        kind='safe_demo_execution'; execution_manifest_version='0.1.0';
        run_id=$RunId; run_label=$RunLabel; target_host=$ExpectedComputerName;
        scenario_id=$Checked.Kit.scenario_id; scenario_version=$Checked.Kit.scenario_version;
        payload_sha256=$Checked.PayloadHash; payload_path=$Checked.PayloadPath;
        rule_id=$Checked.Kit.rule_id; parent_sid=$Checked.Kit.parent_sid;
        applied_rule_revision_declared=$AppliedRuleRevision; applied_rule_sha256_declared=$AppliedRuleSha256;
        rule_state_verified_remotely=$false; runner_pid=$PID; child_pid=$null;
        executable=$Checked.Exe; arguments=$arguments;
        window_start_utc=$windowStart.ToString('o'); window_planned_end_utc=$windowEnd.ToString('o');
        launch_utc=$null; exit_observed_utc=$null; window_observed_end_utc=$null;
        exit_code=$null; timed_out=$false; status='started'; failure_code=$null
    }
    Write-AegisNewFile (Join-Path $RunDirectory 'execution-start.json') ($report | ConvertTo-Json -Depth 6)
    $child = $null
    try {
        Start-Sleep -Seconds 10
        # Re-check immediately before launch. Use a private directory with no concurrent writers.
        $currentHash = Get-AegisHash (Read-AegisBytes $Checked.PayloadPath)
        if ($currentHash -cne $Checked.PayloadHash) { throw 'AEGIS_PAYLOAD_CHANGED' }
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $Checked.Exe
        $start.Arguments = $arguments
        $start.WorkingDirectory = $KitDirectory
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $child = [Diagnostics.Process]::new()
        $child.StartInfo = $start
        $report.launch_utc = [DateTimeOffset]::UtcNow.ToString('o')
        if (-not $child.Start()) { throw 'AEGIS_CHILD_START_FAILED' }
        $report.child_pid = $child.Id
        Write-AegisNewFile (Join-Path $RunDirectory 'execution-launched.json') ($report | ConvertTo-Json -Depth 6)
        $stdout = $child.StandardOutput.ReadToEndAsync()
        $stderr = $child.StandardError.ReadToEndAsync()
        if (-not $child.WaitForExit(30000)) {
            $report.timed_out = $true
            $child.Kill()
            if (-not $child.WaitForExit(5000)) { throw 'AEGIS_CHILD_STOP_UNCONFIRMED' }
        }
        $report.exit_observed_utc = [DateTimeOffset]::UtcNow.ToString('o')
        $report.exit_code = $child.ExitCode
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw 'AEGIS_CHILD_OUTPUT_TIMEOUT' }
        Write-AegisNewFile (Join-Path $RunDirectory 'stdout.txt') $stdout.Result
        Write-AegisNewFile (Join-Path $RunDirectory 'stderr.txt') $stderr.Result
        Assert-AegisChildResult $report.exit_code $report.timed_out $report.child_pid $stdout.Result $stderr.Result
        $report.status = 'executed'
    } catch {
        $report.status = 'failed'
        $code = $_.Exception.Message
        $report.failure_code = if ($code -cmatch '^AEGIS_[A-Z0-9_]+$') { $code } else { 'AEGIS_EXECUTION_ERROR' }
    } finally {
        if ($child) {
            try {
                if (-not $child.HasExited) {
                    $child.Kill()
                    $null = $child.WaitForExit(5000)
                }
            } catch { $report.status = 'failed'; $report.failure_code = 'AEGIS_CHILD_STOP_UNCONFIRMED' }
            $child.Dispose()
        }
    }
    # A system-clock correction cannot extend the run indefinitely.
    while ($elapsed.Elapsed.TotalSeconds -lt 120) { Start-Sleep -Milliseconds 200 }
    $elapsed.Stop()
    $report['elapsed_seconds'] = $elapsed.Elapsed.TotalSeconds
    $report.window_observed_end_utc = [DateTimeOffset]::UtcNow.ToString('o')
    Write-AegisNewFile (Join-Path $RunDirectory 'execution.json') ($report | ConvertTo-Json -Depth 6)
    if ($report.status -cne 'executed') { throw $report.failure_code }
    [Console]::WriteLine('{"kind":"safe_demo_execution","status":"executed_not_evaluated"}')
}

try {
    $checked = Get-AegisPreflight
    if (-not $Execute) {
        [Console]::WriteLine('{"kind":"safe_demo_preflight","status":"ready","executed":false}')
    } else {
        Invoke-AegisExecution $checked
    }
    exit 0
} catch {
    $safeCode = $_.Exception.Message
    if ($safeCode -cnotmatch '^AEGIS_[A-Z0-9_]+$') { $safeCode = 'AEGIS_PREFLIGHT_OR_IO_ERROR' }
    [Console]::Error.WriteLine($safeCode)
    exit 2
}
