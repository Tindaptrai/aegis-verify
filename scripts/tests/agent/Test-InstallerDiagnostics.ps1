$ErrorActionPreference='Stop'
$library=Join-Path $PSScriptRoot 'InstallerDiagnostics.ps1'
if (!(Test-Path -LiteralPath $library)) { throw 'RED: safe installer diagnostics are not implemented' }
. $library
$code='a' * 64
$cases=@(
    @{text='state_invalid'; secret=''; want='state_invalid'},
    @{text='{"error":{"code":"pairing_denied"}}'; secret=''; want='pairing_denied'},
    @{text='private source says state_invalid'; secret=''; want='diagnostic_unknown'},
    @{text='{"stage":"installer","code":"hresult_-2147024891"}'; secret=''; want='hresult_-2147024891'},
    @{text='{"stage":"installer","code":"win32_999999"}'; secret=''; want='diagnostic_unknown'},
    @{text='{"stage":"installer","code":"state_invalid","private":"hidden"}'; secret=''; want='diagnostic_unknown'},
    @{text='{"stage":"installer","code":"state_invalid","code":"pairing_denied"}'; secret=''; want='diagnostic_unknown'},
    @{text="state_invalid`n$code"; secret=$code; want='installer_output_secret_leak'},
    @{text="PRIVATE KEY`nstate_invalid"; secret=''; want='installer_output_secret_leak'},
    @{text=('x' * 65537); secret=''; want='diagnostic_unknown'}
)
foreach ($case in $cases) {
    $result=Get-AgentCapturedDiagnostic $case.text $case.secret 'installer'
    $serialized=$result | ConvertTo-Json -Compress
    if ($result.code -cne $case.want -or $serialized.Length -gt 512 -or $serialized.Contains($code) -or $serialized.Contains('hidden') -or @($result.Keys).Count -ne 2) { throw 'Unsafe or incorrect diagnostic selection' }
}
try { throw (New-Object IO.IOException('sensitive source value')) } catch {
    $result=Get-AgentErrorDiagnostic $_ 'installer'
    if ($result.code -notmatch '^hresult_-?[0-9]+$' -or ($result | ConvertTo-Json -Compress).Contains('sensitive')) { throw 'Exception diagnostic leaked source values' }
}
$testPackage=Join-Path ([IO.Path]::GetTempPath()) ('aegis-diagnostic-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $testPackage | Out-Null
    foreach ($leak in @($false,$true)) {
        $body='param([string]$Manager,[string]$ServerCa) function Install-AegisAgent { $value=[Console]::In.ReadLine(); '
        if ($leak) { $body+='[Console]::Error.WriteLine($value); ' }
        $body+="throw 'state_invalid' }"
        [IO.File]::WriteAllText((Join-Path $testPackage 'Install-Agent.ps1'),$body)
        $start=New-Object Diagnostics.ProcessStartInfo
        $start.FileName="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $start.Arguments='-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot 'Invoke-WindowsInstallerDiagnostic.ps1') + '" -PackageRoot "' + $testPackage + '"'
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true
        $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
        $child=[Diagnostics.Process]::Start($start)
        $stdout=$child.StandardOutput.ReadToEndAsync(); $stderr=$child.StandardError.ReadToEndAsync()
        $child.StandardInput.WriteLine($code); $child.StandardInput.Close()
        if (!$child.WaitForExit(10000)) { $child.Kill(); throw 'Diagnostic wrapper child timeout' }
        $diagnostic=Get-AgentCapturedDiagnostic ($stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()) $code 'installer'
        $expected=if($leak){'installer_output_secret_leak'}else{'state_invalid'}
        if ($child.ExitCode -eq 0 -or $diagnostic.code -cne $expected) { throw 'Diagnostic child transport did not preserve safe failure classification' }
    }
} finally { if(Test-Path -LiteralPath $testPackage){Remove-Item -LiteralPath $testPackage -Recurse -Force} }
Write-Output '13 safe Windows diagnostic contracts passed; no SCM call made'
