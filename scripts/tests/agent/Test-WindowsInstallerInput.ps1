# Inert PS5.1 transport contract: no native service installation or state access.
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
. (Join-Path $PSScriptRoot 'InstallerDiagnostics.ps1')
# Load the real transport function without executing the guarded SCM entrypoint.
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-WindowsService.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'native_helper_parse_failed'}
$transport=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-ClosedInstaller'},$true)
if(!$transport){throw 'native_transport_missing'}
$PackageRoot=Join-Path ([IO.Path]::GetTempPath()) ('aegis-input-contract-' + [Guid]::NewGuid().ToString('N'))
$resolved=[IO.Path]::GetFullPath($PackageRoot)
if (![IO.Path]::GetDirectoryName($resolved).Equals([IO.Path]::GetTempPath().TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)) { throw 'unexpected_test_root' }
$ManagerOrigin=$null; $ServerCa=$null
$originalEncoding=[Console]::InputEncoding
try {
    New-Item -ItemType Directory -Path $PackageRoot | Out-Null
    foreach($file in @('Invoke-WindowsInstallerDiagnostic.ps1','InstallerDiagnostics.ps1','native-diagnostic-codes.txt')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination (Join-Path $PackageRoot $file)
    }
    # Preserve the exact function signature and a real script path for PSScriptRoot.
    $transportPath=Join-Path $PackageRoot 'transport.ps1'
    [IO.File]::WriteAllText($transportPath,$transport.Extent.Text)
    . $transportPath
    $probe=Join-Path $PackageRoot 'input-probe.exe'
    Add-Type -OutputAssembly $probe -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.IO;
public static class NativeInputProbe {
    public static int Main(string[] args) {
        using (var input = Console.OpenStandardInput())
        using (var bytes = new MemoryStream()) {
            input.CopyTo(bytes);
            var value = bytes.ToArray();
            var expected = Int32.Parse(args[0]);
            var valid = value.Length == expected;
            if (expected == 66 && valid) {
                for (int i=0; i<64; i++) valid &= value[i] == (byte)'a';
                valid &= value[64] == 13 && value[65] == 10;
            }
            // Only a fixed result crosses the diagnostic wrapper. Input is never echoed.
            if (!valid) { Console.Error.WriteLine("pairing_code_invalid"); return 1; }
            Console.WriteLine("input_validated");
            return 0;
        }
    }
}
'@
    # Reproduce the runner's UTF8 console encoding, including its preamble.
    [Console]::InputEncoding=[Text.Encoding]::UTF8
    foreach($case in @(@{expected=66;hasCode=$true;accepted=$true},@{expected=0;hasCode=$false;accepted=$true},@{expected=0;hasCode=$true;accepted=$false})) {
        $expected=$case.expected
        $body='param([string]$Manager,[string]$ServerCa) function Install-AegisAgent { & (Join-Path $PSScriptRoot ''input-probe.exe'') ' + $expected + '; if($LASTEXITCODE -ne 0){throw ''pairing_code_invalid''} }'
        [IO.File]::WriteAllText((Join-Path $PackageRoot 'Install-Agent.ps1'),$body)
        $script:AgentInnerDiagnostic=$null
        $testCode=if($case.hasCode){'a' * 64}else{$null}
        $accepted=$false
        try { Invoke-ClosedInstaller $testCode; $accepted=$true }
        catch {
            if(!$script:AgentInnerDiagnostic -or $script:AgentInnerDiagnostic.code -ne 'pairing_code_invalid') { throw 'Unexpected inert transport failure; output withheld' }
        }
        finally { $testCode=$null }
        if([Console]::InputEncoding.CodePage -ne 65001 -or [Console]::InputEncoding.GetPreamble().Length -ne 3) { throw 'transport_changed_caller_encoding' }
        if($accepted -ne $case.accepted){throw 'Native child did not receive exact closed stdin bytes; output withheld'}
    }
    Write-Output '3 native Windows stdin contracts passed; no SCM call made'
} finally {
    [Console]::InputEncoding=$originalEncoding
    if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
