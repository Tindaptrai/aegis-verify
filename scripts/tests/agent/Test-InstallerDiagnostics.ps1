$ErrorActionPreference='Stop'
$library=Join-Path $PSScriptRoot 'InstallerDiagnostics.ps1'
if (!(Test-Path -LiteralPath $library)) { throw 'RED: safe installer diagnostics are not implemented' }
. $library
if (!(Get-Command Get-AgentStatusDiagnostic -ErrorAction SilentlyContinue)) { throw 'status_diagnostic_projection_missing' }
$statusCases=@(
    @{text='{"error":{"code":"state_invalid"}}';want='state_invalid'},
    @{text="{`"error`":{`"code`":`"state_permissions_invalid`"}}`r`n";want='state_permissions_invalid'},
    @{text='{"error":{"code":"PRIVATE"}}';want='status_failed'},
    @{text='{"error":{"code":"state_invalid","raw":"PRIVATE"}}';want='status_failed'},
    @{text='{"error":{"code":"state_invalid","code":"state_locked"}}';want='status_failed'},
    @{text='{"error":{"code":"state_invalid"},"raw":"PRIVATE"}';want='status_failed'},
    @{text="{`"error`":{`"code`":`"state_invalid`"}}`nPRIVATE";want='status_failed'},
    @{text='{"stage":"status","code":"state_invalid"}';want='status_failed'},
    @{text='{"error":{"code":3}}';want='status_failed'},
    @{text='{"error":{"error":{"code":"state_invalid"}}}';want='status_failed'},
    @{text='PRIVATE KEY';want='status_failed'},
    @{text=('x'*513);want='status_failed'}
)
foreach($case in $statusCases){
    $result=Get-AgentStatusDiagnostic $case.text
    if($result.stage -cne 'status' -or $result.code -cne $case.want -or @($result.Keys).Count -ne 2 -or ($result|ConvertTo-Json -Compress).Contains('PRIVATE')){throw 'status_diagnostic_projection_failed'}
}
# Extract the real reader without entering any disposable service action.
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-WindowsService.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'status_reader_parse_failed'}
$definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Read-NativeStatus'},$false)
. ([scriptblock]::Create($definition.Extent.Text))
function Invoke-NativeStatusCommand { return $script:statusResult }
$binary='synthetic-unopened-agent';$stateDirectory='synthetic-unopened-state';$ExpectedDeviceId='synthetic-id'
foreach($case in @(
    @{stderr='{"error":{"code":"state_invalid"}}';exit=3;want='state_invalid'},
    @{stderr='PRIVATE KEY';exit=3;want='status_failed'},
    @{stderr=('x'*513);exit=3;want='status_failed'},
    @{stderr='{"error":{"code":"state_invalid"},"extra":"PRIVATE"}';exit=3;want='status_failed'}
)){
    $script:statusResult=@{stdout='PRIVATE_STDOUT';stderr=$case.stderr;exit_code=$case.exit}
    $script:AgentInnerDiagnostic=$null;$failure=$null;$output=$null
    try{$output=Read-NativeStatus}catch{$failure=$_.Exception.Message}
    if($failure -cne 'status_failed' -or $null -ne $output -or $script:AgentInnerDiagnostic.stage -cne 'status' -or $script:AgentInnerDiagnostic.code -cne $case.want){throw 'status_reader_failed_to_capture_closed_child_error'}
}
$script:statusResult=@{stdout='{"device_id":"synthetic-id","state":"identity_denied"}';stderr='';exit_code=0}
$status=Read-NativeStatus
if($status.device_id -cne 'synthetic-id' -or $status.state -cne 'identity_denied'){throw 'status_reader_success_changed'}
$script:AgentInnerDiagnostic=$null
# Exercise the actual process transport with an inert temporary executable;
# arguments/streams/exit handling are real, and SCM is never called.
$transport=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-NativeStatusCommand'},$false)
. ([scriptblock]::Create($transport.Extent.Text))
$installerAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../../../deploy/agent/windows/Install-Agent.ps1'),[ref]$tokens,[ref]$errors)
$argument=$installerAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertTo-AgentNativeArgument'},$false)
. ([scriptblock]::Create($argument.Extent.Text))
$transportRoot=Join-Path ([IO.Path]::GetTempPath()) ('aegis-status-diagnostic-'+[guid]::NewGuid().ToString('N'))
try{
    New-Item -ItemType Directory -Path $transportRoot | Out-Null
    $binary=Join-Path $transportRoot 'inert status.exe'
    Add-Type -OutputAssembly $binary -OutputType ConsoleApplication -TypeDefinition @'
using System;
public static class InertStatusDiagnostic {
    public static int Main(string[] args) {
        if(args.Length!=3 || args[0]!="status" || args[1]!="--state-dir") return 2;
        if(args[2]=="success state & args") {Console.Write("{\"device_id\":\"synthetic-id\",\"state\":\"identity_denied\"}");return 0;}
        if(args[2]=="oversize") {Console.Error.Write(new string('x',513));return 3;}
        if(args[2]=="stdout oversize") {Console.Out.Write(new string('x',4096));return 3;}
        Console.Out.Write("PRIVATE_STDOUT");Console.Error.WriteLine("{\"error\":{\"code\":\"state_invalid\"}}");return 3;
    }
}
'@
    $stateDirectory='success state & args';$status=Read-NativeStatus
    if($status.device_id -cne 'synthetic-id' -or $status.state -cne 'identity_denied'){throw 'status_transport_arguments_or_success_invalid'}
    foreach($case in @(@{state='failure';want='state_invalid'},@{state='oversize';want='status_failed'})){
        $stateDirectory=$case.state;$script:AgentInnerDiagnostic=$null;$failure=$null;$output=$null
        try{$output=Read-NativeStatus}catch{$failure=$_.Exception.Message}
        if($failure -cne 'status_failed' -or $null -ne $output -or $script:AgentInnerDiagnostic.code -cne $case.want){throw 'status_transport_failed_to_capture_closed_error'}
    }
    $stateDirectory='stdout oversize';$failure=$null
    try{Read-NativeStatus|Out-Null}catch{$failure=$_.Exception.Message}
    if($failure -cne 'status_failed'){throw 'status_transport_stdout_cap_failed'}
} finally{
    $target=[IO.Path]::GetFullPath($transportRoot)
    if([IO.Path]::GetDirectoryName($target) -cne [IO.Path]::GetTempPath().TrimEnd('\') -or [IO.Path]::GetFileName($target) -cnotmatch '^aegis-status-diagnostic-[0-9a-f]{32}$'){throw 'status_transport_cleanup_path_invalid'}
    if(Test-Path -LiteralPath $target){Remove-Item -LiteralPath $target -Recurse -Force}
}
$script:AgentInnerDiagnostic=$null
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
foreach ($kind in @('ParameterBindingException','MethodException','ItemNotFoundException','CommandNotFoundException','PropertyNotFoundException')) {
    try { throw (New-Object ('Management.Automation.' + $kind)('sensitive argument value')) } catch {
        $category=@{ParameterBindingException='exception_parameterbinding';MethodException='exception_method';ItemNotFoundException='exception_itemnotfound';CommandNotFoundException='exception_commandnotfound';PropertyNotFoundException='exception_propertynotfound'}[$kind]
        $result=Get-AgentErrorDiagnostic $_ 'preflight'
        if ($result.code -cne $category -or ($result | ConvertTo-Json -Compress).Contains('sensitive')) { throw 'Unknown PowerShell preflight failure category' }
    }
}
$testPackage=Join-Path ([IO.Path]::GetTempPath()) ('aegis-diagnostic-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $testPackage | Out-Null
    foreach ($scenario in @('fixed','leak','double')) {
        $body='param([string]$Manager,[string]$ServerCa) function Install-AegisAgent { $value=[Console]::In.ReadLine(); '
        if ($scenario -eq 'leak') { $body+='[Console]::Error.WriteLine($value); ' }
        if ($scenario -eq 'double') { $body+="try { throw 'state_invalid' } catch { throw 'service_operation_failed' } }" }
        else { $body+="throw 'state_invalid' }" }
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
        $outText=$stdout.GetAwaiter().GetResult(); $errText=$stderr.GetAwaiter().GetResult()
        $diagnostic=Get-AgentCapturedDiagnostic ($outText + $errText) $code 'installer'
        $expected=if($scenario -eq 'leak'){'installer_output_secret_leak'}else{'state_invalid'}
        if ($child.ExitCode -eq 0 -or $diagnostic.code -cne $expected) { throw 'Diagnostic child transport did not preserve safe failure classification' }
        if ($scenario -ne 'leak' -and ($outText.Trim() -ne '' -or $errText.Trim() -cne '{"stage":"installer","code":"state_invalid"}')) { throw 'Diagnostic child exposed raw failure text' }
    }
} finally { if(Test-Path -LiteralPath $testPackage){Remove-Item -LiteralPath $testPackage -Recurse -Force} }
Write-Output '40 safe Windows diagnostic contracts passed; no SCM call made'
