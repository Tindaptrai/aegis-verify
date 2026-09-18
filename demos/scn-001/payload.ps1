$facts = @{ Host = $env:COMPUTERNAME; User = $env:USERNAME; Pid = $PID }
Write-Output 'AEGIS_SAFE_DEMO_V1'
Write-Output ('AEGIS_PID=' + $facts.Pid)
