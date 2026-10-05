# Deploys the fail-safe and runs a closed-loop test of it:
# 1. copy the new helper into ProgramData
# 2. register the permanent SYSTEM scheduled task
# 3. close the Cheat.Guard instance launched for testing
# 4. SIMULATE an interrupted session (deny ACE, 127.0.0.1 DNS, leftover rule, state file)
# 5. run -FailSafeCheck
# 6. verify the machine is fully clean again
$ErrorActionPreference = 'Continue'
Start-Transcript -Path 'C:\Users\mdroh\.zcode\workspace\default\CheatGuard_repo\test\failsafe-test-output.txt' -Force | Out-Null
$netDir = 'C:\ProgramData\CheatGuard\network'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

Write-Output '[1] copy helper'
Copy-Item 'C:\Users\mdroh\.zcode\workspace\default\CheatGuard_repo\resources\network-lockdown.ps1' (Join-Path $netDir 'network-lockdown.ps1') -Force

Write-Output '[2] register fail-safe task'
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script = Join-Path $netDir 'network-lockdown.ps1'
$action = New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -FailSafeCheck')
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650)
Register-ScheduledTask -TaskName 'CheatGuard SessionFailSafe' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force -ErrorAction Stop | Out-Null
Write-Output ('    task state: ' + (Get-ScheduledTask -TaskName 'CheatGuard SessionFailSafe').State)

Write-Output '[3] close test CheatGuard instance'
Get-Process -Name 'CheatGuard' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

Write-Output '[4] simulate interrupted session'
$testDir = 'C:\Users\mdroh\Documents\STRESSTEST'
New-Item -ItemType Directory -Path $testDir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $testDir 'work.txt') -Value 'exam work' -Encoding ASCII
icacls "$testDir" /deny "*${sid}:(OI)(CI)(RX,D)" | Out-Null
$wifi = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceIndex $wifi.ifIndex -ServerAddresses '127.0.0.1' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'Cheat.Guard - STRESS leftover' -Group 'Cheat.Guard Strict Exam' -Direction Outbound -Protocol TCP -RemotePort 9999 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
$profiles = @(Get-NetFirewallProfile | ForEach-Object {
    [ordered]@{ Name = $_.Name; Enabled = $_.Enabled.ToString(); DefaultOutboundAction = $_.DefaultOutboundAction.ToString() }
})
$falseState = [ordered]@{ Exists = $false; Kind = ''; Value = $null }
$state = [ordered]@{
    UserSid = $sid
    Profiles = $profiles
    Proxy = [ordered]@{ ProxyEnable = $falseState; ProxyServer = $falseState; ProxyOverride = $falseState; AutoConfigURL = $falseState }
    Dns = @()
    Doh = @()
    Fus = @{ Exists = $false }
    FileLocks = @($testDir)
}
$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $netDir 'firewall_state.json') -Encoding UTF8

Write-Output '--- BROKEN STATE CHECK ---'
Write-Output ('  deny present: ' + @(icacls "$testDir" | Where-Object { $_ -match '\(DENY\)' }).Count)
Write-Output ('  dns on ' + $wifi.Name + ': ' + ((Get-DnsClientServerAddress -InterfaceIndex $wifi.ifIndex -AddressFamily IPv4).ServerAddresses -join ','))
Write-Output ('  leftover rules: ' + @(Get-NetFirewallRule -Group 'Cheat.Guard Strict Exam' -ErrorAction SilentlyContinue).Count)
Write-Output ('  read test (expect FAIL): ' + $(try { Get-Content (Join-Path $testDir 'work.txt') -ErrorAction Stop; 'READABLE' } catch { 'ACCESS DENIED (as expected)' }))

Write-Output '[5] run -FailSafeCheck'
& $ps -NoProfile -ExecutionPolicy Bypass -File $script -FailSafeCheck
Write-Output ('    exit code: ' + $LASTEXITCODE)

Write-Output '--- CLEAN STATE CHECK ---'
Write-Output ('  deny present (expect 0): ' + @(icacls "$testDir" | Where-Object { $_ -match '\(DENY\)' }).Count)
Write-Output ('  dns on ' + $wifi.Name + ' (expect DHCP/empty): ' + ((Get-DnsClientServerAddress -InterfaceIndex $wifi.ifIndex -AddressFamily IPv4).ServerAddresses -join ','))
Write-Output ('  leftover rules (expect 0): ' + @(Get-NetFirewallRule -Group 'Cheat.Guard Strict Exam' -ErrorAction SilentlyContinue).Count)
Write-Output ('  read test (expect OK): ' + $(try { Get-Content (Join-Path $testDir 'work.txt') -ErrorAction Stop; 'READABLE' } catch { 'ACCESS DENIED' }))
Write-Output ('  state file deleted: ' + (-not (Test-Path (Join-Path $netDir 'firewall_state.json'))))
Write-Output ('  failsafe log: ' + $(if (Test-Path (Join-Path $netDir 'failsafe-log.txt')) { (Get-Content (Join-Path $netDir 'failsafe-log.txt') -Tail 1) } else { 'MISSING' }))
Remove-Item -LiteralPath $testDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Output 'TEST_DONE'
Stop-Transcript | Out-Null
