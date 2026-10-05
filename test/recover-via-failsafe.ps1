# Fix the mutual-skip guard, redeploy, and let the fail-safe clean the simulated
# interrupted session (this also restores the Wi-Fi DNS the simulation broke).
$ErrorActionPreference = 'Continue'
Start-Transcript -Path 'C:\Users\mdroh\.zcode\workspace\default\CheatGuard_repo\test\failsafe-recover-output.txt' -Force | Out-Null
$netDir = 'C:\ProgramData\CheatGuard\network'

Write-Output '[1] close test CheatGuard instance (so the fail-safe sees an interrupted session)'
Get-Process -Name 'CheatGuard' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Write-Output ('    cheatguard processes now: ' + @(Get-Process -Name 'CheatGuard' -ErrorAction SilentlyContinue).Count)

Write-Output '[2] redeploy fixed helper'
Copy-Item 'C:\Users\mdroh\.zcode\workspace\default\CheatGuard_repo\resources\network-lockdown.ps1' (Join-Path $netDir 'network-lockdown.ps1') -Force

Write-Output '[3] broken state before fail-safe'
$wifi = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
Write-Output ('  dns on ' + $wifi.Name + ': ' + ((Get-DnsClientServerAddress -InterfaceIndex $wifi.ifIndex -AddressFamily IPv4).ServerAddresses -join ','))
Write-Output ('  leftover rules: ' + @(Get-NetFirewallRule -Group 'Cheat.Guard Strict Exam' -ErrorAction SilentlyContinue).Count)
Write-Output ('  state file exists: ' + (Test-Path (Join-Path $netDir 'firewall_state.json')))

Write-Output '[4] run -FailSafeCheck'
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script = Join-Path $netDir 'network-lockdown.ps1'
& $ps -NoProfile -ExecutionPolicy Bypass -File $script -FailSafeCheck

Write-Output '[5] clean state after fail-safe'
Write-Output ('  dns on ' + $wifi.Name + ' (expect DHCP/empty): ' + ((Get-DnsClientServerAddress -InterfaceIndex $wifi.ifIndex -AddressFamily IPv4).ServerAddresses -join ','))
Write-Output ('  leftover rules (expect 0): ' + @(Get-NetFirewallRule -Group 'Cheat.Guard Strict Exam' -ErrorAction SilentlyContinue).Count)
Write-Output ('  state file deleted: ' + (-not (Test-Path (Join-Path $netDir 'firewall_state.json'))))
Write-Output ('  failsafe log: ' + $(if (Test-Path (Join-Path $netDir 'failsafe-log.txt')) { (Get-Content (Join-Path $netDir 'failsafe-log.txt') -Tail 1) } else { 'MISSING' }))
Write-Output ('  deny on OneDrive-Desktop (expect 0 cheatguard-type): ' + @(icacls "C:\Users\mdroh\OneDrive\Desktop" 2>$null | Where-Object { $_ -match '\(DENY\)\(OI\)\(CI\)\(RX' }).Count)

Write-Output '[6] internet check (DNS resolution + TCP 443)'
Clear-DnsClientCache -ErrorAction SilentlyContinue
try {
    $r = Resolve-DnsName -Name 'www.google.com' -ErrorAction Stop | Select-Object -First 1
    Write-Output ('  resolved www.google.com -> ' + $r.IPAddress)
} catch { Write-Output ('  DNS RESOLUTION FAILED: ' + $_.Exception.Message) }
try {
    $c = New-Object System.Net.Sockets.TcpClient
    $a = $c.BeginConnect('www.google.com', 443, $null, $null)
    if ($a.AsyncWaitHandle.WaitOne(6000) -and $c.Connected) { Write-Output '  TCP 443 connect: OK' } else { Write-Output '  TCP 443 connect: FAILED' }
    $c.Close()
} catch { Write-Output ('  TCP 443 connect: FAILED - ' + $_.Exception.Message) }
Write-Output 'RECOVER_DONE'
Stop-Transcript | Out-Null
