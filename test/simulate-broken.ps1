# Simulate ONLY the broken state of an interrupted session. The scheduled task
# (every 10 min, SYSTEM) should clean it without any manual intervention.
$ErrorActionPreference = 'Continue'
Start-Transcript -Path 'C:\Users\mdroh\.zcode\workspace\default\CheatGuard_repo\test\simulate-output.txt' -Force | Out-Null
$netDir = 'C:\ProgramData\CheatGuard\network'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

Get-Process -Name 'CheatGuard' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$testDir = 'C:\Users\mdroh\Documents\STRESSTEST'
New-Item -ItemType Directory -Path $testDir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $testDir 'work.txt') -Value 'exam work' -Encoding ASCII
icacls "$testDir" /deny "*${sid}:(OI)(CI)(RX,D)" | Out-Null
$wifi = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
$origDns = (Get-DnsClientServerAddress -InterfaceIndex $wifi.ifIndex -AddressFamily IPv4).ServerAddresses -join ','
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
    Dns = @(@{ InterfaceIndex = $wifi.ifIndex; InterfaceAlias = $wifi.Name; StaticNameServer = $origDns; StaticNameServerV6 = '' })
    Doh = @()
    Fus = @{ Exists = $false }
    FileLocks = @($testDir)
}
$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $netDir 'firewall_state.json') -Encoding UTF8

Write-Output ('wifi=' + $wifi.Name + ' originalDns=[' + $origDns + ']')
Write-Output ('broken: deny=' + @(icacls "$testDir" | Where-Object { $_ -match '\(DENY\)' }).Count + ' dns=[' + ((Get-DnsClientServerAddress -InterfaceIndex $wifi.ifIndex -AddressFamily IPv4).ServerAddresses -join ',') + '] rules=' + @(Get-NetFirewallRule -Group 'Cheat.Guard Strict Exam' -ErrorAction SilentlyContinue).Count + ' state=' + (Test-Path (Join-Path $netDir 'firewall_state.json')))
Write-Output 'SIMULATED - now waiting for the scheduled task to clean it'
Stop-Transcript | Out-Null
