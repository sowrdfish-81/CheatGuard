# Rebuild the live session's firewall_state.json that the red-team attack deleted,
# so the running v1.3 helper can restore everything cleanly at session end.
$ErrorActionPreference = 'Continue'
Start-Transcript -Path 'C:\Users\mdroh\.zcode\workspace\default\CheatGuard_repo\test\reconstruct-output.txt' -Force | Out-Null
$netDir = 'C:\ProgramData\CheatGuard\network'
$sid = 'S-1-5-21-3386253252-3976114247-2349148618-1001'

$wifi = Get-NetAdapter | Where-Object { $_.Name -eq 'Wi-Fi' } | Select-Object -First 1
# The student's own pre-exam DNS setting (verified earlier today): 8.8.8.8, 8.8.4.4
$origDns = '8.8.8.8,8.8.4.4'

$fileLocks = @()
$lp = Join-Path $netDir 'lock-paths.txt'
if (Test-Path $lp) { $fileLocks = @(Get-Content $lp -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

$falseState = [ordered]@{ Exists = $false; Kind = ''; Value = $null }
$state = [ordered]@{
    UserSid = $sid
    Profiles = @(
        [ordered]@{ Name = 'Domain';  Enabled = 'True'; DefaultOutboundAction = 'NotConfigured' },
        [ordered]@{ Name = 'Private'; Enabled = 'True'; DefaultOutboundAction = 'NotConfigured' },
        [ordered]@{ Name = 'Public';  Enabled = 'True'; DefaultOutboundAction = 'NotConfigured' }
    )
    Proxy = [ordered]@{ ProxyEnable = $falseState; ProxyServer = $falseState; ProxyOverride = $falseState; AutoConfigURL = $falseState }
    Dns = @(@{ InterfaceIndex = $wifi.ifIndex; InterfaceAlias = $wifi.Name; StaticNameServer = $origDns; StaticNameServerV6 = '' })
    Doh = @()
    Fus = @{ Exists = $false; Value = $null }
    FileLocks = $fileLocks
}
$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $netDir 'firewall_state.json') -Encoding UTF8
Write-Output ('state written: ' + (Test-Path (Join-Path $netDir 'firewall_state.json')) + ' FileLocks=' + $fileLocks.Count + ' wifi ifIndex=' + $wifi.ifIndex)
Write-Output 'RECONSTRUCT_DONE'
Stop-Transcript | Out-Null
