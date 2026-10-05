# One-off repair for a stale (interrupted) Cheat.Guard session on THIS machine:
# removes every deny ACE the session placed, restores firewall/DNS/DoH state from
# the saved snapshot, and deletes the stale session files. Elevated run required.
$ErrorActionPreference = 'Continue'

$netDir = 'C:\ProgramData\CheatGuard\network'
$statePath = Join-Path $netDir 'firewall_state.json'
$lockPathsPath = Join-Path $netDir 'lock-paths.txt'

# ---- SIDs to clean: the session's student SID + every local account found ----
$sids = New-Object System.Collections.Generic.HashSet[string]
if (Test-Path $statePath) {
    try { [void]$sids.Add([string](Get-Content $statePath -Raw | ConvertFrom-Json).UserSid) } catch {}
}
Get-LocalUser | ForEach-Object {
    try { [void]$sids.Add($_.SID.Value) } catch {}
}
try { [void]$sids.Add([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) } catch {}
Write-Output ("SIDs to clean: " + ($sids -join ', '))

# ---- Paths to clean: recorded lock list + blind sweep set ----
$paths = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
if (Test-Path $lockPathsPath) {
    foreach ($line in @(Get-Content $lockPathsPath -ErrorAction SilentlyContinue)) {
        $p = $line.Trim()
        if ($p) { [void]$paths.Add($p) }
    }
}
[System.IO.DriveInfo]::GetDrives() | ForEach-Object {
    try { if ($_.IsReady) { [void]$paths.Add($_.RootDirectory.FullName) } } catch {}
}
foreach ($n in @('Documents','Downloads','Music','Pictures','Videos','Saved Games',
                 'Contacts','Links','OneDrive','3D Objects','Searches','Desktop')) {
    $p = Join-Path $env:USERPROFILE $n
    if (Test-Path -LiteralPath $p) {
        [void]$paths.Add($p)
        Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue | ForEach-Object { [void]$paths.Add($_.FullName) }
    }
}
Write-Output ("Paths to clean: " + $paths.Count)

# ---- Remove deny ACEs ----
$cleaned = 0
foreach ($p in $paths) {
    if (-not (Test-Path -LiteralPath $p)) { continue }
    foreach ($sid in $sids) {
        try { icacls "$p" /remove:d "*$sid" | Out-Null } catch {}
    }
    $out = icacls "$p" 2>$null
    $denyLeft = @($out | Where-Object { $_ -match '\(DENY\)' })
    if ($denyLeft.Count -eq 0) { $cleaned++ }
    else { Write-Output ("  DENY STILL PRESENT: " + $p); $denyLeft | ForEach-Object { Write-Output ("    " + $_) } }
}
Write-Output ("Paths clean of deny ACEs: " + $cleaned)

# ---- Firewall: remove our rules, restore outbound default from state ----
Get-NetFirewallRule -Group 'Cheat.Guard Strict Exam' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
if (Test-Path $statePath) {
    try {
        $state = Get-Content $statePath -Raw | ConvertFrom-Json
        foreach ($p in @($state.Profiles)) {
            $action = if ([string]$p.DefaultOutboundAction -eq 'NotConfigured') { 'NotConfigured' } else { [string]$p.DefaultOutboundAction }
            try { Set-NetFirewallProfile -Profile $p.Name -DefaultOutboundAction $action -ErrorAction Stop } catch {}
        }
        # ---- DNS: restore from snapshot then reset anything static-loopback ----
        foreach ($e in @($state.Dns)) {
            try {
                $servers = @([string]$e.StaticNameServer -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne '127.0.0.1' -and $_ -ne '::1' })
                if ($servers.Count -gt 0) { Set-DnsClientServerAddress -InterfaceIndex $e.InterfaceIndex -ServerAddresses $servers -ErrorAction Stop }
                else { Set-DnsClientServerAddress -InterfaceIndex $e.InterfaceIndex -ResetServerAddresses -ErrorAction Stop }
            } catch {}
        }
    } catch { Write-Output ("State restore warning: " + $_.Exception.Message) }
}
Get-NetAdapter | ForEach-Object {
    try { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction Stop } catch {}
}

# ---- Browser DoH policies ----
foreach ($kv in @(@('HKLM:\SOFTWARE\Policies\Google\Chrome','DnsOverHttpsMode'),
                  @('HKLM:\SOFTWARE\Policies\Microsoft\Edge','DnsOverHttpsMode'),
                  @('HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS','Enabled'))) {
    try { Remove-ItemProperty -LiteralPath $kv[0] -Name $kv[1] -ErrorAction SilentlyContinue } catch {}
}

Clear-DnsClientCache -ErrorAction SilentlyContinue

# ---- Delete stale session files ----
foreach ($f in @('firewall_state.json','active-config.json','ready.marker','stop.marker',
                 'restored.marker','error.txt','egress-status.txt','lock-status.txt','lock-paths.txt',
                 'allowed-ips.txt','network-lockdown.ps1')) {
    Remove-Item -LiteralPath (Join-Path $netDir $f) -Force -ErrorAction SilentlyContinue
}

# ---- Verification ----
Write-Output '--- VERIFY ---'
$denyAny = 0
foreach ($p in $paths) {
    if (-not (Test-Path -LiteralPath $p)) { continue }
    $out = icacls "$p" 2>$null
    if (@($out | Where-Object { $_ -match '\(DENY\)' }).Count -gt 0) { $denyAny++ }
}
Write-Output ("Paths with remaining DENY entries: " + $denyAny)
$rulesLeft = @(Get-NetFirewallRule -Group 'Cheat.Guard Strict Exam' -ErrorAction SilentlyContinue).Count
Write-Output ("Cheat.Guard firewall rules left: " + $rulesLeft)
$dnsBad = 0
foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
    $guid = $a.InterfaceGuid
    foreach ($root in @('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces',
                        'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces')) {
        try {
            $v = [string](Get-ItemProperty -LiteralPath "$root\$guid" -Name NameServer -ErrorAction Stop).NameServer
            if ($v -match '127\.0\.0\.1|::1') { $dnsBad++; Write-Output ("  LOOPBACK DNS STILL ON: " + $a.Name + " -> " + $v) }
        } catch {}
    }
}
Write-Output ("Adapters with loopback DNS: " + $dnsBad)
Write-Output ("Profiles outbound: " + ((Get-NetFirewallProfile | ForEach-Object { $_.Name + '=' + $_.DefaultOutboundAction }) -join ', '))
Write-Output 'REPAIR_DONE'
