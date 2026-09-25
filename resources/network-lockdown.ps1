param(
    [Parameter(Mandatory=$true)][string]$Config,
    [switch]$RecoverOnly
)

$ErrorActionPreference = 'Stop'
$cfg = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
$stateFile = $cfg.stateFile
$readyFile = $cfg.readyFile
$stopFile = $cfg.stopFile
$restoredFile = $cfg.restoredFile
$errorFile = $cfg.errorFile
$protectRequestFile = $cfg.protectRequestFile
$protectDoneFile = $cfg.protectDoneFile
$allowedIpFile = [string]$cfg.allowedIpFile
$egressStatusFile = [string]$cfg.egressStatusFile
$verifyHost = [string]$cfg.verifyHost
$fusKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$groupName = 'Cheat.Guard Strict Exam'
$proxyKey = "Registry::HKEY_USERS\$($cfg.userSid)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The network helper is not running as Administrator. Approve the UAC prompt with an administrator account.'
    }
}

function Ensure-FirewallServices {
    foreach ($name in @('BFE','MpsSvc')) {
        $svc = Get-Service -Name $name -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            try { Start-Service -Name $name -ErrorAction Stop } catch {
                throw "Windows Firewall dependency '$name' is not running and could not be started: $($_.Exception.Message)"
            }
        }
    }
    if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        throw 'Windows NetSecurity PowerShell module is unavailable on this computer.'
    }
}

function Get-RegState([string]$Path, [string]$Name) {
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        $value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $value) { return [ordered]@{ Exists=$false; Kind=''; Value=$null } }
        $kind = $key.GetValueKind($Name).ToString()
        return [ordered]@{ Exists=$true; Kind=$kind; Value=$value }
    } catch {
        return [ordered]@{ Exists=$false; Kind=''; Value=$null }
    }
}

function Set-RegFromState([string]$Path, [string]$Name, $State) {
    if (-not $State.Exists) {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        return
    }
    $type = if ($State.Kind -eq 'DWord') { 'DWord' } elseif ($State.Kind -eq 'QWord') { 'QWord' } elseif ($State.Kind -eq 'ExpandString') { 'ExpandString' } else { 'String' }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $State.Value -PropertyType $type -Force | Out-Null
}

function Notify-InternetSettings {
    try {
        if (-not ('CheatGuard.WinInetNative' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace CheatGuard {
    public static class WinInetNative {
        [DllImport("wininet.dll", SetLastError=true)]
        public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    }
}
"@
        }
        [CheatGuard.WinInetNative]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
        [CheatGuard.WinInetNative]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
    } catch {}
}

function Get-BrowserPaths {
    $paths = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    $names = @('chrome','msedge','firefox','brave','opera','opera_gx','vivaldi','iexplore')
    foreach ($n in $names) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            try { if ($_.Path -and (Test-Path -LiteralPath $_.Path)) { [void]$paths.Add($_.Path) } } catch {}
        }
    }
    $candidates = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe",
        "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
        "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Mozilla Firefox\firefox.exe",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe",
        "$env:LOCALAPPDATA\Vivaldi\Application\vivaldi.exe",
        "$env:LOCALAPPDATA\Programs\Opera\opera.exe",
        "$env:LOCALAPPDATA\Programs\Opera GX\opera.exe"
    )
    foreach ($p in $candidates) { if ($p -and (Test-Path -LiteralPath $p)) { [void]$paths.Add($p) } }
    return @($paths)
}

# Browser DNS-over-HTTPS policies. A browser resolving names itself over HTTPS would
# never consult the local DNS filter, so DoH is forced off for the exam and restored after.
$dohPolicies = @(
    [ordered]@{ Path='HKLM:\SOFTWARE\Policies\Google\Chrome';                Name='DnsOverHttpsMode'; Value='off'; Type='String' },
    [ordered]@{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge';               Name='DnsOverHttpsMode'; Value='off'; Type='String' },
    [ordered]@{ Path='HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'; Name='Enabled';          Value=0;     Type='DWord'  }
)

function Get-DohState {
    $out = [ordered]@{}
    foreach ($p in $dohPolicies) { $out[($p.Path + '|' + $p.Name)] = Get-RegState $p.Path $p.Name }
    return $out
}

function Disable-BrowserDoh {
    foreach ($p in $dohPolicies) {
        try {
            if (-not (Test-Path -LiteralPath $p.Path)) { New-Item -Path $p.Path -Force | Out-Null }
            New-ItemProperty -LiteralPath $p.Path -Name $p.Name -Value $p.Value -PropertyType $p.Type -Force | Out-Null
        } catch {}
    }
}

function Restore-Doh($DohState) {
    foreach ($p in $dohPolicies) {
        $key = $p.Path + '|' + $p.Name
        try {
            $st = $null
            if ($null -ne $DohState) { $st = $DohState.$key }
            if ($null -ne $st) { Set-RegFromState $p.Path $p.Name $st }
            else { Remove-ItemProperty -LiteralPath $p.Path -Name $p.Name -ErrorAction SilentlyContinue }
        } catch {}
    }
}

# Per-adapter DNS, both address families. Windows keeps separate IPv6 DNS servers and
# prefers them, so redirecting only IPv4 would leave lookups going around the filter (or,
# once outbound port 53 is denied to other programs, stall until those servers time out -
# which makes even approved sites fail to load). The static NameServer registry value is
# recorded per family so an adapter that used DHCP-provided DNS goes back to DHCP.
function Get-DnsState {
    @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
        $guid = $_.InterfaceGuid
        $v4 = ''
        $v6 = ''
        try { $v4 = [string](Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"  -Name NameServer -ErrorAction Stop).NameServer } catch { $v4 = '' }
        try { $v6 = [string](Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction Stop).NameServer } catch { $v6 = '' }
        [ordered]@{ InterfaceIndex=$_.ifIndex; InterfaceAlias=$_.Name; StaticNameServer=$v4; StaticNameServerV6=$v6 }
    })
}

function Set-ExamDns {
    param([bool]$RedirectIpv6)
    $changed = 0
    foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '127.0.0.1' -ErrorAction Stop
            $changed++
        } catch {}
        if ($RedirectIpv6) {
            try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '::1' -ErrorAction Stop } catch {}
        }
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    return $changed
}

function Restore-Dns($DnsState) {
    foreach ($e in @($DnsState)) {
        foreach ($family in @('v4','v6')) {
            try {
                $raw = if ($family -eq 'v4') { [string]$e.StaticNameServer } else { [string]$e.StaticNameServerV6 }
                if ($raw -and $raw.Trim() -ne '') {
                    $servers = @($raw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' -and $_ -ne '127.0.0.1' -and $_ -ne '::1' })
                    if ($servers.Count -gt 0) {
                        Set-DnsClientServerAddress -InterfaceIndex $e.InterfaceIndex -ServerAddresses $servers -ErrorAction Stop
                        continue
                    }
                }
                # No static value recorded for this family: put the adapter back on DHCP.
                # Both families must be reset - a v6-only reset would leave the adapter's
                # IPv6 resolver on the dead ::1 exam address, and Windows prefers IPv6
                # resolvers, stalling every lookup even though IPv4 is already correct.
                Set-DnsClientServerAddress -InterfaceIndex $e.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
            } catch {}
        }
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

# Confirms the local Cheat.Guard DNS filter is actually answering before the exam is
# allowed to start. Any reply (including NXDOMAIN) proves it is serving; a timeout means
# resolution would be dead for approved sites too, so lockdown must be rolled back.
function Test-DnsFilter {
    param([string]$Server = '127.0.0.1')
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.UdpClient
        $client.Client.ReceiveTimeout = 4000
        $client.Connect($Server, 53)
        $q = New-Object System.Collections.Generic.List[byte]
        $q.AddRange([byte[]]@(0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00))
        foreach ($label in @('selftest','invalid')) {
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($label)
            $q.Add([byte]$bytes.Length)
            $q.AddRange($bytes)
        }
        $q.Add([byte]0)
        $q.AddRange([byte[]]@(0x00,0x01,0x00,0x01))
        $payload = $q.ToArray()
        [void]$client.Send($payload, $payload.Length)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $reply = $client.Receive([ref]$remote)
        return ($null -ne $reply -and $reply.Length -ge 12)
    } catch {
        return $false
    } finally {
        if ($null -ne $client) { $client.Close() }
    }
}

# Hardens a sealed session log so the desktop account cannot delete or edit it.
# Ownership moves to the Administrators group and inherited rights are dropped, so the
# signed-in user keeps read access but has no delete right and - not being the owner -
# cannot grant itself one. Only grants are used: an explicit deny would also block the
# elevated delete that the admin dashboard performs on purpose.
function Protect-LogFile([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        takeown /F "$Path" /A | Out-Null
        icacls "$Path" /inheritance:r | Out-Null
        icacls "$Path" /grant "*S-1-5-32-544:(F)" | Out-Null   # Administrators: full
        icacls "$Path" /grant "*S-1-5-18:(F)"     | Out-Null   # SYSTEM: full
        icacls "$Path" /grant "*S-1-5-32-545:(R)" | Out-Null   # Users: read only
    } catch {}
}

function Handle-ProtectRequest {
    if ([string]::IsNullOrWhiteSpace($protectRequestFile)) { return }
    if (-not (Test-Path -LiteralPath $protectRequestFile)) { return }
    try {
        # Only paths the exam itself owns may be hardened. The request file is
        # written by the elevated app, but accepting arbitrary paths would turn a
        # bug or a misuse into a tool for ACL-bombing any folder on the machine.
        $networkRoot = Split-Path -Parent $Config
        $vaultDir = ''
        try { $vaultDir = [string]$cfg.vaultDir } catch {}
        $allowedRoots = @($networkRoot)
        if ($vaultDir) { $allowedRoots += $vaultDir }
        $dirs = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
        foreach ($line in Get-Content -LiteralPath $protectRequestFile -ErrorAction SilentlyContinue) {
            $path = $line.Trim()
            if (-not $path) { continue }
            $ok = $false
            try {
                $full = [System.IO.Path]::GetFullPath($path).TrimEnd('\')
                foreach ($root in $allowedRoots) {
                    if ($root -and $full.StartsWith($root.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) { $ok = $true; break }
                }
            } catch { $ok = $false }
            if (-not $ok) { continue }
            Protect-LogFile $path
            $parent = Split-Path -Parent $path
            if ($parent) { [void]$dirs.Add($parent) }
        }
        foreach ($d in $dirs) { Protect-VaultDirectory $d }
    } catch {}
    Remove-Item -LiteralPath $protectRequestFile -Force -ErrorAction SilentlyContinue
    if (-not [string]::IsNullOrWhiteSpace($protectDoneFile)) {
        'PROTECTED' | Set-Content -LiteralPath $protectDoneFile -Encoding ASCII
    }
}

# Removes the account's delete-child right on the vault folder. Without this a sealed
# file could still be deleted despite its own permissions, because delete-child on the
# parent folder is enough to remove a file. New files keep inheriting Modify so the app
# can still write a session log and remove its own plaintext copy when sealing.
function Protect-VaultDirectory([string]$Dir) {
    if ([string]::IsNullOrWhiteSpace($Dir)) { return }
    if (-not (Test-Path -LiteralPath $Dir)) { return }
    try {
        takeown /F "$Dir" /A | Out-Null
        icacls "$Dir" /inheritance:r | Out-Null
        icacls "$Dir" /grant "*S-1-5-32-544:(OI)(CI)(F)" | Out-Null   # Administrators
        icacls "$Dir" /grant "*S-1-5-18:(OI)(CI)(F)"     | Out-Null   # SYSTEM
        icacls "$Dir" /grant "*S-1-5-32-545:(RX,W)"      | Out-Null   # folder: read + create, no delete-child
        icacls "$Dir" /grant "*S-1-5-32-545:(OI)(IO)(M)" | Out-Null   # new files: modify
    } catch {}
}

function Remove-OurRules {
    Get-NetFirewallRule -PolicyStore PersistentStore -Group $groupName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

# VPN concentrators and remote-desktop relays speak on fixed ports that no exam
# traffic uses. Additive Block rules, the same safe pattern as the DoT rules;
# they also cover hand-rolled tunnelling tools the process sweep cannot name.
function Add-TunnelPortBlocks {
    $blocks = @(
        @{ Name = 'block VPN / IPsec / WireGuard ports'; Protocol = 'UDP'; Port = '500,4500,1194,51820' },
        @{ Name = 'block PPTP and outbound RDP';         Protocol = 'TCP'; Port = '1723,3389' },
        @{ Name = 'block VNC ports';                     Protocol = 'TCP'; Port = '5900-5910' },
        @{ Name = 'block QUIC (HTTP/3)';                 Protocol = 'UDP'; Port = '443' }
    )
    foreach ($b in $blocks) {
        New-NetFirewallRule -PolicyStore PersistentStore `
            -DisplayName ('Cheat.Guard - ' + $b.Name) -Group $groupName `
            -Direction Outbound -Protocol $b.Protocol -RemotePort $b.Port `
            -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
}

# The Java filter writes every address an approved domain resolved to into the
# IP file; these are the only destinations the web ports may reach.
function Read-AllowedIps {
    if ([string]::IsNullOrWhiteSpace($allowedIpFile)) { return @() }
    if (-not (Test-Path -LiteralPath $allowedIpFile)) { return @() }
    $ips = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($line in @(Get-Content -LiteralPath $allowedIpFile -ErrorAction SilentlyContinue)) {
            $v = $line.Trim()
            if (-not $v) { continue }
            $ip = $null
            if ([System.Net.IPAddress]::TryParse($v, [ref]$ip)) {
                if (-not $ip.IsIPv6LinkLocal -and -not $ip.Equals([System.Net.IPAddress]::Loopback) -and -not $ip.Equals([System.Net.IPAddress]::IPv6Loopback)) {
                    $ips.Add($v)
                }
            }
            if ($ips.Count -ge 400) { break }
        }
    } catch {}
    return $ips.ToArray()
}

function Set-AllowedDestinationRules([string[]]$Ips) {
    Get-NetFirewallRule -PolicyStore PersistentStore -Group $groupName -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'Cheat.Guard - allowed web destinations*' } |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    if ($Ips.Count -lt 1) { return }
    New-NetFirewallRule -PolicyStore PersistentStore `
        -DisplayName 'Cheat.Guard - allowed web destinations (TCP)' -Group $groupName `
        -Direction Outbound -Protocol TCP -RemotePort 80,443 -RemoteAddress $Ips `
        -Action Allow -Profile Any -ErrorAction Stop | Out-Null
}

# Plain TCP reachability of an approved domain on 443 - proves the allowlist
# actually carries traffic on this network without any HTTP/certificate quirks.
function Test-HttpsReachable([string]$Target) {
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($Target, 443, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(8000)) { return $false }
        $client.EndConnect($async) | Out-Null
        return $client.Connected
    } catch {
        return $false
    } finally {
        try { $client.Close() } catch {}
    }
}

# The full egress lockdown: outbound web traffic is denied by default and only the
# resolved addresses of approved domains (plus the local gateway, so campus
# captive portals and 802.1X page logins keep working) may pass. Verified against
# a real approved site; on a network where that fails, everything is rolled back
# and the session continues in DNS-only mode rather than risking a dead network.
function Apply-EgressLockdown {
    $ips = @(Read-AllowedIps)
    if ($ips.Count -lt 1) { return $false }
    Set-AllowedDestinationRules $ips

    $gateways = @()
    try {
        $gateways = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty NextHop -Unique | Where-Object { $_ -and $_ -ne '0.0.0.0' -and $_ -ne '::' })
    } catch {}
    if ($gateways.Count -ge 1) {
        New-NetFirewallRule -PolicyStore PersistentStore `
            -DisplayName 'Cheat.Guard - local network gateway' -Group $groupName `
            -Direction Outbound -RemoteAddress $gateways `
            -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }

    foreach ($p in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        try { Set-NetFirewallProfile -Profile $p.Name -DefaultOutboundAction Block -ErrorAction Stop } catch {}
    }

    $verified = $false
    try { $verified = Test-HttpsReachable $verifyHost } catch { $verified = $false }
    if (-not $verified) {
        foreach ($p in @($state.Profiles)) {
            try { Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction -ErrorAction Stop } catch {}
        }
        Get-NetFirewallRule -PolicyStore PersistentStore -Group $groupName -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like 'Cheat.Guard - allowed web destinations*' -or $_.DisplayName -like 'Cheat.Guard - local network gateway' } |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
        return $false
    }
    return $true
}

# Hides the "Switch user" entry so a pre-existing second local account cannot be
# used mid-exam. The previous value is snapshotted and Restore-All puts it back.
function Get-FusState {
    try {
        $p = Get-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -ErrorAction Stop
        return @{ Exists = $true; Value = [int]$p.HideFastUserSwitching }
    } catch {
        return @{ Exists = $false; Value = $null }
    }
}

function Set-FusHidden {
    try {
        if (-not (Test-Path -LiteralPath $fusKey)) { New-Item -Path $fusKey -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -PropertyType DWord -Value 1 -Force -ErrorAction Stop | Out-Null
    } catch {}
}

function Restore-Fus($Fus) {
    try {
        if ($Fus.Exists) {
            Set-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -Value ([int]$Fus.Value) -ErrorAction Stop
        } else {
            Remove-ItemProperty -LiteralPath $fusKey -Name 'HideFastUserSwitching' -ErrorAction SilentlyContinue
        }
    } catch {}
}

function Restore-All {
    Remove-OurRules
    if (-not (Test-Path -LiteralPath $stateFile)) { return }
    $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json

    foreach ($p in @($state.Profiles)) {
        try {
            Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled -DefaultOutboundAction $p.DefaultOutboundAction -ErrorAction Stop
        } catch {}
    }

    if (Test-Path -LiteralPath $proxyKey) {
        Set-RegFromState $proxyKey 'ProxyEnable' $state.Proxy.ProxyEnable
        Set-RegFromState $proxyKey 'ProxyServer' $state.Proxy.ProxyServer
        Set-RegFromState $proxyKey 'ProxyOverride' $state.Proxy.ProxyOverride
        Set-RegFromState $proxyKey 'AutoConfigURL' $state.Proxy.AutoConfigURL
        Notify-InternetSettings
    }

    Restore-Dns $state.Dns
    Restore-Doh $state.Doh
    Restore-Fus $state.Fus
    Remove-Item -LiteralPath $egressStatusFile -Force -ErrorAction SilentlyContinue

    Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
}

try {
    Assert-Administrator
    Ensure-FirewallServices

    if ($RecoverOnly) {
        Restore-All
        'RESTORED' | Set-Content -LiteralPath $restoredFile -Encoding ASCII
        exit 0
    }

    Remove-Item -LiteralPath $readyFile,$stopFile,$restoredFile,$errorFile -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $cfg.programPath)) {
        throw "Cheat.Guard executable path was not found: $($cfg.programPath)"
    }

    # Recover a previous interrupted session before taking a fresh snapshot.
    if (Test-Path -LiteralPath $stateFile) { Restore-All }

    $profiles = @(Get-NetFirewallProfile | ForEach-Object {
        [ordered]@{ Name=$_.Name; Enabled=$_.Enabled.ToString(); DefaultOutboundAction=$_.DefaultOutboundAction.ToString() }
    })
    $state = [ordered]@{
        UserSid = $cfg.userSid
        Profiles = $profiles
        Proxy = [ordered]@{
            ProxyEnable = Get-RegState $proxyKey 'ProxyEnable'
            ProxyServer = Get-RegState $proxyKey 'ProxyServer'
            ProxyOverride = Get-RegState $proxyKey 'ProxyOverride'
            AutoConfigURL = Get-RegState $proxyKey 'AutoConfigURL'
        }
        Dns = Get-DnsState
        Doh = Get-DohState
        Fus = Get-FusState
    }
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $stateFile -Encoding UTF8

    Set-FusHidden

    # A user-configured proxy is a complete bypass: the browser hands the request to
    # the proxy, which resolves names and connects on its own, never touching the
    # local DNS filter. The original settings were snapshotted above and Restore-All
    # puts them back, so user proxy and PAC are force-disabled for the exam and all
    # browsing goes direct - where the DNS allowlist applies. (An older build's
    # leftover loopback proxy, which points at a port nothing listens on, is covered
    # by the same disable step.)
    try {
        Set-ItemProperty -LiteralPath $proxyKey -Name 'ProxyEnable' -Value 0 -ErrorAction Stop
        Remove-ItemProperty -LiteralPath $proxyKey -Name 'ProxyServer' -ErrorAction SilentlyContinue
        Remove-ItemProperty -LiteralPath $proxyKey -Name 'AutoConfigURL' -ErrorAction SilentlyContinue
        Notify-InternetSettings
    } catch {}
    $state.Proxy.ProxyEnable = [ordered]@{ Exists=$false; Kind=''; Value=$null }
    $state.Proxy.ProxyServer = [ordered]@{ Exists=$false; Kind=''; Value=$null }
    $state.Proxy.AutoConfigURL = [ordered]@{ Exists=$false; Kind=''; Value=$null }
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $stateFile -Encoding UTF8

    # Strict default-deny is essential: it prevents an unsupported browser, a browser installed
    # in an unusual path, or another application from bypassing the proxy during the exam.
    # The original profile settings were snapshotted above and Restore-All puts them back.
    Remove-OurRules

    # Enforcement is at name resolution, not at the socket layer. An earlier design set
    # every profile's DefaultOutboundAction to Block and allowed browsers to reach only a
    # local proxy port; that blocked unapproved sites but also killed approved ones on any
    # machine where a browser did not honour the injected proxy setting. The firewall is now
    # used only for narrow, additive Block rules that cannot break normal traffic.

    # Close the DNS-over-HTTPS escape at the network layer as well as by policy: deny TCP 443
    # to the well-known public DoH resolvers. Ordinary websites are unaffected, and the
    # Cheat.Guard filter's own upstream lookups use UDP/TCP 53, not 443.
    $dohResolvers = @(
        '1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4','9.9.9.9','149.112.112.112',
        '208.67.222.222','208.67.220.220','94.140.14.14','94.140.15.15','45.90.28.0/24','45.90.30.0/24'
    )
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block DoH resolvers' -Group $groupName -Direction Outbound -Protocol TCP -RemoteAddress $dohResolvers -RemotePort 443 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # Deny DNS-over-TLS entirely (TCP and UDP 853): a custom resolver or a Windows 11
    # DoT setting would otherwise tunnel around the local filter the same way DoH would.
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block DoT TCP' -Group $groupName -Direction Outbound -Protocol TCP -RemotePort 853 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block DoT UDP' -Group $groupName -Direction Outbound -Protocol UDP -RemotePort 853 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # A custom tool could bypass the local filter by querying a well-known public
    # resolver directly (nslookup facebook.com 8.8.8.8). Block port 53 to those
    # resolvers. The filter's own upstreams never use this list: the Java side drops
    # captured system resolvers that appear here and falls back to Quad9 unfiltered
    # endpoints instead, so its own path stays open.
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block public resolver 53 TCP' -Group $groupName -Direction Outbound -Protocol TCP -RemoteAddress $dohResolvers -RemotePort 53 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - block public resolver 53 UDP' -Group $groupName -Direction Outbound -Protocol UDP -RemoteAddress $dohResolvers -RemotePort 53 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # Keep the Cheat.Guard process explicitly permitted outbound so its upstream DNS keeps
    # working even on a machine whose profiles already default to Block.
    New-NetFirewallRule -PolicyStore PersistentStore -DisplayName 'Cheat.Guard - filter host outbound' -Group $groupName -Direction Outbound -Program $cfg.programPath -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

    # ---- tunnel/remote-access hardening, then the egress web lockdown ----
    Add-TunnelPortBlocks
    $script:lastIps = ''
    $script:egressActive = $false
    if ((-not [string]::IsNullOrWhiteSpace($allowedIpFile)) -and (-not [string]::IsNullOrWhiteSpace($verifyHost))) {
        try {
            $script:egressActive = Apply-EgressLockdown
            $script:lastIps = (@(Read-AllowedIps) -join ',')
        } catch {
            $script:egressActive = $false
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($egressStatusFile)) {
        if ($script:egressActive) { 'ACTIVE' | Set-Content -LiteralPath $egressStatusFile -Encoding ASCII }
        else { 'FALLBACK' | Set-Content -LiteralPath $egressStatusFile -Encoding ASCII }
    }

    # Force browsers onto the system resolver, then point the system resolver at the
    # Cheat.Guard DNS filter. Unapproved domains then fail to resolve for every program,
    # while approved domains resolve normally and connect over their usual direct path.
    Disable-BrowserDoh
    $redirectIpv6 = [bool]$cfg.dnsIpv6
    $dnsChanged = Set-ExamDns -RedirectIpv6 $redirectIpv6
    if ($dnsChanged -lt 1) {
        throw 'Could not redirect any network adapter to the Cheat.Guard DNS filter (127.0.0.1). Check that a network adapter is connected.'
    }
    if (-not (Test-DnsFilter '127.0.0.1')) {
        throw 'The Cheat.Guard DNS filter on 127.0.0.1:53 did not answer a test lookup. Lockdown has been rolled back so the computer keeps working; start the exam again.'
    }

    # Chromium/Firefox cache DoH and resolver state, so restart them once when exam mode
    # begins to make sure the policy and the redirected DNS are picked up.
    foreach ($name in @('chrome','msedge','firefox','brave','opera','opera_gx','vivaldi','iexplore')) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 700

    # Verify DNS redirection before telling the Java app that lockdown is ready.
    $dnsOk = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses -contains '127.0.0.1' }).Count
    if ($dnsOk -lt 1) { throw 'DNS redirection verification failed: no adapter is using the Cheat.Guard DNS filter.' }
    if (-not (Test-DnsFilter '127.0.0.1')) { throw 'The Cheat.Guard DNS filter stopped answering during verification.' }

    # Keep new or re-connected adapters on the filter for the whole session. A USB
    # Wi-Fi dongle or a re-connected Ethernet adapter comes up with DHCP DNS and
    # would resolve straight through the real resolvers, bypassing the exam allowlist.
    $redirectedIfIndex = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($e in @($state.Dns)) { if ($e.InterfaceIndex) { [void]$redirectedIfIndex.Add([string]$e.InterfaceIndex) } }
    foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
        [void]$redirectedIfIndex.Add([string]$a.ifIndex)
    }

    # This directory holds the session's control markers (stop, protect-request) and
    # the helper configuration. Restrict it to Administrators now that the app itself
    # runs elevated: the signed-in account keeps read access but can no longer forge
    # a stop marker to silently end the lockdown, rewrite the helper configuration,
    # or swap this script while the UAC prompt is on screen.
    try {
        $networkRoot = Split-Path -Parent $Config
        takeown /F "$networkRoot" /A | Out-Null
        icacls "$networkRoot" /inheritance:r | Out-Null
        icacls "$networkRoot" /grant "*S-1-5-32-544:(OI)(CI)(F)" | Out-Null   # Administrators: full
        icacls "$networkRoot" /grant "*S-1-5-18:(OI)(CI)(F)"     | Out-Null   # SYSTEM: full
        icacls "$networkRoot" /grant "*S-1-5-32-545:(OI)(CI)(RX)" | Out-Null  # Users: read+execute only
    } catch {}

    'READY' | Set-Content -LiteralPath $readyFile -Encoding ASCII

    $loopCount = 0
    while ($true) {
        if (Test-Path -LiteralPath $stopFile) { break }
        if (-not (Get-Process -Id ([int]$cfg.parentPid) -ErrorAction SilentlyContinue)) { break }
        Handle-ProtectRequest
        $loopCount++
        if ($script:egressActive -and ($loopCount % 10) -eq 0) {
            # Approved pages resolve new CDN addresses mid-exam; the allow rule follows.
            $ips = @(Read-AllowedIps)
            if ($ips.Count -ge 1) {
                $blob = $ips -join ','
                if ($blob -ne $script:lastIps) {
                    try {
                        Set-AllowedDestinationRules $ips
                        $script:lastIps = $blob
                    } catch {}
                }
            }
        }
        foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
            $key = [string]$a.ifIndex
            if (-not $redirectedIfIndex.Contains($key)) {
                try {
                    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '127.0.0.1' -ErrorAction Stop
                    if ($redirectIpv6) {
                        try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '::1' -ErrorAction Stop } catch {}
                    }
                    [void]$redirectedIfIndex.Add($key)
                } catch {}
            }
        }
        Start-Sleep -Milliseconds 500
    }

    # The app seals the log just before asking for shutdown, so serve one last request.
    Handle-ProtectRequest

    Restore-All
    'RESTORED' | Set-Content -LiteralPath $restoredFile -Encoding ASCII
    exit 0
} catch {
    $msg = @(
        'Cheat.Guard strict-network helper failed.',
        ('Message: ' + $_.Exception.Message),
        ('Type: ' + $_.Exception.GetType().FullName),
        ('PowerShell: ' + $PSVersionTable.PSVersion.ToString()),
        ('Windows user: ' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
    ) -join [Environment]::NewLine
    try { $msg | Set-Content -LiteralPath $errorFile -Encoding UTF8 } catch {}
    try { Restore-All } catch {}
    exit 1
}
