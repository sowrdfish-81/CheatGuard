# Cheat.Guard emergency restore.
#
# Repairs the machine after a Cheat.Guard session ended abnormally (power loss,
# forced reboot, crash): DNS back to automatic, firewall rules and the outbound
# default removed, browser DoH policies lifted, and every "Access is denied" file
# wall the session placed on the student's account is taken back off. It
# deliberately REFUSES to run while Cheat.Guard itself is running: an active
# lockdown must be ended through the app's own password-gated controls, or this
# one-click tool would be the easiest bypass on the machine.

$app = Get-Process -Name 'CheatGuard' -ErrorAction SilentlyContinue
if ($app) {
    Write-Host ''
    Write-Host '  Cheat.Guard is currently RUNNING.' -ForegroundColor Yellow
    Write-Host '  An exam session may be active.'
    Write-Host '  End the session from the app ("End session and seal log").'
    Write-Host '  This tool only repairs leftovers from an INTERRUPTED session.'
    Write-Host ''
    exit 1
}

Write-Host ''
Write-Host '  Restoring network and file access (administrator approval required)...'
Write-Host ''

# Runs elevated. The student's SID comes from the saved state when possible,
# otherwise from the signed-in console user - the elevated account itself may be
# a different administrator, and the deny ACEs are on the STUDENT's account.
$inner =
    '$sid = ""; ' +
    '$statePath = Join-Path $env:ProgramData ''CheatGuard\network\firewall_state.json''; ' +
    'if (Test-Path $statePath) { try { $sid = [string](Get-Content $statePath -Raw | ConvertFrom-Json).UserSid } catch {} }; ' +
    'if (-not $sid) { try { $u = (Get-CimInstance Win32_ComputerSystem).UserName; if ($u) { $sid = (New-Object Security.Principal.NTAccount($u)).Translate([Security.Principal.SecurityIdentifier]).Value } } catch {} }; ' +
    'Get-NetAdapter | ForEach-Object { try { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction Stop } catch {} }; ' +
    'Get-NetFirewallRule -Group ''Cheat.Guard Strict Exam'' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; ' +
    'Get-NetFirewallProfile | ForEach-Object { try { Set-NetFirewallProfile -Name $_.Name -DefaultOutboundAction Allow -ErrorAction SilentlyContinue } catch {} }; ' +
    'try { Remove-ItemProperty -Path ''HKLM:\SOFTWARE\Policies\Google\Chrome'' -Name DnsOverHttpsMode -ErrorAction SilentlyContinue } catch {}; ' +
    'try { Remove-ItemProperty -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Edge'' -Name DnsOverHttpsMode -ErrorAction SilentlyContinue } catch {}; ' +
    'try { Remove-ItemProperty -Path ''HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'' -Name Enabled -ErrorAction SilentlyContinue } catch {}; ' +
    '$roots = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase); ' +
    '[System.IO.DriveInfo]::GetDrives() | ForEach-Object { try { if ($_.IsReady) { [void]$roots.Add($_.RootDirectory.FullName) } } catch {} }; ' +
    'foreach ($n in @(''Documents'',''Downloads'',''Music'',''Pictures'',''Videos'',''Saved Games'',''Contacts'',''Links'',''OneDrive'',''3D Objects'',''Searches'',''Desktop'')) { ' +
    '$p = Join-Path $env:USERPROFILE $n; if (Test-Path -LiteralPath $p) { [void]$roots.Add($p); ' +
    'Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue | ForEach-Object { [void]$roots.Add($_.FullName) } } }; ' +
    'foreach ($s in @($sid, [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) { ' +
    'if (-not $s) { continue }; ' +
    'foreach ($r in $roots) { try { icacls "$r" /remove:d "*$s" | Out-Null } catch {} } }; ' +
    'if (Test-Path $statePath) { Remove-Item $statePath -Force -ErrorAction SilentlyContinue }; ' +
    'Clear-DnsClientCache -ErrorAction SilentlyContinue; ipconfig /flushdns | Out-Null'

try {
    Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -Wait -WindowStyle Hidden `
        -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command',$inner
    Write-Host '  Network settings and file access restored.' -ForegroundColor Green
    Write-Host '  If a site still will not open, reconnect Wi-Fi/Ethernet once.'
} catch {
    Write-Host '  Administrator approval was declined; nothing was changed.' -ForegroundColor Red
}
