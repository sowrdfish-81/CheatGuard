# Cheat.Guard emergency network restore.
#
# Repairs the machine's DNS and firewall after a Cheat.Guard session ended
# abnormally (power loss, forced reboot, crash). It deliberately REFUSES to run
# while Cheat.Guard itself is running: an active lockdown must be ended through
# the app's own password-gated controls, or this one-click tool would be the
# easiest bypass on the machine.

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
Write-Host '  Restoring network settings (administrator approval required)...'
Write-Host ''

$inner =
    'Get-NetAdapter | ForEach-Object { try { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction Stop } catch {} }; ' +
    'Get-NetFirewallRule -Group ''Cheat.Guard Strict Exam'' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; ' +
    '$d = Join-Path $env:ProgramData ''CheatGuard\network''; ' +
    '$s = Join-Path $d ''firewall_state.json''; ' +
    'if (Test-Path $s) { Remove-Item $s -Force -ErrorAction SilentlyContinue }; ' +
    'Clear-DnsClientCache -ErrorAction SilentlyContinue; ipconfig /flushdns | Out-Null'

try {
    Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -Wait -WindowStyle Hidden `
        -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command',$inner
    Write-Host '  Network settings restored.' -ForegroundColor Green
    Write-Host '  If a site still will not open, reconnect Wi-Fi/Ethernet once.'
} catch {
    Write-Host '  Administrator approval was declined; nothing was changed.' -ForegroundColor Red
}
