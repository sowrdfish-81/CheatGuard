# RED-TEAM: try to break the fail-safe. Three attacks, all WITHOUT touching DNS:
#   A1: corrupt firewall_state.json (invalid JSON) + deny ACE + leftover rule
#   A2: DELETE firewall_state.json, keep deny ACE + leftover rule + lock-paths.txt
#   A3: deny ACE with NO evidence (no state, no rules, no lock list) -> must be ignored
$ErrorActionPreference = 'Continue'
Start-Transcript -Path 'C:\Users\mdroh\.zcode\workspace\default\CheatGuard_repo\test\attack-output.txt' -Force | Out-Null
$netDir = 'C:\ProgramData\CheatGuard\network'
$script = Join-Path $netDir 'network-lockdown.ps1'
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# deploy the latest helper first
Copy-Item 'C:\Users\mdroh\.zcode\workspace\default\CheatGuard_repo\resources\network-lockdown.ps1' $script -Force

$testDir = 'C:\Users\mdroh\Documents\STRESSTEST'
function Reset-TestState {
    Remove-Item -LiteralPath $testDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $testDir 'work.txt') -Value 'exam work' -Encoding ASCII
    icacls "$testDir" /deny "*${sid}:(OI)(CI)(RX,D)" | Out-Null
}
function Broken {
    return ('deny=' + @(icacls "$testDir" 2>$null | Where-Object { $_ -match '\(DENY\)' }).Count +
            ' rules=' + @(Get-NetFirewallRule -Group 'Cheat.Guard Strict Exam' -ErrorAction SilentlyContinue).Count +
            ' readable=' + $(try { Get-Content (Join-Path $testDir 'work.txt') -ErrorAction Stop; 'YES' } catch { 'NO(access-denied)' }))
}

Write-Output '=== ATTACK 1: corrupt state file ==='
Reset-TestState
New-NetFirewallRule -DisplayName 'Cheat.Guard - ATK leftover' -Group 'Cheat.Guard Strict Exam' -Direction Outbound -Protocol TCP -RemotePort 9998 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
'{{{ this is not json !!!' | Set-Content -LiteralPath (Join-Path $netDir 'firewall_state.json') -Encoding UTF8
Write-Output ('broken: ' + (Broken))
& $ps -NoProfile -ExecutionPolicy Bypass -File $script -FailSafeCheck
Write-Output ('after : ' + (Broken))

Write-Output '=== ATTACK 2: state file DELETED, evidence left ==='
Reset-TestState
New-NetFirewallRule -DisplayName 'Cheat.Guard - ATK leftover' -Group 'Cheat.Guard Strict Exam' -Direction Outbound -Protocol TCP -RemotePort 9998 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
Set-Content -LiteralPath (Join-Path $netDir 'lock-paths.txt') -Value "$testDir" -Encoding ASCII
Remove-Item -LiteralPath (Join-Path $netDir 'firewall_state.json') -Force -ErrorAction SilentlyContinue
Write-Output ('broken: ' + (Broken))
& $ps -NoProfile -ExecutionPolicy Bypass -File $script -FailSafeCheck
Write-Output ('after : ' + (Broken))

Write-Output '=== ATTACK 3: deny with NO evidence (must stay untouched) ==='
Reset-TestState
Remove-Item -LiteralPath (Join-Path $netDir 'lock-paths.txt') -Force -ErrorAction SilentlyContinue
Write-Output ('before: ' + (Broken))
& $ps -NoProfile -ExecutionPolicy Bypass -File $script -FailSafeCheck
Write-Output ('after : ' + (Broken) + '  (deny expected to REMAIN: no evidence = not ours)')

Write-Output '=== cleanup test folder ==='
icacls "$testDir" /remove:d "*$sid" | Out-Null
Remove-Item -LiteralPath $testDir -Recurse -Force -ErrorAction SilentlyContinue
Get-Content (Join-Path $netDir 'failsafe-log.txt') -Tail 5 -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ('LOG: ' + $_) }
Write-Output 'ATTACKS_DONE'
Stop-Transcript | Out-Null
