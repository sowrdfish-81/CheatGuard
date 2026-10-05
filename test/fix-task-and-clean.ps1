$ErrorActionPreference = 'Continue'
Start-Transcript -Path 'C:\Users\mdroh\.zcode\workspace\default\CheatGuard_repo\test\fixtask-output.txt' -Force | Out-Null
$netDir = 'C:\ProgramData\CheatGuard\network'
$script = Join-Path $netDir 'network-lockdown.ps1'
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

Write-Output '[1] re-register fail-safe task with classic schtasks.exe'
$tr = '"' + $ps + '" -NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -FailSafeCheck'
schtasks /Create /F /TN "CheatGuard SessionFailSafe" /SC MINUTE /MO 10 /RU SYSTEM /RL HIGHEST /TR "$tr" 2>&1 | Out-String | Write-Output
schtasks /Query /TN "CheatGuard SessionFailSafe" 2>&1 | Out-String | Write-Output

Write-Output '[2] manual -FailSafeCheck to clean the current simulated leftovers'
& $ps -NoProfile -ExecutionPolicy Bypass -File $script -FailSafeCheck
Write-Output ('    exit=' + $LASTEXITCODE)

Write-Output '[3] verify'
Write-Output ('  rules (expect 0): ' + @(Get-NetFirewallRule -Group 'Cheat.Guard Strict Exam' -ErrorAction SilentlyContinue).Count)
Write-Output ('  state file (expect False): ' + (Test-Path (Join-Path $netDir 'firewall_state.json')))
$a = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
Write-Output ('  dns untouched [' + ((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses -join ',') + ']')
Write-Output ('  STRESSTEST readable (expect ACL lines, no DENY):')
icacls 'C:\Users\mdroh\Documents\STRESSTEST' 2>&1 | Select-Object -First 4 | ForEach-Object { Write-Output ('    ' + $_) }
Write-Output ('  failsafe log: ' + $(if (Test-Path (Join-Path $netDir 'failsafe-log.txt')) { (Get-Content (Join-Path $netDir 'failsafe-log.txt') -Tail 1) } else { 'no log (state was already gone or check skipped)' }))

Write-Output '[4] force-run the task once to prove the task path works'
schtasks /Run /TN "CheatGuard SessionFailSafe" 2>&1 | Out-String | Write-Output
Start-Sleep -Seconds 5
schtasks /Query /TN "CheatGuard SessionFailSafe" /V /FO LIST 2>&1 | Select-String 'Last Run Time|Last Result|Status' | Out-String | Write-Output

Write-Output '[5] task still present after run?'
schtasks /Query /TN "CheatGuard SessionFailSafe" 2>&1 | Out-String | Write-Output
Remove-Item -LiteralPath 'C:\Users\mdroh\Documents\STRESSTEST' -Recurse -Force -ErrorAction SilentlyContinue
Write-Output 'DONE'
Stop-Transcript | Out-Null
