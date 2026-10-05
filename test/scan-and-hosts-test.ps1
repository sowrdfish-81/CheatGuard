# 1) Rebuild state.FileLocks by scanning for folders the student SID cannot read
#    (the file wall denies (RX,D) - unreadable = locked by the wall).
# 2) Red-team BUG-3: prove the v1.3 helper does NOT deny writes to the hosts file.
$ErrorActionPreference = 'Continue'
Start-Transcript -Path 'C:\Users\mdroh\.zcode\workspace\default\CheatGuard_repo\test\scan-output.txt' -Force | Out-Null
$netDir = 'C:\ProgramData\CheatGuard\network'
$sid = 'S-1-5-21-3386253252-3976114247-2349148618-1001'

$roots = @('C:\Users\mdroh\Documents','C:\Users\mdroh\Downloads','C:\Users\mdroh\OneDrive\Desktop',
           'C:\Users\mdroh\OneDrive\Documents','C:\Users\mdroh\OneDrive\Pictures',
           'C:\Users\mdroh\Music','C:\Users\mdroh\Videos','C:\Users\mdroh\Pictures')
$locked = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
foreach ($r in $roots) {
    if (-not (Test-Path -LiteralPath $r)) { continue }
    try { Get-Acl -LiteralPath $r -ErrorAction Stop | Out-Null } catch { [void]$locked.Add($r); continue }
    foreach ($kid in @(Get-ChildItem -LiteralPath $r -Force -ErrorAction SilentlyContinue)) {
        try { Get-Acl -LiteralPath $kid.FullName -ErrorAction Stop | Out-Null } catch { [void]$locked.Add($kid.FullName) }
    }
}
foreach ($d in @([System.IO.DriveInfo]::GetDrives())) {
    try { if ($d.IsReady -and $d.Name -ne 'C:\') { [void]$locked.Add($d.RootDirectory.FullName) } } catch {}
}
Write-Output ('locked-by-scan: ' + $locked.Count)
$locked | ForEach-Object { Write-Output ('  ' + $_) }

$statePath = Join-Path $netDir 'firewall_state.json'
try {
    $state = Get-Content $statePath -Raw | ConvertFrom-Json
    $state.FileLocks = @($locked)
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8
    Write-Output ('state updated, FileLocks=' + @($state.FileLocks).Count)
} catch { Write-Output ('state update FAILED: ' + $_.Exception.Message) }

Write-Output '--- BUG-3 hosts write test (expect SUCCESS on v1.3 = bug confirmed) ---'
$hosts = 'C:\Windows\System32\drivers\etc\hosts'
Copy-Item $hosts "$env:TEMP\hosts.bak" -Force
try {
    Add-Content -LiteralPath $hosts -Value "127.0.0.1 stress-test.invalid" -ErrorAction Stop
    Write-Output 'HOSTS WRITE SUCCEEDED -> BUG-3 CONFIRMED (v1.3 does not protect hosts)'
    Select-String -LiteralPath $hosts -Pattern 'stress-test.invalid' | ForEach-Object { Write-Output ('  line present: ' + $_.Line) }
    # restore the original hosts content
    Copy-Item "$env:TEMP\hosts.bak" $hosts -Force
    Write-Output ('hosts restored clean: ' + (-not (Select-String -LiteralPath $hosts -Pattern 'stress-test.invalid' -Quiet)))
} catch {
    Write-Output ('HOSTS WRITE DENIED: ' + $_.Exception.Message)
}
Write-Output 'SCAN_AND_HOSTS_DONE'
Stop-Transcript | Out-Null
