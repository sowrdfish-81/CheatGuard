# Cheat.Guard diagnostics collector (read-only).
# Gathers adapter/DNS state, app data listing and the recent app log into a single
# text file on the Desktop, ready to send to the development team.

$out = Join-Path ([Environment]::GetFolderPath('Desktop')) 'CheatGuard-Diagnostics.txt'
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('Cheat.Guard diagnostics  -  ' + (Get-Date))
$lines.Add('')

$lines.Add('-- network adapters --')
try { $lines.Add((Get-NetAdapter | Format-Table Name,Status,ifIndex -AutoSize | Out-String)) } catch { $lines.Add('unavailable') }
$lines.Add('-- DNS servers per adapter --')
try { $lines.Add((Get-DnsClientServerAddress | Format-Table InterfaceAlias,AddressFamily,ServerAddresses -AutoSize | Out-String)) } catch { $lines.Add('unavailable') }

$data = Join-Path $env:ProgramData 'CheatGuard'
$lines.Add('-- app data files (' + $data + ') --')
if (Test-Path $data) {
    try { $lines.Add((Get-ChildItem $data -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | Format-Table -AutoSize | Out-String)) } catch {}
} else {
    $lines.Add('No app data directory exists yet.')
}

$logs = Join-Path $data 'logs'
if (Test-Path $logs) {
    $lines.Add('-- recent app log (last 100 lines of the 2 newest files) --')
    try {
        Get-ChildItem $logs -Filter '*.log' | Sort-Object LastWriteTime -Descending |
            Select-Object -First 2 | ForEach-Object {
                $lines.Add('[' + $_.Name + ']')
                $lines.Add((Get-Content $_.FullName -Tail 100 | Out-String))
            }
    } catch {}
}

$lines | Set-Content -LiteralPath $out -Encoding UTF8
Write-Host ''
Write-Host ('  Diagnostics saved to: ' + $out) -ForegroundColor Green
