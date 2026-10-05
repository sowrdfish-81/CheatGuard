$ErrorActionPreference = 'Stop'
$file = Join-Path $PSScriptRoot '..\resources\network-lockdown.ps1'
$errors = $null
$tokens = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$errors)
if ($errors -and $errors.Count -gt 0) {
    Write-Output ("PS1 SYNTAX ERRORS: " + $errors.Count)
    foreach ($e in $errors) { Write-Output ("  line " + $e.Extent.StartLineNumber + ": " + $e.Message) }
    exit 1
}
Write-Output "PS1 SYNTAX OK"
