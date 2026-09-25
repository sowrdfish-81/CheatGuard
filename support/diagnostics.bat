@echo off
title Cheat.Guard - Diagnostics
echo ============================================================
echo  Cheat.Guard - Collect Diagnostics
echo ============================================================
echo.
echo  Collects network/DNS state and recent app logs into one
echo  text file on the Desktop. Read-only; changes nothing.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0support\diagnostics.ps1"
echo.
pause
