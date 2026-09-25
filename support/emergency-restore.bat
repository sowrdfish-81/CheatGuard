@echo off
title Cheat.Guard - Emergency Network Restore
echo ============================================================
echo  Cheat.Guard - Emergency Network Restore
echo ============================================================
echo.
echo  Use this ONLY if a Cheat.Guard session ended abnormally
echo  (power loss, forced reboot, crash) and the Internet stayed
echo  blocked. If Cheat.Guard is running right now, end the
echo  session from the app instead.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0support\emergency-restore.ps1"
echo.
pause
