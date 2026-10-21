@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Live.ps1" -SendEmail
if errorlevel 1 pause
