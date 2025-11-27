@echo off
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File ".\Analyze-ApacheLog.ps1"
pause
