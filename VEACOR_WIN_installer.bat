@echo off
cd /d %~dp0
echo [+] Launching installer...
py -3 VEACOR_installer.py
if errorlevel 1 (
  echo.
  echo [!] Installer failed.
  pause
  exit /b 1
)
pause
