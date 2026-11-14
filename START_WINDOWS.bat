@echo off
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel% equ 0 (
  py -3 server.py
) else (
  python server.py
)
if errorlevel 1 (
 echo.
 echo Python 3.10+ is required. Install Python from python.org and try again.
 pause
)
