@echo off
cd /d "%~dp0"
py -3 -m pip install "cryptography>=42,<48"
if errorlevel 1 python -m pip install "cryptography>=42,<48"
echo.
echo Installation attempted. If there were errors above, install Python 3.10+ and try again.
pause
