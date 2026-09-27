@echo off
title Beam - LAN File Transfer
cd /d "%~dp0"

rem Find a real Python 3.8+ (the Microsoft Store "python" stub doesn't count).
set "PY="
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>nul && set "PY=python"
if not defined PY py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>nul && set "PY=py -3"
if not defined PY goto nopython

if not exist "%~dp0lan_file_transfer.py" (
  echo.
  echo   lan_file_transfer.py is missing. Keep this .bat file in the same folder as it.
  echo.
  pause
  exit /b 1
)

%PY% "%~dp0lan_file_transfer.py"
if errorlevel 1 pause
exit /b

:nopython
echo.
echo   Python 3.8 or newer isn't installed (or wasn't added to PATH).
echo   1. Download it from https://www.python.org/downloads/
echo   2. Run the installer and TICK "Add python.exe to PATH" on the first screen.
echo   3. Double-click this file again.
echo.
pause
exit /b 1
