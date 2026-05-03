@echo off
setlocal
cd /d "%~dp0"

echo HomeGuard - Security Definition Updater
echo Updates CISA KEV and recent NVD CVE definitions used by HomeGuard.
echo.

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set "PY=py -3"
) else (
    set "PY=python"
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating local Python virtual environment...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo Failed to create the virtual environment. Install Python 3.10+ and try again.
        pause
        exit /b 1
    )
)

call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip
python -m pip install -e .
if errorlevel 1 (
    echo Failed to install HomeGuard.
    pause
    exit /b 1
)

python -m greynoc_homeguard update-definitions --nvd-days 30
if errorlevel 1 (
    echo Definition update failed.
    pause
    exit /b 1
)

echo.
echo Definition update complete.
pause
