@echo off
setlocal
cd /d "%~dp0"

echo HomeGuard - GUI Launcher
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
python -m pip install -e ".[tray]"
if errorlevel 1 (
    echo Failed to install HomeGuard.
    pause
    exit /b 1
)

echo Launching HomeGuard GUI...
python -m greynoc_homeguard gui
if errorlevel 1 (
    echo HomeGuard exited with an error.
    pause
    exit /b 1
)
