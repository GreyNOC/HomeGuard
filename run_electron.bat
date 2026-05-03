@echo off
setlocal
cd /d "%~dp0"

echo HomeGuard - Electron Launcher
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
python -m pip install -e .
if errorlevel 1 (
    echo Failed to install HomeGuard.
    pause
    exit /b 1
)

if not exist "node_modules\electron" (
    echo Installing Electron dependencies...
    npm install
    if errorlevel 1 (
        echo Failed to install Electron dependencies. Install Node.js and try again.
        pause
        exit /b 1
    )
)

echo Launching HomeGuard Electron frontend...
npm run electron
if errorlevel 1 (
    echo HomeGuard Electron frontend exited with an error.
    pause
    exit /b 1
)
