@echo off
setlocal
cd /d "%~dp0"

echo HomeGuard - Chat UI Launcher
echo.

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set "PY=py -3"
) else (
    set "PY=python"
)

where npm >nul 2>nul
if errorlevel 1 (
    echo Node.js and npm are required to run the HomeGuard chat UI.
    echo Install Node.js, then run this file again.
    pause
    exit /b 1
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
if errorlevel 1 (
    echo Failed to activate the virtual environment.
    pause
    exit /b 1
)

echo Installing HomeGuard Python backend...
python -m pip install --upgrade pip
python -m pip install -e .
if errorlevel 1 (
    echo Failed to install the HomeGuard Python backend.
    pause
    exit /b 1
)

if not exist "node_modules\electron" (
    echo Installing Electron dependencies...
    npm install
    if errorlevel 1 (
        echo Failed to install Electron dependencies.
        pause
        exit /b 1
    )
)

echo Launching HomeGuard chat UI...
npm run electron
if errorlevel 1 (
    echo HomeGuard chat UI exited with an error.
    pause
    exit /b 1
)
