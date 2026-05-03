@echo off
setlocal
cd /d "%~dp0"

echo HomeGuard - Windows EXE Compiler
echo This bumps the patch version, builds the Electron desktop app at dist\electron\win-unpacked\HomeGuard.exe, and signs it when a GreyNOC code-signing certificate is configured.
echo.
echo Signing environment:
echo   HOMEGUARD_SIGN_CERT_PATH       path to GreyNOC .pfx/.p12 certificate
echo   HOMEGUARD_SIGN_CERT_PASSWORD   certificate password
echo   HOMEGUARD_SIGN_CERT_SHA1       optional Windows cert-store thumbprint
echo   HOMEGUARD_REQUIRE_SIGNING=1    fail the build if signing cannot complete
echo.

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set "PY=py -3"
) else (
    set "PY=python"
)

if not exist ".venv-build\Scripts\python.exe" (
    echo Creating build virtual environment...
    %PY% -m venv .venv-build
    if errorlevel 1 (
        echo Failed to create the build environment. Install Python 3.10+ and try again.
        pause
        exit /b 1
    )
)

call ".venv-build\Scripts\activate.bat"
python -m pip install --upgrade pip
python -m pip install -e ".[tray]" pyinstaller
if errorlevel 1 (
    echo Failed to install build dependencies.
    pause
    exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
    echo Node.js and npm are required to compile the Electron app.
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

if not exist "node_modules\electron-builder" (
    echo Installing Electron Builder dependencies...
    npm install
    if errorlevel 1 (
        echo Failed to install Electron Builder dependencies.
        pause
        exit /b 1
    )
)

npm run smoke
if errorlevel 1 (
    echo Electron smoke check failed.
    pause
    exit /b 1
)

python scripts\build_electron.py
if errorlevel 1 (
    echo Electron EXE build failed.
    pause
    exit /b 1
)

echo.
echo Build complete: dist\electron\win-unpacked\HomeGuard.exe
pause
