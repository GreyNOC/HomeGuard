@echo off
setlocal

REM HomeGuard - Android build wrapper for Windows.
REM Buildozer does not run natively on Windows, so this launches the
REM repo's Linux/macOS build script inside WSL.

set "MODE=%~1"
if "%MODE%"=="" set "MODE=debug"

if /I "%MODE%"=="help" goto :usage
if /I "%MODE%"=="--help" goto :usage
if /I "%MODE%"=="-h" goto :usage

if /I "%MODE%"=="debug" goto :check_wsl
if /I "%MODE%"=="release" goto :check_wsl
if /I "%MODE%"=="aab" goto :check_wsl
if /I "%MODE%"=="clean" goto :check_wsl

echo ERROR: Unknown Android build mode: %MODE%
echo.
goto :usage

:check_wsl

where wsl.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: WSL is required to build the Android app from Windows.
    echo Install Ubuntu with: wsl --install -d Ubuntu
    echo Then run this script again from the repo root.
    exit /b 1
)

wsl -e sh -lc "printf ok" >nul 2>nul
if errorlevel 1 (
    echo ERROR: WSL is present but no Linux distro is ready.
    echo Install Ubuntu with: wsl --install -d Ubuntu
    echo Then open Ubuntu once, finish setup, and run this script again.
    exit /b 1
)

echo Building HomeGuard Android app via WSL mode: %MODE%
wsl bash -lc "cd \"$(wslpath '%CD%')\" && chmod +x ./scripts/compile_android.sh && ./scripts/compile_android.sh %MODE%"
if errorlevel 1 (
    echo Android build failed.
    exit /b 1
)

echo Android build finished. Check dist\android.
exit /b 0

:usage
echo Usage: compile_android.bat [debug^|release^|aab^|clean]
echo.
echo Build outputs are copied to dist\android.
echo.
echo   debug    Build a debug APK. This is the default.
echo   release  Build a release APK. Requires signing configuration for real use.
echo   aab      Build a Play Store-style Android App Bundle when configured.
echo   clean    Remove Buildozer build artifacts.
exit /b 0
