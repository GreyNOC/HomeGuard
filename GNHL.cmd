@echo off
setlocal
set "GNHL_LAUNCHER=repo"
node "%~dp0scripts\cli.js" %*
exit /b %ERRORLEVEL%
