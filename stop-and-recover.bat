@echo off
setlocal enabledelayedexpansion

:: Change to script directory
cd /d "%~dp0"

:: Check for administrative rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Administrative privileges required. Elevating...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
    exit /b
)

:: Elevated execution continues here
title dpibypass - Stop and Recover
echo =======================================================
echo   dpibypass - Recovery and Driver Cleanup
echo =======================================================
echo.

if not exist "dpibypass.exe" (
    echo [ERROR] dpibypass.exe not found in "%~dp0".
    pause
    exit /b 1
)

echo Stopping any running dpibypass processes...
taskkill /F /IM dpibypass.exe >nul 2>&1
timeout /t 1 /nobreak >nul

echo Running recover...
dpibypass.exe recover

echo.
echo Recovery operation complete.
echo.
pause
