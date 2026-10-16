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
title dpibypass - Wire Engine and WebUI
echo =======================================================
echo   dpibypass - Packet Wire Engine with WebUI
echo =======================================================
echo.
echo Configuration : config.json
echo WebUI Address : http://127.0.0.1:8787
echo.
echo Starting engine... Press Ctrl+C in this window to stop.
echo.

if not exist "dpibypass.exe" (
    echo [ERROR] dpibypass.exe not found in "%~dp0".
    echo Please run build.ps1 first to compile the binary.
    echo.
    pause
    exit /b 1
)

echo Stopping any lingering dpibypass instances and resetting driver...
taskkill /F /IM dpibypass.exe >nul 2>&1
timeout /t 1 /nobreak >nul
dpibypass.exe recover >nul 2>&1

echo Flushing Windows DNS cache...
ipconfig /flushdns >nul 2>&1

echo Cleaning up any stuck Discord or updater processes...
taskkill /F /IM Discord.exe >nul 2>&1
taskkill /F /IM Update.exe >nul 2>&1

echo Starting dpibypass wire engine...
dpibypass.exe run --config config.json --webui 127.0.0.1:8787
if errorlevel 1 (
    echo.
    echo [ERROR] Engine exited with an error.
    pause
)
pause
