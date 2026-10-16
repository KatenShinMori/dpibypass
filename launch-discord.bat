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

title dpibypass - Launch Discord with Wire Bypass
echo =======================================================
echo   dpibypass - Discord Launcher with Wire Bypass
echo =======================================================
echo.

if not exist "dpibypass.exe" (
    echo [ERROR] dpibypass.exe not found in "%~dp0".
    echo Please run build.ps1 first to compile the binary.
    echo.
    pause
    exit /b 1
)

echo [1/4] Closing any stuck Discord or Update processes...
taskkill /F /IM Discord.exe >nul 2>&1
taskkill /F /IM Update.exe >nul 2>&1

echo [2/4] Starting fresh dpibypass packet wire engine...
taskkill /F /IM dpibypass.exe >nul 2>&1
timeout /t 1 /nobreak >nul
dpibypass.exe recover >nul 2>&1

set "ENGINE_READY=0"
echo Starting dpibypass wire engine in background...
start "dpibypass Wire Engine" /min "%~dp0dpibypass.exe" run --config "%~dp0config.json" --webui 127.0.0.1:8787

echo Waiting for DoH hosts sync and WinDivert driver initialization...
for /L %%i in (1,1,20) do (
    timeout /t 1 /nobreak >nul
    curl.exe -s -m 1 http://127.0.0.1:8787/api/stats >nul 2>&1
    if !errorlevel! equ 0 (
        set "ENGINE_READY=1"
        goto :engine_ready
    )
)

:engine_ready
if "!ENGINE_READY!" neq "1" (
    echo [ERROR] dpibypass failed to initialize WinDivert driver within 20 seconds.
    echo Please check if another security tool or driver is conflicting.
    pause
    exit /b 1
)
echo dpibypass wire engine is active and capturing packets.

echo [3/4] Flushing and verifying Windows DNS Resolver Cache...
ipconfig /flushdns >nul 2>&1

echo Verifying clean resolution for Discord domains...
set "DNS_CLEAN=0"
for /L %%k in (1,1,5) do (
    powershell -NoProfile -Command "$domains = @('discord.com', 'updates.discord.com', 'gateway.discord.gg', 'cdn.discordapp.com', 'media.discordapp.net', 'status.discord.com', 'dl.discordapp.net'); $poisoned = $false; foreach ($d in $domains) { try { $addrs = [System.Net.Dns]::GetHostAddresses($d); $ips = ($addrs | ForEach-Object { $_.IPAddressToString }) -join ', '; if (-not $ips -or ($ips -match '195\.175\.254\.2')) { Write-Host ('  [WARN] ' + $d + ' resolved to ISP sinkhole: ' + $ips); $poisoned = $true } else { Write-Host ('  [OK] ' + $d + ' -> ' + $ips) } } catch { Write-Host ('  [FAIL] ' + $d + ': ' + $_.Exception.Message); if ($d -eq 'discord.com' -or $d -eq 'updates.discord.com') { $poisoned = $true } } }; if ($poisoned) { exit 2 } else { exit 0 }"
    if !errorlevel! equ 0 (
        set "DNS_CLEAN=1"
        goto :dns_verified
    )
    echo [WARNING] ISP poisoned DNS record 195.175.254.2 detected. Re-flushing...
    ipconfig /flushdns >nul 2>&1
    timeout /t 1 /nobreak >nul
)

:dns_verified
if "!DNS_CLEAN!" neq "1" (
    echo [ERROR] updates.discord.com or discord.com did not resolve to a clean IP.
    echo Aborting Discord launch to prevent Chromium HostCache sinkhole poisoning.
    pause
    exit /b 1
)
echo [OK] Verified clean Discord resolution with no ISP poisoning.

echo [4/4] Locating and launching Discord desktop client...
set "DISCORD_EXE="
if exist "%LOCALAPPDATA%\Discord\Update.exe" (
    set "DISCORD_EXE=%LOCALAPPDATA%\Discord\Update.exe"
    start "" "!DISCORD_EXE!" --processStart Discord.exe
    echo Discord launched via Update.exe.
    goto :done
)

for /d %%D in ("%LOCALAPPDATA%\Discord\app-*") do (
    if exist "%%D\Discord.exe" (
        set "DISCORD_EXE=%%D\Discord.exe"
    )
)

if defined DISCORD_EXE (
    start "" "!DISCORD_EXE!"
    echo Discord launched from !DISCORD_EXE!.
    goto :done
)

echo [WARNING] Discord executable was not found in %LOCALAPPDATA%\Discord.
echo Please start Discord manually from your Start Menu or Desktop.

:done
echo.
echo Setup complete. Discord update and launch in progress.
timeout /t 3 /nobreak >nul
exit /b 0
