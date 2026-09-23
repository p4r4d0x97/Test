@echo off
setlocal EnableDelayedExpansion
title IP Availability Scanner

REM ================== SETTINGS ==================
set "SUBNET=192.168.1"
set "START=1"
set "END=254"
REM Seconds between re-checks (300 = 5 minutes)
set "INTERVAL=300"
REM Ping timeout in milliseconds
set "TIMEOUT=500"
set "OUTFILE=%~dp0available_ips.txt"
set "TMPFILE=%~dp0available_ips.tmp"
set "LOGFILE=%~dp0came_online_log.txt"
REM ==============================================

echo ============================================
echo  Initial scan: %SUBNET%.%START% - %SUBNET%.%END%
echo ============================================

if exist "%OUTFILE%" del "%OUTFILE%"
type nul > "%OUTFILE%"
set /a FREE=0

for /L %%i in (%START%,1,%END%) do (
    REM Check for "TTL=" so "Destination host unreachable" counts as offline
    ping -n 1 -w %TIMEOUT% %SUBNET%.%%i | find "TTL=" >nul
    if errorlevel 1 (
        >>"%OUTFILE%" echo %SUBNET%.%%i
        set /a FREE+=1
        echo   %SUBNET%.%%i  - no reply
    ) else (
        echo   %SUBNET%.%%i  - ONLINE
    )
)

echo.
echo Initial scan done. !FREE! possibly free IPs saved to:
echo   %OUTFILE%

:LOOP
echo.
echo Next check in %INTERVAL% seconds. Press Ctrl+C to stop.
timeout /t %INTERVAL% /nobreak
echo.
echo [!date! !time!] Re-checking free IPs...

type nul > "%TMPFILE%"
set /a FREE=0

for /f "usebackq delims=" %%a in ("%OUTFILE%") do (
    ping -n 1 -w %TIMEOUT% %%a | find "TTL=" >nul
    if errorlevel 1 (
        >>"%TMPFILE%" echo %%a
        set /a FREE+=1
    ) else (
        echo   %%a came ONLINE - removed from list
        >>"%LOGFILE%" echo [!date! !time!] %%a came online
    )
)

move /y "%TMPFILE%" "%OUTFILE%" >nul
echo [!date! !time!] !FREE! IPs still free.
goto LOOP
