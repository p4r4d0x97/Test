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
REM ==============================================

REM If a list already exists, resume from it instead of rescanning
if exist "%OUTFILE%" (
    echo Resuming with existing list: %OUTFILE%
    goto LOOP
)

:SCAN
echo Scanning %SUBNET%.%START% - %SUBNET%.%END% ...
type nul > "%TMPFILE%"
set /a FREE=0

for /L %%i in (%START%,1,%END%) do (
    REM Check for "TTL=" so "Destination host unreachable" counts as offline
    ping -n 1 -w %TIMEOUT% %SUBNET%.%%i | find "TTL=" >nul
    if errorlevel 1 (
        >>"%TMPFILE%" echo %SUBNET%.%%i
        set /a FREE+=1
    )
)

move /y "%TMPFILE%" "%OUTFILE%" >nul
echo Scan done. !FREE! free IPs saved to %OUTFILE%

:LOOP
echo.
echo Next check in %INTERVAL% seconds. Press Ctrl+C to stop.
timeout /t %INTERVAL% /nobreak >nul

type nul > "%TMPFILE%"
set /a FREE=0

for /f "usebackq delims=" %%a in ("%OUTFILE%") do (
    ping -n 1 -w %TIMEOUT% %%a | find "TTL=" >nul
    if errorlevel 1 (
        >>"%TMPFILE%" echo %%a
        set /a FREE+=1
    )
)

move /y "%TMPFILE%" "%OUTFILE%" >nul
echo [!date! !time!] !FREE! IPs still free.
goto LOOP
