@echo off
setlocal EnableExtensions
title MalTracer Service Stopper

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

echo.
echo ============================================================
echo                   Stopping MalTracer
echo ============================================================
echo.

REM Prefer stopping by saved PIDs created by the single-console launcher.
if exist "%ROOT%\backend.pid" (
    set /p BACKEND_PID=<"%ROOT%\backend.pid"
    if defined BACKEND_PID (
        taskkill /PID %BACKEND_PID% /T /F >nul 2>&1
    )
    del /q "%ROOT%\backend.pid" >nul 2>&1
)

if exist "%ROOT%\frontend.pid" (
    set /p FRONTEND_PID=<"%ROOT%\frontend.pid"
    if defined FRONTEND_PID (
        taskkill /PID %FRONTEND_PID% /T /F >nul 2>&1
    )
    del /q "%ROOT%\frontend.pid" >nul 2>&1
)

REM Fallback: stop anything still listening on MalTracer's ports.
powershell -NoProfile -Command ^
  "$ports = 5055,5173; foreach ($port in $ports) { Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | ForEach-Object { try { Stop-Process -Id $_.OwningProcess -Force -ErrorAction Stop } catch {} } }"

echo MalTracer backend and frontend stop request completed.
echo.
pause
