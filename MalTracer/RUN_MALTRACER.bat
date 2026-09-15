@echo off
setlocal
title MalTracer Launcher

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "PYTHON=%ROOT%\Malsec_venv\Scripts\python.exe"
set "BACKEND=%ROOT%\Malsecure.py"
set "FRONTEND=%ROOT%\frontend-react"

echo.
echo ==========================================
echo          MalTracer System Launcher
echo ==========================================
echo.

if not exist "%PYTHON%" (
    echo [ERROR] Python virtual environment not found.
    pause
    exit /b 1
)

if not exist "%BACKEND%" (
    echo [ERROR] Backend file not found.
    pause
    exit /b 1
)

if not exist "%FRONTEND%\package.json" (
    echo [ERROR] React frontend not found.
    pause
    exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
    echo [ERROR] npm was not found in PATH.
    pause
    exit /b 1
)

echo [0/2] Cleaning old MalTracer processes...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$root='%ROOT%'; foreach($port in 5055,5173){ $conns=Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue; foreach($c in $conns){ $p=Get-CimInstance Win32_Process -Filter ('ProcessId=' + $c.OwningProcess) -ErrorAction SilentlyContinue; if($p -and $p.CommandLine -and $p.CommandLine -like ('*' + $root + '*')){ Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue } } }"

timeout /t 2 /nobreak >nul

echo [1/2] Starting Backend API...
start "MalTracer Backend API" cmd /k "cd /d "%ROOT%" && "%PYTHON%" "%BACKEND%" --ui"

timeout /t 2 /nobreak >nul

echo [2/2] Starting React Frontend...
start "MalTracer React Frontend" cmd /k "cd /d "%FRONTEND%" && npm run dev -- --port 5173 --strictPort"

timeout /t 4 /nobreak >nul

start "" "http://localhost:5173"

echo.
echo MalTracer started.
echo.
echo To stop:
echo   Backend window  -> CTRL+C
echo   Frontend window -> CTRL+C
echo.
exit /b 0
