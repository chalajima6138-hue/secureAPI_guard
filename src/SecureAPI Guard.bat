@echo off
setlocal
title SecureAPI Guard
cd /d "%~dp0"

echo ==============================================
echo   SecureAPI Guard - local start
echo ==============================================
echo.

where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js is not installed. Install the LTS version from https://nodejs.org and run this again.
  pause
  exit /b 1
)

rem Needs Node 22.5 or newer (built-in SQLite).
node -e "const [a,b]=process.versions.node.split('.').map(Number);process.exit(a>22||(a===22&&b>=5)?0:1)"
if errorlevel 1 (
  echo [ERROR] Your Node.js is too old:
  node --version
  echo Install Node.js 22.5 or newer from https://nodejs.org and run this again.
  pause
  exit /b 1
)

if not exist node_modules (
  echo First run: installing dependencies...
  call npm install
  if errorlevel 1 (
    echo [ERROR] npm install failed.
    pause
    exit /b 1
  )
)

rem Local testing only: lets you protect a backend running on this computer (for example http://127.0.0.1:4000).
rem The server still listens on this computer only (127.0.0.1). Never use this setting in production.
set ALLOW_PRIVATE_UPSTREAMS=true
set PORT=3000

echo.
echo Starting server at http://localhost:%PORT%
echo Your browser will open in a few seconds. Keep this window open. Press Ctrl+C to stop.
echo.

start "" /b cmd /c "timeout /t 3 >nul & start "" http://localhost:%PORT%"
call npm start

echo.
echo Server stopped.
pause