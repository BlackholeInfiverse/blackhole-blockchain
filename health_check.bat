@echo off
echo ========================================
echo   Blackhole Blockchain Health Check
echo ========================================
echo.

set HEALTHY=1

REM Check if processes are running
echo 🔍 Checking running processes...
tasklist /fi "imagename eq blockchain.exe" 2>nul | find /i "blockchain.exe" >nul
if %errorlevel% equ 0 (
    echo ✅ Blockchain node is running
) else (
    echo ❌ Blockchain node is NOT running
    set HEALTHY=0
)

tasklist /fi "imagename eq wallet.exe" 2>nul | find /i "wallet.exe" >nul
if %errorlevel% equ 0 (
    echo ✅ Wallet service is running
) else (
    echo ❌ Wallet service is NOT running
    set HEALTHY=0
)

REM Check MongoDB
echo.
echo 🔍 Checking MongoDB connection...
mongosh --eval "db.runCommand('ping')" >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ MongoDB is connected
) else (
    echo ❌ MongoDB is NOT accessible
    set HEALTHY=0
)

REM Check API endpoints
echo.
echo 🔍 Checking API endpoints...
curl -s http://localhost:8080/api/health >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Blockchain API is responding
) else (
    echo ❌ Blockchain API is NOT responding
    set HEALTHY=0
)

curl -s http://localhost:9000 >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Wallet web interface is accessible
) else (
    echo ❌ Wallet web interface is NOT accessible
    set HEALTHY=0
)

REM Check data directories
echo.
echo 🔍 Checking data directories...
if exist "data" (
    echo ✅ Data directory exists
) else (
    echo ⚠️ Data directory missing
)

if exist "logs" (
    echo ✅ Logs directory exists
) else (
    echo ⚠️ Logs directory missing
)

echo.
echo ========================================
if %HEALTHY% equ 1 (
    echo ✅ SYSTEM HEALTHY - All checks passed
    echo.
    echo 🌐 Access Points:
    echo   Wallet: http://localhost:9000
    echo   API:    http://localhost:8080/api/health
) else (
    echo ❌ SYSTEM UNHEALTHY - Some checks failed
    echo.
    echo 🔧 Recommended Actions:
    echo   1. Run: start_production.bat
    echo   2. Check logs in .\logs\ directory
    echo   3. Ensure MongoDB is running
)
echo ========================================
echo.
pause
