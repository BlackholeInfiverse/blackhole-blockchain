@echo off
echo ========================================
echo   Stopping Blackhole Blockchain
echo ========================================
echo.

echo 🛑 Stopping blockchain services...

REM Stop blockchain process
taskkill /f /im blockchain.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Blockchain node stopped
) else (
    echo ⚠️ Blockchain node was not running
)

REM Stop wallet process
taskkill /f /im wallet.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Wallet service stopped
) else (
    echo ⚠️ Wallet service was not running
)

REM Close any remaining windows
taskkill /f /fi "WindowTitle eq Blackhole Blockchain" >nul 2>&1
taskkill /f /fi "WindowTitle eq Blackhole Wallet" >nul 2>&1

echo.
echo ✅ All services stopped successfully!
echo.
echo 📁 Data preserved in:
echo   .\data\ - Blockchain data
echo   .\logs\ - Log files
echo.
echo 🚀 To restart: start_production.bat
echo.
pause
