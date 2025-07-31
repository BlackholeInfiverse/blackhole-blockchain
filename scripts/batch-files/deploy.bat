@echo off
REM BlackHole Blockchain Simple Deployment Script for Windows
REM This script builds production binaries for local deployment

setlocal enabledelayedexpansion

echo 🚀 BlackHole Blockchain Production Deployment
echo ===============================================

REM Check prerequisites
echo [STEP] Checking prerequisites...

REM Check if Go is installed
go version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Go is not installed or not in PATH
    echo [INFO] Please install Go from: https://golang.org/dl/
    pause
    exit /b 1
)

REM Check if MongoDB is accessible
echo [INFO] Checking MongoDB connection...
mongosh --eval "db.runCommand('ping')" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] MongoDB is not running or not accessible
    echo [INFO] Please ensure MongoDB is installed and running
    echo [INFO] You can continue deployment and start MongoDB later
    echo.
)

echo [INFO] Prerequisites check completed

REM Create necessary directories
echo [STEP] Creating necessary directories...
if not exist "bin" mkdir bin
if not exist "logs" mkdir logs
if not exist "data" mkdir data
echo [INFO] Directories created successfully

REM Build blockchain binary
echo [STEP] Building blockchain binary...
cd core\relay-chain\cmd\relay
go build -o ..\..\..\..\bin\blockchain.exe main.go
if errorlevel 1 (
    echo [ERROR] Failed to build blockchain binary
    echo [INFO] Check Go installation and dependencies
    cd ..\..\..\..
    pause
    exit /b 1
)
cd ..\..\..\..
echo [INFO] Blockchain binary built successfully

REM Build wallet binary
echo [STEP] Building wallet binary...
cd services\wallet
go build -o ..\..\bin\wallet.exe main.go
if errorlevel 1 (
    echo [ERROR] Failed to build wallet binary
    echo [INFO] Check Go installation and dependencies
    cd ..\..
    pause
    exit /b 1
)
cd ..\..
echo [INFO] Wallet binary built successfully

echo [STEP] Deployment completed successfully!
echo.
echo ✅ Production binaries created:
echo    bin\blockchain.exe - Blockchain node
echo    bin\wallet.exe     - Wallet service
echo.
echo 📁 Directory structure:
echo    bin\               - Executable files
echo    data\              - Blockchain data (created on first run)
echo    logs\              - Log files (created on first run)
echo.
echo 🚀 Next steps:
echo    1. Start system:    start_production.bat
echo    2. Check health:    health_check.bat
echo    3. Stop system:     stop_production.bat
echo.
echo 🌐 Once started, access:
echo    Wallet Dashboard:   http://localhost:9000
echo    Blockchain API:     http://localhost:8080
echo    Health Check:       http://localhost:8080/api/health
echo.
echo 📖 Documentation:
echo    README_PRODUCTION.md - Complete production guide
echo.
echo [INFO] Deployment completed! Run start_production.bat to begin.
pause
