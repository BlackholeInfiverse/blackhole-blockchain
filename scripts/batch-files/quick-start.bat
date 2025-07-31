@echo off
REM Quick Start Script for BlackHole Blockchain
REM This script starts the blockchain without Docker for immediate testing

echo 🚀 BlackHole Blockchain - Quick Start
echo =====================================

echo [INFO] Starting BlackHole Blockchain locally...

REM Check if Go is installed
go version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Go is not installed. Please install Go 1.21+ first.
    echo [INFO] Alternatively, use Docker deployment with: deploy-simple.bat
    pause
    exit /b 1
)

echo [INFO] Go is available

REM Navigate to blockchain directory
cd core\relay-chain\cmd\relay

REM Build the blockchain node
echo [INFO] Building blockchain node...
go mod tidy
go build -o blockchain-node.exe .

if errorlevel 1 (
    echo [ERROR] Failed to build blockchain node
    pause
    exit /b 1
)

echo [INFO] Starting blockchain node on port 3000...

REM Start the blockchain node
start "BlackHole Blockchain Node" blockchain-node.exe 3000

REM Wait a moment for startup
timeout /t 5 /nobreak >nul

echo.
echo ✅ BlackHole Blockchain is starting!
echo.
echo 🌐 Access Points:
echo    Blockchain Dashboard:   http://localhost:8080
echo    API Endpoint:          http://localhost:8080/api/status
echo    P2P Port:              3000
echo.
echo 🔧 Features Available:
echo    - Enhanced monitoring system
echo    - E2E validation framework  
echo    - Governance simulation
echo    - Load testing capabilities
echo    - Advanced security features
echo.
echo 📊 CLI Commands (in the blockchain window):
echo    status     - Show blockchain status
echo    monitor    - Show monitoring metrics
echo    validate   - Run E2E validation tests
echo    governance - Show governance dashboard
echo    proposal   - Create governance proposal
echo    vote       - Vote on proposals
echo.
echo Press any key to open the blockchain dashboard...
pause >nul

REM Open dashboard
start http://localhost:8080

echo.
echo 🎉 BlackHole Blockchain is now running!
echo    Check the blockchain node window for CLI commands
echo    Dashboard: http://localhost:8080
echo.
pause
