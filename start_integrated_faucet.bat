@echo off
echo ========================================
echo 🌍 BlackHole Integrated Faucet System
echo ========================================
echo.
echo This script starts the integrated faucet system with proper blockchain connection.
echo.

REM Check if blockchain is running
echo 🔍 Checking if blockchain is running...
netstat -an | findstr ":3000" >nul
if %errorlevel% equ 0 (
    echo ✅ Blockchain appears to be running on port 3000
) else (
    echo ⚠️  Blockchain doesn't appear to be running on port 3000
    echo.
    echo Would you like to start the blockchain first?
    set /p START_BLOCKCHAIN="Start blockchain? (y/n): "
    if /i "%START_BLOCKCHAIN%"=="y" (
        echo 🚀 Starting blockchain...
        start "BlackHole Blockchain" cmd /k "start_blockchain.bat"
        echo ⏳ Waiting 10 seconds for blockchain to initialize...
        timeout /t 10 /nobreak >nul
    )
)

echo.
echo 🔧 Setting up faucet integration...

REM Navigate to faucet directory
cd services\validator-faucet

REM Build the faucet
echo 🔨 Building faucet...
go build -o faucet.exe real_world_faucet.go
if %errorlevel% neq 0 (
    echo ❌ Failed to build faucet
    pause
    exit /b 1
)

echo ✅ Faucet built successfully

REM Get peer address for connection
echo.
echo 🔗 Blockchain Connection Setup
echo.
echo You can either:
echo 1. Use default local peer address
echo 2. Enter custom peer address
echo 3. Start without connection (configure later)
echo.

set /p CONNECTION_CHOICE="Choose option (1/2/3): "

if "%CONNECTION_CHOICE%"=="1" (
    set PEER_ADDRESS=/ip4/127.0.0.1/tcp/3000/p2p/12D3KooWG5v7Kff6pcNjAyd9upk53d47vLADeD1DkKJ55mfsiwEL
    echo Using default peer: %PEER_ADDRESS%
) else if "%CONNECTION_CHOICE%"=="2" (
    set /p PEER_ADDRESS="Enter peer address: "
) else (
    set PEER_ADDRESS=
    echo Starting without initial connection
)

echo.
echo 🚀 Starting Integrated Faucet System...
echo.
echo Configuration:
echo - Port: 8095
echo - Token: BHX (BlackHole)
echo - Amount: 50 BHX per request
echo - Cooldown: 3 hours
echo - Daily Limit: 8 requests
echo.

if "%PEER_ADDRESS%"=="" (
    echo 🌐 Starting faucet without blockchain connection...
    echo 💡 Configure connection via admin panel: http://localhost:8095/admin
    faucet.exe
) else (
    echo 🌐 Starting faucet with blockchain connection: %PEER_ADDRESS%
    faucet.exe "%PEER_ADDRESS%"
)

echo.
echo 📍 Access Points:
echo - Faucet Web Interface: http://localhost:8095
echo - Admin Panel: http://localhost:8095/admin (API Key: real_world_admin_2024)
echo - API Documentation: http://localhost:8095/api/v1
echo - Health Check: http://localhost:8095/api/v1/health
echo.

if %errorlevel% neq 0 (
    echo ❌ Faucet failed to start
    echo.
    echo Common issues:
    echo - Port 8095 already in use
    echo - Blockchain connection failed
    echo - Missing dependencies
    echo.
    echo Check the error messages above for details.
)

echo.
pause
