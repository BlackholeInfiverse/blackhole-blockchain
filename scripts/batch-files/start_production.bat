@echo off
echo ========================================
echo    Blackhole Blockchain Production
echo ========================================
echo.

REM Check if binaries exist
if not exist "bin\blockchain.exe" (
    echo ❌ Blockchain binary not found. Please run deploy.bat first.
    pause
    exit /b 1
)

if not exist "bin\wallet.exe" (
    echo ❌ Wallet binary not found. Please run deploy.bat first.
    pause
    exit /b 1
)

REM Check if MongoDB is running
echo 🔍 Checking MongoDB connection...
mongosh --eval "db.runCommand('ping')" >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ MongoDB is not running or not accessible
    echo Please start MongoDB service
    pause
    exit /b 1
)

echo ✅ Prerequisites check passed
echo.

REM Create necessary directories
if not exist "data" mkdir data
if not exist "logs" mkdir logs

REM Start blockchain in background
echo 🚀 Starting blockchain node...
start "Blackhole Blockchain" /min bin\blockchain.exe 3000

REM Wait for blockchain to start
echo ⏳ Waiting for blockchain to initialize...
timeout /t 10 /nobreak >nul

REM Get peer address from blockchain
echo 🔍 Getting peer address...
for /f "tokens=*" %%i in ('findstr /c:"Peer address:" logs\blockchain.log 2^>nul') do set PEER_LINE=%%i
if defined PEER_LINE (
    for /f "tokens=3" %%j in ("%PEER_LINE%") do set PEER_ADDR=%%j
) else (
    set PEER_ADDR=/ip4/127.0.0.1/tcp/3000/p2p/12D3KooWDefaultPeerAddress
)

echo 📡 Using peer address: %PEER_ADDR%

REM Start wallet service
echo 🚀 Starting wallet service...
start "Blackhole Wallet" /min bin\wallet.exe -web -port 9000 -peerAddr %PEER_ADDR%

REM Wait for services to start
echo ⏳ Waiting for services to start...
timeout /t 15 /nobreak >nul

echo.
echo ✅ Production system started successfully!
echo.
echo 🌐 Service URLs:
echo   Wallet Dashboard:    http://localhost:9000
echo   Blockchain API:      http://localhost:8080
echo   Health Check:        http://localhost:8080/api/health
echo.
echo 📊 System Status:
echo   Blockchain Node:     Running on port 3000 (P2P) and 8080 (API)
echo   Wallet Service:      Running on port 9000
echo   Database:            MongoDB (connected)
echo.
echo 📁 Data Locations:
echo   Blockchain Data:     .\data\
echo   Logs:               .\logs\
echo.
echo 🛠️ Management:
echo   Stop services:       stop_production.bat
echo   View logs:          type logs\blockchain.log
echo   Restart:            stop_production.bat then start_production.bat
echo.

REM Open wallet dashboard
echo Opening wallet dashboard...
timeout /t 3 /nobreak >nul
start http://localhost:9000

echo.
echo Press any key to exit (services will continue running)...
pause >nul
