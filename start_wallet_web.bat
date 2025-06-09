@echo off
echo Starting Wallet Web UI...
echo.
echo This will start the wallet service in web UI mode.
echo.
echo Make sure to:
echo 1. Start MongoDB first (mongod)
echo 2. Start the blockchain node first (start_blockchain.bat)
echo 3. Copy the peer multiaddr from the blockchain node output
echo.
echo The wallet web UI will be available at: http://localhost:9000
echo.
pause
cd services\wallet
set /p peerAddr="Enter peer address (or press Enter for offline mode): "
if "%peerAddr%"=="" (
    go run main.go -web -port 9000
) else (
    go run main.go -web -port 9000 -peerAddr %peerAddr%
)
