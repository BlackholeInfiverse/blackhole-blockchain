@echo off
echo Starting Wallet Service...
echo.
echo Make sure to:
echo 1. Start MongoDB first (mongod)
echo 2. Start the blockchain node first (start_blockchain.bat)
echo 3. Copy the peer multiaddr from the blockchain node output
echo.
echo Usage Examples:
echo   go run main.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R
echo   go run main.go (runs in offline mode)
echo.
pause
cd services\wallet
set /p peerAddr="Enter peer address (or press Enter for offline mode): "
if "%peerAddr%"=="" (
    go run main.go
) else (
    go run main.go -peerAddr %peerAddr%
)
