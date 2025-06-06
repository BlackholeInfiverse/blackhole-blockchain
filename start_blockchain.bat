@echo off
echo Starting Blackhole Blockchain Node...
echo.
echo This will start the blockchain node with mining, validators, and P2P networking.
echo Copy the peer multiaddr that appears and use it in the wallet configuration.
echo.
pause
cd core\relay-chain\cmd\relay
go run main.go 3000
