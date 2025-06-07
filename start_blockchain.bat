@echo off
echo Starting Blackhole Blockchain Node...
echo.
echo This will start the blockchain node with mining, validators, and P2P networking.
echo.
echo IMPORTANT: Copy the peer multiaddr that appears and use it with the wallet:
echo   Example: go run main.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/12D3KooW...
echo.
echo The blockchain will also start an HTML dashboard on http://localhost:8080
echo.
pause
cd core\relay-chain\cmd\relay
go run main.go 3000
