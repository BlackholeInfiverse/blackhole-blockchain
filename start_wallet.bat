@echo off
echo Starting Wallet Service...
echo.
echo Make sure to:
echo 1. Start MongoDB first (mongod)
echo 2. Start the blockchain node first (start_blockchain.bat)
echo 3. Update the peer address in services\wallet\main.go line 54
echo.
pause
cd services\wallet
go run main.go
