@echo off
echo 🌌 Blackhole Blockchain - Fake Transaction Generator
echo ====================================================
echo.
echo Starting fake transaction generator...
echo This will generate transactions between:
echo   - Shivam:  03d0f85fe18231c5aa28cb3b405652a9f3ee1e9ef08aad36ad4c850c52f7bed10f
echo   - Shivam2: 02dc2e3faa525d9a343742e625a1e192560100288635d803a8883e22f7b65eef59
echo.
echo REQUIREMENTS:
echo   1. MongoDB running on localhost:27017
echo   2. Blockchain node running (relay chain)
echo   3. Peer address from the blockchain node
echo.

if "%1"=="" (
    echo ❌ Error: Peer address is required!
    echo.
    echo 📝 Usage: run_fake_transactions.bat ^<peer_address^> [rate]
    echo 📝 Example: run_fake_transactions.bat /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R 4.0
    echo.
    echo 🔧 To get the peer address:
    echo    1. Start blockchain node: go run blackhole-blockchain/core/relay-chain/cmd/relay/main.go
    echo    2. Copy the peer multiaddr from the output
    echo    3. Use that address with this script
    echo.
    pause
    exit /b 1
)

set PEER_ADDR=%1
set RATE=%2
if "%RATE%"=="" set RATE=4.0

echo 🔧 Using peer address: %PEER_ADDR%
echo 🎯 Transaction rate: %RATE% tx/sec
echo.
echo Press Ctrl+C to stop the generator
echo.
pause
echo.

cd test-tools
go run fake_transaction_generator.go -peerAddr "%PEER_ADDR%" -rate %RATE%
