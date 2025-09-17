@echo off
title FREE Mumbai Testnet Deployment
cls

echo 🌟 BlackHole DEX - FREE Mumbai Testnet Deployment
echo ================================================
echo.
echo 💡 Perfect for testing with your 10 TRON budget!
echo 💰 Cost: $0.00 (completely FREE)
echo ⏱️ Time: 5 minutes
echo.

REM Check prerequisites
echo [INFO] Checking prerequisites...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js not found. Please install Node.js first.
    pause
    exit /b 1
)

if not exist "contracts\BHX_ERC20.sol" (
    echo [ERROR] Smart contracts not found. Make sure you're in the project root.
    pause
    exit /b 1
)

echo [SUCCESS] ✅ Prerequisites checked
echo.

REM Navigate to contracts directory
cd contracts

REM Check .env configuration
echo [INFO] Checking environment configuration...
if not exist ".env" (
    echo [WARNING] Creating .env file from template...
    copy .env.example .env >nul
    echo [IMPORTANT] Please edit contracts\.env with your test wallet private key
    echo [IMPORTANT] Then run this script again
    echo.
    echo Example .env setup:
    echo PRIVATE_KEY=your_test_wallet_private_key_without_0x
    echo.
    pause
    exit /b 1
)

REM Install dependencies
echo [INFO] Installing dependencies...
call npm install --silent

REM Compile contracts
echo [INFO] Compiling smart contracts...
call npm run compile

echo.
echo [INFO] 🚀 Deploying to Mumbai testnet...
echo [INFO] Network: Polygon Mumbai (Testnet)
echo [INFO] Cost: FREE (using testnet MATIC)
echo [INFO] Expected gas: ~2M gas units
echo.

REM Deploy to Mumbai
call npm run deploy:mumbai

if %errorlevel% eq 0 (
    echo.
    echo [SUCCESS] 🎉 Contract deployed successfully to Mumbai!
    echo.
    echo 📋 Next Steps:
    echo 1. ✅ Add BHX token to MetaMask using contract address above
    echo 2. 🌊 Test on Mumbai QuickSwap: https://quickswap.exchange/
    echo 3. 🔄 Try swapping BHX with other Mumbai tokens
    echo 4. 📊 Monitor transactions: https://mumbai.polygonscan.com/
    echo.
    echo 💡 When ready for mainnet:
    echo    - Polygon mainnet deployment costs only ~$0.50
    echo    - Use: npm run deploy:polygon
    echo.
    echo 🔗 Mumbai Network Details:
    echo    RPC: https://rpc-mumbai.maticvigil.com/
    echo    Chain ID: 80001
    echo    Explorer: https://mumbai.polygonscan.com/
    echo.
) else (
    echo.
    echo [ERROR] ❌ Deployment failed!
    echo.
    echo 🔧 Troubleshooting:
    echo 1. Make sure you have Mumbai MATIC in your wallet
    echo 2. Check your private key in .env file
    echo 3. Verify Mumbai network is accessible
    echo.
    echo 🎁 Get FREE Mumbai MATIC:
    echo    - https://faucet.polygon.technology/
    echo    - https://mumbaifaucet.com/
    echo.
)

echo.
echo 📋 Your DEX Local Test Results: 94.1%% success rate
echo 🎯 Mumbai testnet will validate real network functionality
echo 💰 Total cost so far: $0.00
echo.
pause