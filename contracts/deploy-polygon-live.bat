@echo off
title BHX Token - Polygon Mainnet Deployment
cls

echo 🟣 BlackHole DEX - Polygon Mainnet Deployment
echo =============================================
echo.
echo 💰 Your Funds: 0.2 POL (~$0.10-0.20)
echo 💸 Deployment Cost: ~$0.05
echo 💡 Perfect fit for your budget!
echo.

REM Check prerequisites
echo [INFO] Checking prerequisites...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js not found. Please install Node.js first.
    pause
    exit /b 1
)

if not exist "BHX_ERC20.sol" (
    echo [ERROR] Smart contracts not found. Make sure you're in contracts directory.
    pause
    exit /b 1
)

echo [SUCCESS] ✅ Prerequisites checked
echo.

REM Check .env configuration
echo [INFO] Checking private key configuration...
if not exist ".env" (
    echo [ERROR] .env file not found. Please create it first.
    pause
    exit /b 1
)

REM Install dependencies
echo [INFO] Installing/updating dependencies...
call npm install --silent

REM Compile contracts
echo [INFO] Compiling smart contracts...
call npm run compile

echo.
echo [INFO] 🚀 Deploying to Polygon Mainnet...
echo [INFO] Network: Polygon (MATIC/POL)
echo [INFO] Expected cost: ~$0.05
echo [INFO] Your address: 0xe5C146a2FCD0844818604a74Cc75F2a4aE25579c
echo [INFO] Available: 0.2 POL
echo.

echo [WARNING] ⚠️ This will deploy to REAL Polygon mainnet with REAL funds!
set /p confirm="Are you sure you want to continue? (y/N): "
if /i not "%confirm%"=="y" (
    echo [INFO] Deployment cancelled by user.
    pause
    exit /b 0
)

REM Deploy to Polygon
call npm run deploy:polygon

if %errorlevel% eq 0 (
    echo.
    echo [SUCCESS] 🎉 BHX Token deployed successfully to Polygon!
    echo.
    echo 📋 Next Steps:
    echo 1. ✅ Contract is now live on Polygon mainnet
    echo 2. 💧 Add liquidity on QuickSwap: https://quickswap.exchange/
    echo 3. 🔄 Start trading BHX tokens
    echo 4. 📊 Monitor on PolygonScan: https://polygonscan.com/
    echo 5. 📈 Submit to CoinGecko and CoinMarketCap
    echo.
    echo 💰 Estimated remaining balance: ~0.15 POL
    echo 💡 Perfect for adding initial liquidity!
    echo.
    echo 🔗 Polygon Network Details:
    echo    RPC: https://polygon-rpc.com/
    echo    Chain ID: 137
    echo    Explorer: https://polygonscan.com/
    echo.
    echo 🌉 Bridge to other networks later:
    echo    - Ethereum (when you have more funds)
    echo    - BSC (cheap alternative)
    echo    - Other L2s
    echo.
) else (
    echo.
    echo [ERROR] ❌ Deployment failed!
    echo.
    echo 🔧 Troubleshooting:
    echo 1. Check your private key in .env matches 0xe5C146a2FCD0844818604a74Cc75F2a4aE25579c
    echo 2. Verify you have sufficient POL balance
    echo 3. Check Polygon RPC is accessible
    echo 4. Try increasing gas limit if needed
    echo.
    echo 💰 Current balance check:
    echo    Visit: https://polygonscan.com/address/0xe5C146a2FCD0844818604a74Cc75F2a4aE25579c
    echo.
)

echo.
echo 📊 Deployment Summary:
echo ━━━━━━━━━━━━━━━━━━━━━━
echo Network: Polygon Mainnet
echo Cost: ~$0.05
echo Your Funds: 0.2 POL
echo Risk: Low (4x safety buffer)
echo DEX Ready: Yes (QuickSwap integration)
echo.
pause