@echo off
title BHX Token - BUDGET DEPLOYMENT (Under $1!)

echo 🌌 BlackHole (BHX) Token - BUDGET-FRIENDLY Deployment
echo ======================================================
echo 💰 ZERO UPFRONT COSTS - Deploy for under $1!
echo.
echo 📍 DEPLOYMENT WALLET: 0xe5C146a2FCD0844818604a74Cc75F2a4aE25579c
echo 💡 Boss should fund this address with $15-20 worth of ETH/USDC/BNB

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed. Please install Node.js first.
    echo Download: https://nodejs.org/
    pause
    exit /b 1
)

REM Check if we're in the right directory
if not exist "contracts\BHX_ERC20.sol" (
    echo [ERROR] BHX_ERC20.sol not found. Make sure you're in the project root directory.
    pause
    exit /b 1
)

echo [INFO] Setting up BUDGET deployment environment...

REM Navigate to contracts directory
cd contracts

REM Check if .env file exists
if not exist ".env" (
    echo [WARNING] .env file not found. Creating from template...
    copy .env.example .env
    echo.
    echo ⚠️  IMPORTANT: You need to edit contracts\.env file with:
    echo    1. Your wallet private key
    echo    2. RPC URLs (we'll help you get FREE ones)
    echo.
    echo 🆓 FREE RPC URLs you can use:
    echo    POLYGON: https://polygon-rpc.com/
    echo    BSC: https://bsc-dataseed1.binance.org/
    echo.
    pause
)

REM Install dependencies
echo [INFO] Installing dependencies...
call npm install

REM Compile contracts
echo [INFO] Compiling contracts...
call npm run compile

REM Show budget-friendly options
echo.
echo 💰 BUDGET-FRIENDLY DEPLOYMENT OPTIONS:
echo.
echo 1) Ethereum Sepolia Testnet - COMPLETELY FREE! (RECOMMENDED)
echo    • Need: FREE testnet ETH from faucets
echo    • Get testnet ETH: https://sepoliafaucet.com/
echo    • Perfect for: Testing everything with zero cost
echo    • Exchanges: Can test listing process
echo.
echo 2) Polygon Mainnet - CHEAPEST REAL DEPLOYMENT! (~$0.10 total cost)
echo    • Need: ~$0.50 worth of MATIC tokens
echo    • Get MATIC: Buy on any exchange or bridge from Ethereum
echo    • Exchanges that list Polygon tokens: PancakeSwap, QuickSwap
echo.
echo 3) BSC Mainnet - VERY CHEAP! (~$1 total cost)  
echo    • Need: ~$2 worth of BNB tokens
echo    • Get BNB: Buy on Binance or any exchange
echo    • Exchanges that list BSC tokens: PancakeSwap, many others
echo.
echo 4) Ethereum Mainnet - EXPENSIVE! ($50-150 cost) ❌
echo    • Only choose if you have the budget
echo.

set /p network_choice="Enter your choice (1-4): "

if "%network_choice%"=="1" (
    set NETWORK=sepolia
    echo [INFO] 🔥 PERFECT CHOICE! Deploying to Sepolia testnet - COMPLETELY FREE!
    echo [INFO] You'll need FREE testnet ETH from faucets
    echo [INFO] Get testnet ETH: https://sepoliafaucet.com/
) else if "%network_choice%"=="2" (
    set NETWORK=polygon
    echo [INFO] 🔥 SMART CHOICE! Deploying to Polygon - cheapest mainnet option!
    echo [INFO] You'll need about $0.50 worth of MATIC tokens
    echo [INFO] Get MATIC: https://quickswap.exchange/ or any CEX
) else if "%network_choice%"=="3" (
    set NETWORK=bsc
    echo [INFO] 🔥 GOOD CHOICE! Deploying to BSC - very cheap!
    echo [INFO] You'll need about $2 worth of BNB tokens
    echo [INFO] Get BNB: https://pancakeswap.finance/ or Binance
) else if "%network_choice%"=="4" (
    set NETWORK=mainnet
    echo [WARNING] ⚠️  EXPENSIVE OPTION! This will cost $50-150 in gas fees!
    set /p confirm="Are you sure you want to spend this much? (y/N): "
    if /i not "%confirm%"=="y" (
        echo [INFO] 💡 Smart decision! Choose Polygon (option 1) instead for $0.10!
        pause
        exit /b 1
    )
) else (
    echo [ERROR] Invalid choice. Exiting.
    pause
    exit /b 1
)

echo.
echo [INFO] 🚀 Deploying BHX token to %NETWORK%...
echo [INFO] This is where the magic happens!

REM Deploy contract
call npm run deploy:%NETWORK%

if %errorlevel% eq 0 (
    echo.
    echo [SUCCESS] 🎉 CONTRACT DEPLOYED SUCCESSFULLY!
    echo.
    
    REM Show next steps based on network
    if "%NETWORK%"=="sepolia" (
        echo 🔥 SEPOLIA TESTNET DEPLOYMENT SUCCESS!
        echo ✅ Your BHX token is now live on Ethereum Sepolia testnet
        echo ✅ Total cost: $0 - COMPLETELY FREE!
        echo.
        echo 📈 IMMEDIATE NEXT STEPS:
        echo 1. Test trading on testnet DEXes
        echo 2. Verify all functions work perfectly
        echo 3. Get community feedback on testnet
        echo 4. When ready, deploy to mainnet with confidence
        echo.
        echo 💡 SEPOLIA ADVANTAGES:
        echo • Identical to Ethereum mainnet functionality
        echo • Perfect for testing exchange integrations
        echo • No financial risk - test everything
        echo • Build confidence before mainnet
    )
    
    if "%NETWORK%"=="polygon" (
        echo 🔥 POLYGON DEPLOYMENT SUCCESS!
        echo ✅ Your BHX token is now live on Polygon network
        echo ✅ Total cost: Under $1!
        echo.
        echo 📈 IMMEDIATE NEXT STEPS:
        echo 1. Add liquidity on QuickSwap: https://quickswap.exchange/
        echo 2. List on DexScreener: https://dexscreener.com/
        echo 3. Submit to CoinGecko: https://www.coingecko.com/en/coins/new
        echo 4. Join Polygon communities and announce your token
        echo.
        echo 💡 POLYGON ADVANTAGES:
        echo • Very cheap transactions (cents, not dollars)
        echo • Fast finality (2-3 seconds)  
        echo • Growing ecosystem
        echo • Many DEXes support Polygon tokens
    )
    
    if "%NETWORK%"=="bsc" (
        echo 🔥 BSC DEPLOYMENT SUCCESS!
        echo ✅ Your BHX token is now live on Binance Smart Chain
        echo ✅ Total cost: Under $2!
        echo.
        echo 📈 IMMEDIATE NEXT STEPS:
        echo 1. Add liquidity on PancakeSwap: https://pancakeswap.finance/
        echo 2. List on DexScreener: https://dexscreener.com/
        echo 3. Submit to CoinGecko: https://www.coingecko.com/en/coins/new
        echo 4. Huge BSC community - announce everywhere!
        echo.
        echo 💡 BSC ADVANTAGES:
        echo • Cheap transactions 
        echo • Massive user base
        echo • PancakeSwap is huge
        echo • Easy to get listed on exchanges
    )
    
    if "%NETWORK%"=="sepolia" (
        echo 🔥 TESTNET DEPLOYMENT SUCCESS!
        echo ✅ Your BHX token is now live on Sepolia testnet
        echo ✅ Total cost: $0 - COMPLETELY FREE!
        echo.
        echo 📈 NEXT STEPS:
        echo 1. Test all functionality thoroughly
        echo 2. When ready, deploy to Polygon mainnet for $0.10
        echo 3. Or deploy to BSC mainnet for ~$1
        echo.
        echo 💡 TESTING ADVANTAGES:
        echo • Perfect for development
        echo • No financial risk
        echo • Test everything before mainnet
    )
    
    echo.
    echo 🚀 BUDGET SUCCESS STRATEGY:
    echo.
    echo Week 1: Community Building (FREE)
    echo • Create Telegram group
    echo • Start Twitter account
    echo • Post on Reddit communities
    echo • Build organic following
    echo.
    echo Week 2: Bootstrap Liquidity (MINIMAL COST)
    echo • Add $50-100 liquidity if you can
    echo • Or ask community to add liquidity
    echo • Get trading started
    echo.
    echo Week 3: Free Exchange Applications
    echo • CoinGecko: FREE listing
    echo • CoinMarketCap: FREE listing  
    echo • MEXC Community Vote: FREE if community supports
    echo • Gate.io Startup Program: FREE for promising projects
    echo.
    echo Week 4: Revenue Generation
    echo • Collect trading fees from your DEX
    echo • Bridge transaction fees
    echo • Community donations/support
    echo • Reinvest profits into bigger exchanges
    echo.
    
    echo 📋 FREE MARKETING CHANNELS:
    echo • Reddit: r/CryptoMoonShots, r/altcoin
    echo • Twitter: Build following with #BHX hashtag
    echo • Telegram: Create community group
    echo • Discord: Join crypto communities
    echo • YouTube: Make tutorial videos
    echo.
    echo 💰 BOOTSTRAP REVENUE IDEAS:
    echo • Offer blockchain consulting services
    echo • Create NFT collection
    echo • Launch token staking rewards
    echo • Partner with other projects
    echo • Apply for blockchain grants
    echo.
    
) else (
    echo [ERROR] Contract deployment failed!
    echo.
    echo 🔧 COMMON ISSUES:
    echo 1. Not enough tokens for gas fees
    echo 2. Wrong private key in .env file
    echo 3. Network RPC issues
    echo.
    echo 💡 SOLUTIONS:
    echo 1. Get tokens from faucets (testnet) or buy small amount
    echo 2. Double-check your .env file
    echo 3. Try different RPC URL
    pause
    exit /b 1
)

echo.
echo [SUCCESS] 🚀 BHX Token deployed with MINIMAL BUDGET!
echo 📋 Check ZERO_BUDGET_STRATEGY.md for complete roadmap
echo 💡 Remember: Start small, grow organically, reinvest profits!

pause