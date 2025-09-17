@echo off
title BHX Token Quick Deployment

echo 🌌 BlackHole (BHX) Token - Quick Deployment to Exchanges
echo ========================================================

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed. Please install Node.js first.
    pause
    exit /b 1
)

REM Check if we're in the right directory
if not exist "contracts\BHX_ERC20.sol" (
    echo [ERROR] BHX_ERC20.sol not found. Make sure you're in the project root directory.
    pause
    exit /b 1
)

echo [INFO] Setting up deployment environment...

REM Navigate to contracts directory
cd contracts

REM Check if .env file exists
if not exist ".env" (
    echo [WARNING] .env file not found. Creating from template...
    copy .env.example .env
    echo [WARNING] Please edit contracts\.env with your private key and RPC URLs before continuing.
    pause
)

REM Install dependencies
echo [INFO] Installing dependencies...
call npm install

REM Compile contracts
echo [INFO] Compiling contracts...
call npm run compile

REM Ask user which network to deploy to
echo.
echo [INFO] Select deployment network:
echo 1) Sepolia Testnet (Recommended for testing)
echo 2) Ethereum Mainnet (Production)
echo 3) BSC Mainnet (Multi-chain)
echo 4) Polygon Mainnet (Multi-chain)
echo.

set /p network_choice="Enter your choice (1-4): "

if "%network_choice%"=="1" (
    set NETWORK=sepolia
    echo [INFO] Deploying to Sepolia testnet...
) else if "%network_choice%"=="2" (
    set NETWORK=mainnet
    echo [WARNING] Deploying to Ethereum mainnet. This will cost real ETH!
    set /p confirm="Are you sure? (y/N): "
    if /i not "%confirm%"=="y" (
        echo [ERROR] Deployment cancelled.
        pause
        exit /b 1
    )
) else if "%network_choice%"=="3" (
    set NETWORK=bsc
    echo [INFO] Deploying to BSC mainnet...
) else if "%network_choice%"=="4" (
    set NETWORK=polygon
    echo [INFO] Deploying to Polygon mainnet...
) else (
    echo [ERROR] Invalid choice. Exiting.
    pause
    exit /b 1
)

REM Deploy contract
echo [INFO] Deploying BHX token contract to %NETWORK%...
call npm run deploy:%NETWORK%

if %errorlevel% eq 0 (
    echo [SUCCESS] Contract deployed successfully!
    
    REM Ask if user wants to verify contract
    set /p verify_choice="Do you want to verify the contract on block explorer? (y/N): "
    if /i "%verify_choice%"=="y" (
        echo [INFO] Please check the deployment output above for the contract address
        set /p contract_address="Enter the contract address: "
        echo [INFO] Verifying contract...
        call npm run verify:%NETWORK% %contract_address% "10000000000000000000000000"
    )
    
    REM Generate exchange submission data
    echo [INFO] Generating exchange submission data...
    
    echo 🚀 BHX Token Exchange Listing Application > ..\exchange_submission.txt
    echo. >> ..\exchange_submission.txt
    echo BASIC INFORMATION: >> ..\exchange_submission.txt
    echo - Token Name: BlackHole >> ..\exchange_submission.txt
    echo - Symbol: BHX >> ..\exchange_submission.txt
    echo - Network: %NETWORK% >> ..\exchange_submission.txt
    echo - Decimals: 18 >> ..\exchange_submission.txt
    echo - Total Supply: 1,000,000,000 BHX >> ..\exchange_submission.txt
    echo - Initial Circulating: 10,000,000 BHX >> ..\exchange_submission.txt
    echo. >> ..\exchange_submission.txt
    echo LINKS: >> ..\exchange_submission.txt
    echo - Website: https://blackhole-blockchain.com >> ..\exchange_submission.txt
    echo - Whitepaper: https://blackhole-blockchain.com/whitepaper.pdf >> ..\exchange_submission.txt
    echo - Twitter: https://twitter.com/BlackHoleChain >> ..\exchange_submission.txt
    echo - Telegram: https://t.me/BlackHoleChain >> ..\exchange_submission.txt
    echo - GitHub: https://github.com/BlackHoleChain/blackhole-blockchain >> ..\exchange_submission.txt
    echo. >> ..\exchange_submission.txt
    echo NEXT STEPS: >> ..\exchange_submission.txt
    echo 1. Add liquidity to Uniswap >> ..\exchange_submission.txt
    echo 2. Submit to CoinGecko >> ..\exchange_submission.txt
    echo 3. Submit to CoinMarketCap >> ..\exchange_submission.txt
    echo 4. Apply to exchanges >> ..\exchange_submission.txt
    
    echo [SUCCESS] Exchange submission data saved to exchange_submission.txt
    
    REM Next steps
    echo.
    echo [INFO] 🎉 Deployment Complete! Next Steps:
    echo.
    echo 1. 💧 Add Liquidity to Uniswap:
    echo    - Go to https://app.uniswap.org/#/add/v2
    echo    - Add BHX/ETH and BHX/USDC pairs
    echo    - Recommended: $5,000+ initial liquidity
    echo.
    echo 2. 📊 Submit to Data Aggregators:
    echo    - CoinGecko: https://www.coingecko.com/en/coins/new
    echo    - CoinMarketCap: https://support.coinmarketcap.com/hc/en-us/requests/new
    echo.
    echo 3. 🏛️ Apply to Exchanges:
    echo    - MEXC: https://www.mexc.com/support/articles/17002695435673
    echo    - Gate.io: https://www.gate.io/listing_application
    echo    - BitMart: https://support.bitmart.com/hc/en-us/articles/360040624234
    echo.
    echo 4. 📋 Use the data in exchange_submission.txt for applications
    echo.
    
) else (
    echo [ERROR] Contract deployment failed!
    pause
    exit /b 1
)

echo.
echo [SUCCESS] 🚀 BHX Token is ready for exchange listings!
echo 📋 Follow the steps in EXCHANGE_LISTING_GUIDE.md for detailed instructions.

pause