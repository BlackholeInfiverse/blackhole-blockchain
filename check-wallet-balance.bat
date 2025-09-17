@echo off
title Check Wallet Balance - BHX Deployment

echo 🔍 Checking Wallet Balance for BHX Deployment
echo =============================================
echo.
echo 📍 Wallet Address: 0xe5C146a2FCD0844818604a74Cc75F2a4aE25579c
echo.

REM Check if curl is available
curl --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] curl not found. Using browser method instead.
    echo.
    echo 🌐 Opening Etherscan in your browser...
    start https://etherscan.io/address/0xe5C146a2FCD0844818604a74Cc75F2a4aE25579c
    echo.
    echo Check your balance on the opened webpage.
    goto end
)

echo 🔄 Checking ETH balance via API...
echo.

REM Using Etherscan API to check balance
curl -s "https://api.etherscan.io/api?module=account&action=balance&address=0xe5C146a2FCD0844818604a74Cc75F2a4aE25579c&tag=latest&apikey=YourApiKeyToken" > temp_balance.txt

REM Check if API call was successful
if %errorlevel% neq 0 (
    echo [ERROR] API call failed. Using browser method.
    echo.
    echo 🌐 Opening Etherscan in your browser...
    start https://etherscan.io/address/0xe5C146a2FCD0844818604a74Cc75F2a4aE25579c
    goto cleanup
)

echo ✅ Balance check complete!
echo.
echo 📊 Results:
type temp_balance.txt
echo.
echo.
echo 💡 For detailed view, check: https://etherscan.io/address/0xe5C146a2FCD0844818604a74Cc75F2a4aE25579c

:cleanup
if exist temp_balance.txt del temp_balance.txt

:end
echo.
echo 📋 What the balance means:
echo • 0 ETH = Not funded yet, ask boss to send crypto
echo • 0.001+ ETH = Ready for testnet deployment (FREE)
echo • 0.01+ ETH = Ready for mainnet deployment
echo • Any USDC/USDT = Need to convert to ETH first
echo.
echo 🚀 Next steps based on balance:
echo • If funded: run .\deploy-bhx-budget.bat
echo • If not funded: wait for boss to send crypto
echo • If USDC/USDT: convert to ETH first
echo.
pause