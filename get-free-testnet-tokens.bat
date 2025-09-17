@echo off
title Get FREE Testnet Tokens - Multiple Sources

echo 🆓 FREE Testnet Token Collection Guide
echo ======================================
echo For interns with zero budget - multiple free sources!

echo.
echo 📋 STEP-BY-STEP FREE TESTNET STRATEGY:
echo.

echo 1️⃣ TRY POLYGON MUMBAI FIRST (EASIEST):
echo    • URL: https://faucet.polygon.technology/
echo    • Requirement: Just wallet address
echo    • Amount: 0.2 testnet MATIC
echo    • Success Rate: 95%%
echo.

echo 2️⃣ TRY BSC TESTNET (VERY EASY):
echo    • URL: https://testnet.binance.org/faucet-smart
echo    • Requirement: Just wallet address  
echo    • Amount: 0.1 testnet BNB
echo    • Success Rate: 90%%
echo.

echo 3️⃣ TRY ALTERNATIVE ETH FAUCETS:
echo    • QuickNode: https://faucet.quicknode.com/ethereum/sepolia
echo    • Infura: https://www.infura.io/faucet/sepolia
echo    • Chainlink: https://faucets.chain.link/sepolia
echo    • Requirement: Social media account or email
echo.

echo 4️⃣ COMMUNITY SOURCES (ASK FOR HELP):
echo    • Reddit r/ethdev daily thread
echo    • Ethereum Discord #faucet channel
echo    • University blockchain groups
echo    • Developer communities
echo.

echo 💡 PRO TIP FOR INTERNS:
echo Post: "Hi! I'm an intern testing my DEX on testnet. 
echo Need 0.01 testnet ETH to deploy. Happy to test 
echo others' projects in return!"
echo.

echo 🎯 RECOMMENDED STRATEGY:
echo 1. Start with Polygon Mumbai (easiest)
echo 2. Deploy your BHX token there first
echo 3. Test all DEX functionality
echo 4. Get Ethereum testnet ETH later if needed
echo.

echo 🚀 AFTER GETTING TOKENS:
echo 1. Run: .\deploy-bhx-budget.bat
echo 2. Choose the network you got tokens for
echo 3. Deploy and test everything
echo 4. Build confidence before mainnet
echo.

pause

echo.
echo 🌐 Opening faucet websites for you...
echo.

REM Open the easiest faucets
start https://faucet.polygon.technology/
timeout /t 2 >nul
start https://testnet.binance.org/faucet-smart
timeout /t 2 >nul  
start https://faucet.quicknode.com/ethereum/sepolia

echo ✅ Faucet websites opened!
echo 📋 Try them in order - start with Polygon (easiest)
echo 💡 Remember: You only need ONE to work!

pause