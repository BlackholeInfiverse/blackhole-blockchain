@echo off
title DEX Testing Suite - Validate Your DEX Before Deployment

echo 🧪 BlackHole DEX - Comprehensive Testing Suite
echo ===============================================
echo 🎯 Goal: Validate DEX functionality before spending money on deployment

echo.
echo [INFO] This will test your DEX locally with ZERO cost
echo [INFO] We'll verify all trading functions work correctly
echo.

REM Check if Go is installed
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Go is not installed. Please install Go first.
    echo Download from: https://golang.org/download/
    pause
    exit /b 1
)

echo [INFO] Starting DEX testing environment...
echo [INFO] This will take about 2-3 minutes

echo.
echo 🚀 Step 1: Starting local blockchain...
echo [INFO] Starting blockchain on port 8080...

REM Start blockchain in background (you may need to start this manually)
echo [INFO] Please start your blockchain manually in another terminal:
echo        cd core/relay-chain
echo        go run cmd/relay/main.go

echo.
echo 🧪 Step 2: Running DEX test suite...
echo [INFO] Testing all DEX functions...

REM Run the test suite
cd scripts
go run dex_testing_suite.go

if %errorlevel% EQU 0 (
    echo.
    echo [SUCCESS] 🎉 DEX testing completed!
    echo.
    echo 📊 Check the results above to see if your DEX is ready
    echo.
    echo 🎯 Next Steps Based on Results:
    echo.
    echo If SUCCESS RATE GTE 95:
    echo   ✅ Your DEX is ready for deployment!
    echo   ✅ You can confidently deploy to testnet/mainnet
    echo   ✅ Proceed with exchange listing strategy
    echo.
    echo If SUCCESS RATE 80-94:
    echo   ⚠️  Minor issues found - fix these first:
    echo   ⚠️  Review failed tests in the report
    echo   ⚠️  Re-run tests after fixes
    echo.
    echo If SUCCESS RATE LSS 80:
    echo   ❌ Major issues found - needs work before deployment:
    echo   ❌ Fix critical DEX functions first
    echo   ❌ Don't deploy until tests pass
    echo.
    echo 💡 RECOMMENDATION:
    echo   • Only deploy if success rate GTE 95
    echo   • Fix all critical issues locally first  
    echo   • Testing costs $0, fixing after deployment costs $$$
    echo.
) else (
    echo.
    echo [ERROR] ❌ DEX testing failed to complete
    echo [ERROR] This usually means:
    echo   1. Blockchain not running on port 8080
    echo   2. DEX API endpoints not responding
    echo   3. Code compilation issues
    echo.
    echo 🔧 TROUBLESHOOTING:
    echo   1. Make sure blockchain is running:
    echo      cd core/relay-chain
    echo      go run cmd/relay/main.go
    echo   2. Wait 30 seconds for startup
    echo   3. Check http://localhost:8080 is accessible
    echo   4. Re-run this test
    echo.
)

echo.
echo 📋 What This Test Validates:
echo   ✅ Trading pair creation
echo   ✅ Liquidity pool management  
echo   ✅ Swap execution and pricing
echo   ✅ Fee calculation (0.3 percent)
echo   ✅ Error handling
echo   ✅ Performance under load
echo   ✅ Cross-chain DEX integration
echo.

echo 💰 Why Test Locally First:
echo   • Costs $0 vs $50-150 to test on mainnet
echo   • Find issues before deployment
echo   • Validate functionality completely
echo   • Build confidence in your system
echo.

echo 🚀 Ready for Deployment When:
echo   • All tests pass (95+ percent success rate)
echo   • No critical errors found
echo   • Performance meets targets
echo   • You're confident DEX works perfectly
echo.

pause