@echo off
title Quick DEX Connection Test

echo 🧪 Quick DEX Connection Test
echo ============================
echo Testing if your blockchain and DEX are accessible...

echo.
echo [INFO] Testing connection to localhost:8080...

REM Test if port 8080 is responding
curl -s --connect-timeout 5 http://localhost:8080/api/health > nul 2>&1

if %errorlevel% EQU 0 (
    echo ✅ SUCCESS: Blockchain is running on port 8080!
    echo.
    echo [INFO] Testing DEX API endpoint...
    
    REM Test DEX endpoint
    curl -s --connect-timeout 5 http://localhost:8080/api/dev/test-dex > nul 2>&1
    
    if %errorlevel% EQU 0 (
        echo ✅ SUCCESS: DEX API is accessible!
        echo.
        echo 🎯 Your DEX is ready for testing!
        echo Now you can run: .\test-dex.bat
    ) else (
        echo ⚠️ WARNING: DEX API not responding
        echo The blockchain is running but DEX might not be enabled
    )
) else (
    echo ❌ ERROR: Cannot connect to blockchain on port 8080
    echo.
    echo 🔧 SOLUTIONS:
    echo 1. Make sure you started the blockchain: .\start_blockchain.bat
    echo 2. Wait 30-60 seconds for full startup
    echo 3. Check that no other service is using port 8080
    echo 4. Try opening http://localhost:8080 in your browser
)

echo.
pause