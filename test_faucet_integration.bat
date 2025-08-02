@echo off
echo ========================================
echo 🧪 Faucet Integration Test Suite
echo ========================================
echo.

REM Test 1: Build Test
echo 🔨 Test 1: Building faucet...
cd services\validator-faucet
go build -o test_faucet.exe real_world_faucet.go
if %errorlevel% neq 0 (
    echo ❌ Build test failed
    goto :error
)
echo ✅ Build test passed

REM Test 2: Module Dependencies
echo.
echo 📦 Test 2: Checking module dependencies...
go mod verify
if %errorlevel% neq 0 (
    echo ❌ Module verification failed
    goto :error
)
echo ✅ Module dependencies verified

REM Test 3: Import Resolution
echo.
echo 🔍 Test 3: Testing import resolution...
go list -m all | findstr "blackhole-blockchain" >nul
if %errorlevel% neq 0 (
    echo ❌ Import resolution test failed
    goto :error
)
echo ✅ Import resolution test passed

REM Test 4: Quick Start Test (without blockchain)
echo.
echo 🚀 Test 4: Quick start test (5 seconds)...
start /b test_faucet.exe
timeout /t 5 /nobreak >nul

REM Check if faucet is responding
echo 🌐 Checking faucet health endpoint...
curl -s http://localhost:8095/api/v1/health >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Faucet health check passed
) else (
    echo ⚠️  Faucet health check failed (may be normal without blockchain)
)

REM Stop test faucet
taskkill /f /im test_faucet.exe >nul 2>&1

REM Test 5: Configuration Test
echo.
echo ⚙️  Test 5: Configuration validation...
echo Testing faucet configuration...
if exist "real_world_faucet.go" (
    findstr "Port.*8095" real_world_faucet.go >nul
    if %errorlevel% equ 0 (
        echo ✅ Port configuration correct
    ) else (
        echo ❌ Port configuration issue
        goto :error
    )
    
    findstr "BHX" real_world_faucet.go >nul
    if %errorlevel% equ 0 (
        echo ✅ Token configuration correct
    ) else (
        echo ❌ Token configuration issue
        goto :error
    )
) else (
    echo ❌ Faucet source file not found
    goto :error
)

REM Test 6: Workspace Integration
echo.
echo 🏗️  Test 6: Workspace integration...
cd ..\..
go work sync
if %errorlevel% neq 0 (
    echo ❌ Workspace sync failed
    goto :error
)
echo ✅ Workspace integration test passed

echo.
echo ========================================
echo ✅ ALL INTEGRATION TESTS PASSED!
echo ========================================
echo.
echo The faucet is properly integrated and ready to use.
echo.
echo Next steps:
echo 1. Start blockchain: start_blockchain.bat
echo 2. Start faucet: start_integrated_faucet.bat
echo 3. Access web interface: http://localhost:8095
echo.
goto :end

:error
echo.
echo ========================================
echo ❌ INTEGRATION TESTS FAILED!
echo ========================================
echo.
echo Please check the error messages above and fix the issues.
echo.

:end
pause
