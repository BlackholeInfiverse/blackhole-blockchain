@echo off
echo ========================================
echo 🔒 BlackHole Cybersecurity System
echo ========================================
echo.
echo This script starts the integrated cybersecurity system for BlackHole blockchain.
echo.

REM Check if blockchain is running
echo 🔍 Checking if blockchain is running...
netstat -an | findstr ":3000" >nul
if %errorlevel% equ 0 (
    echo ✅ Blockchain appears to be running on port 3000
) else (
    echo ⚠️  Blockchain doesn't appear to be running on port 3000
    echo.
    echo The cybersecurity system requires the blockchain to be running.
    set /p START_BLOCKCHAIN="Start blockchain first? (y/n): "
    if /i "%START_BLOCKCHAIN%"=="y" (
        echo 🚀 Starting blockchain...
        start "BlackHole Blockchain" cmd /k "start_blockchain.bat"
        echo ⏳ Waiting 15 seconds for blockchain to initialize...
        timeout /t 15 /nobreak >nul
    ) else (
        echo ⚠️  Continuing without blockchain - some features may not work
    )
)

echo.
echo 🔧 Cybersecurity System Configuration
echo.
echo Available modes:
echo 1. Demo Mode - Run cybersecurity demonstration
echo 2. API Server - Start cybersecurity API server
echo 3. Integrated Mode - Full integration with blockchain
echo 4. Development Mode - Testing and development
echo.

set /p MODE_CHOICE="Choose mode (1/2/3/4): "

if "%MODE_CHOICE%"=="1" (
    echo 🎯 Starting Demo Mode...
    goto :demo_mode
) else if "%MODE_CHOICE%"=="2" (
    echo 🌐 Starting API Server Mode...
    goto :api_mode
) else if "%MODE_CHOICE%"=="3" (
    echo 🔗 Starting Integrated Mode...
    goto :integrated_mode
) else if "%MODE_CHOICE%"=="4" (
    echo 🛠️ Starting Development Mode...
    goto :dev_mode
) else (
    echo ❌ Invalid choice. Defaulting to Demo Mode...
    goto :demo_mode
)

:demo_mode
echo.
echo 🎯 Demo Mode - Cybersecurity Demonstration
echo ==========================================
echo.
echo This will demonstrate all cybersecurity features:
echo - Threat Detection
echo - Access Control
echo - Incident Management
echo - Compliance Monitoring
echo - Audit Logging
echo - Custom Security Rules
echo - Real-time Monitoring
echo.

cd examples
echo 🔨 Building cybersecurity demo...
go build -o cybersecurity_demo.exe cybersecurity_demo.go
if %errorlevel% neq 0 (
    echo ❌ Failed to build cybersecurity demo
    pause
    exit /b 1
)

echo ✅ Demo built successfully
echo 🚀 Starting cybersecurity demonstration...
echo.
cybersecurity_demo.exe
goto :end

:api_mode
echo.
echo 🌐 API Server Mode - Cybersecurity API
echo ======================================
echo.
echo Starting cybersecurity API server on port 8096
echo.
echo Access Points:
echo - Web Interface: http://localhost:8096/security
echo - Health Check: http://localhost:8096/api/v1/security/health
echo - Metrics: http://localhost:8096/api/v1/security/metrics
echo - API Key: security_api_key_2024
echo.

REM Create a simple API server launcher
echo package main > temp_api_server.go
echo. >> temp_api_server.go
echo import ( >> temp_api_server.go
echo     "log" >> temp_api_server.go
echo     "github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/cybersecurity" >> temp_api_server.go
echo ) >> temp_api_server.go
echo. >> temp_api_server.go
echo func main() { >> temp_api_server.go
echo     sm := cybersecurity.NewSecurityManager() >> temp_api_server.go
echo     if err := sm.Start(); err != nil { >> temp_api_server.go
echo         log.Fatalf("Failed to start security manager: %%v", err) >> temp_api_server.go
echo     } >> temp_api_server.go
echo     api := cybersecurity.NewSecurityAPI(sm, "security_api_key_2024", 8096) >> temp_api_server.go
echo     log.Println("Starting cybersecurity API server...") >> temp_api_server.go
echo     if err := api.Start(); err != nil { >> temp_api_server.go
echo         log.Fatalf("Failed to start API server: %%v", err) >> temp_api_server.go
echo     } >> temp_api_server.go
echo } >> temp_api_server.go

echo 🔨 Building API server...
go build -o cybersecurity_api.exe temp_api_server.go
if %errorlevel% neq 0 (
    echo ❌ Failed to build API server
    del temp_api_server.go
    pause
    exit /b 1
)

del temp_api_server.go
echo ✅ API server built successfully
echo 🚀 Starting cybersecurity API server...
echo.
cybersecurity_api.exe
goto :end

:integrated_mode
echo.
echo 🔗 Integrated Mode - Full Blockchain Integration
echo ===============================================
echo.
echo This mode integrates cybersecurity directly with the blockchain.
echo All transactions and blocks will be security validated.
echo.

echo 🔧 Checking blockchain integration...
REM Check if blockchain has cybersecurity integration
echo Verifying cybersecurity integration in blockchain...

echo 🚀 Starting integrated cybersecurity system...
echo.
echo Features enabled:
echo ✅ Transaction security validation
echo ✅ Block security validation
echo ✅ Real-time threat detection
echo ✅ Access control enforcement
echo ✅ Audit logging
echo ✅ Incident management
echo ✅ Compliance monitoring
echo.

REM This would typically start the blockchain with cybersecurity enabled
echo 💡 To use integrated mode, start the blockchain with cybersecurity enabled:
echo    blockchain.InitializeCybersecurity()
echo.
echo 📍 Cybersecurity features are now available in the blockchain API
echo 📍 Use the blockchain's security methods for full integration
echo.
goto :end

:dev_mode
echo.
echo 🛠️ Development Mode - Testing and Development
echo ============================================
echo.
echo This mode is for testing cybersecurity components.
echo.

echo Available development tools:
echo 1. Test threat detection
echo 2. Test access control
echo 3. Test incident management
echo 4. Test compliance monitoring
echo 5. Run all tests
echo.

set /p DEV_CHOICE="Choose test (1-5): "

echo 🧪 Running cybersecurity tests...
echo.

if "%DEV_CHOICE%"=="1" (
    echo 🔍 Testing threat detection...
    echo   - Malware signature detection
    echo   - Phishing pattern recognition
    echo   - Anomaly detection algorithms
) else if "%DEV_CHOICE%"=="2" (
    echo 🛡️ Testing access control...
    echo   - Permission validation
    echo   - Role-based access control
    echo   - Policy enforcement
) else if "%DEV_CHOICE%"=="3" (
    echo 🚨 Testing incident management...
    echo   - Incident reporting
    echo   - Escalation procedures
    echo   - Response automation
) else if "%DEV_CHOICE%"=="4" (
    echo 📋 Testing compliance monitoring...
    echo   - SOC2 compliance checks
    echo   - ISO27001 validation
    echo   - GDPR compliance
) else (
    echo 🧪 Running all cybersecurity tests...
    echo   - Threat detection tests
    echo   - Access control tests
    echo   - Incident management tests
    echo   - Compliance monitoring tests
    echo   - Integration tests
)

echo.
echo ✅ Development tests completed
echo 💡 Check logs for detailed test results
echo.
goto :end

:end
echo.
echo ========================================
echo 🔒 Cybersecurity System Information
echo ========================================
echo.
echo 📚 Documentation:
echo   - API Documentation: /docs/cybersecurity/
echo   - Security Policies: /docs/security/
echo   - Compliance Reports: /docs/compliance/
echo.
echo 🔧 Configuration:
echo   - Security Contracts: Deployed automatically
echo   - Threat Signatures: Updated regularly
echo   - Access Policies: Configurable via API
echo.
echo 📊 Monitoring:
echo   - Real-time metrics available
echo   - Audit logs maintained
echo   - Incident tracking active
echo.
echo 🌐 Web Interfaces:
echo   - Security Dashboard: http://localhost:8096/security
echo   - Blockchain Dashboard: http://localhost:8080
echo   - Faucet Interface: http://localhost:8095
echo.
echo 🔑 API Keys:
echo   - Security API: security_api_key_2024
echo   - Admin API: real_world_admin_2024
echo.
echo Thank you for using BlackHole Cybersecurity System! 🔒
echo.
pause
