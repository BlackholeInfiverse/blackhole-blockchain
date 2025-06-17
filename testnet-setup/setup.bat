@echo off
REM BlackHole Bridge Testnet Setup Script for Windows
REM This script sets up the complete end-to-end testnet demonstration

echo 🚀 BlackHole Bridge Testnet Setup
echo ==================================

REM Check prerequisites
echo 🔍 Checking prerequisites...

REM Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed. Please install Node.js 18+ from https://nodejs.org/
    pause
    exit /b 1
) else (
    echo ✅ Node.js is installed
)

REM Check npm
npm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ npm is not installed. Please install npm.
    pause
    exit /b 1
) else (
    echo ✅ npm is installed
)

REM Check Go
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Go is not installed. Please install Go 1.21+ from https://golang.org/
    pause
    exit /b 1
) else (
    echo ✅ Go is installed
)

REM Check Git
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Git is not installed. Please install Git.
    pause
    exit /b 1
) else (
    echo ✅ Git is installed
)

REM Create necessary directories
echo.
echo 📁 Creating project directories...
if not exist "logs" mkdir logs
if not exist "config" mkdir config
if not exist "screenshots" mkdir screenshots
echo ✅ Created directories: logs, config, screenshots

REM Setup Ethereum contracts
echo.
echo 🔧 Setting up Ethereum contracts...
cd ethereum-contracts

if not exist "package.json" (
    echo ❌ Ethereum contracts package.json not found!
    pause
    exit /b 1
)

echo ℹ️  Installing Ethereum dependencies...
call npm install

if not exist ".env" (
    echo ⚠️  Creating .env file from template...
    copy .env.example .env
    echo ⚠️  Please edit .env file with your private key and RPC URLs
)

cd ..

REM Setup Solana contracts
echo.
echo 🔧 Setting up Solana contracts...
cd solana-contracts

if not exist "package.json" (
    echo ❌ Solana contracts package.json not found!
    pause
    exit /b 1
)

echo ℹ️  Installing Solana dependencies...
call npm install

cd ..

REM Setup monitoring scripts
echo.
echo 🔧 Setting up monitoring scripts...
cd scripts

echo ℹ️  Installing monitoring dependencies...
call npm init -y >nul 2>&1
call npm install ethers @solana/web3.js @solana/spl-token dotenv bs58

cd ..

REM Check bridge SDK
echo.
echo 🔧 Checking bridge SDK...
cd ..\bridge-sdk

if not exist "go.mod" (
    echo ❌ Bridge SDK go.mod not found!
    pause
    exit /b 1
)

echo ℹ️  Installing Go dependencies...
go mod tidy

cd example
if not exist "main.go" (
    echo ❌ Bridge example main.go not found!
    pause
    exit /b 1
)

echo ✅ Bridge SDK is ready

cd ..\..\testnet-setup

REM Create demo configuration
echo.
echo 📋 Creating demo configuration...

echo {> config\demo-config.json
echo   "demo": {>> config\demo-config.json
echo     "name": "BlackHole Bridge End-to-End Testnet Demo",>> config\demo-config.json
echo     "version": "1.0.0",>> config\demo-config.json
echo     "networks": {>> config\demo-config.json
echo       "ethereum": {>> config\demo-config.json
echo         "name": "Sepolia Testnet",>> config\demo-config.json
echo         "chainId": 11155111,>> config\demo-config.json
echo         "rpcUrl": "https://ethereum-sepolia-rpc.publicnode.com",>> config\demo-config.json
echo         "explorerUrl": "https://sepolia.etherscan.io",>> config\demo-config.json
echo         "faucetUrl": "https://sepoliafaucet.com/">> config\demo-config.json
echo       },>> config\demo-config.json
echo       "solana": {>> config\demo-config.json
echo         "name": "Devnet",>> config\demo-config.json
echo         "cluster": "devnet",>> config\demo-config.json
echo         "rpcUrl": "https://api.devnet.solana.com",>> config\demo-config.json
echo         "explorerUrl": "https://explorer.solana.com",>> config\demo-config.json
echo         "faucetCommand": "solana airdrop 2">> config\demo-config.json
echo       }>> config\demo-config.json
echo     },>> config\demo-config.json
echo     "bridge": {>> config\demo-config.json
echo       "dashboardUrl": "http://localhost:8084",>> config\demo-config.json
echo       "apiUrl": "http://localhost:8084/api">> config\demo-config.json
echo     }>> config\demo-config.json
echo   }>> config\demo-config.json
echo }>> config\demo-config.json

echo ✅ Demo configuration created

REM Create quick start script
echo.
echo 📝 Creating quick start script...

echo @echo off> quick-start.bat
echo.>> quick-start.bat
echo echo 🚀 BlackHole Bridge Quick Start>> quick-start.bat
echo echo ===============================>> quick-start.bat
echo.>> quick-start.bat
echo echo 1. 📋 Prerequisites Check:>> quick-start.bat
echo echo    - Ethereum Sepolia ETH in wallet (get from https://sepoliafaucet.com/)>> quick-start.bat
echo echo    - Private key in ethereum-contracts\.env file>> quick-start.bat
echo echo    - Solana CLI installed (optional)>> quick-start.bat
echo.>> quick-start.bat
echo echo.>> quick-start.bat
echo echo 2. 🚀 Deploy Contracts (if not already deployed):>> quick-start.bat
echo echo    cd ethereum-contracts ^&^& npm run deploy:sepolia>> quick-start.bat
echo echo    cd ..\solana-contracts ^&^& npm run deploy:devnet>> quick-start.bat
echo.>> quick-start.bat
echo echo.>> quick-start.bat
echo echo 3. 🌉 Start Bridge System:>> quick-start.bat
echo echo    cd ..\bridge-sdk\example ^&^& go run main.go>> quick-start.bat
echo.>> quick-start.bat
echo echo.>> quick-start.bat
echo echo 4. 👁️  Start Monitoring (in new terminal):>> quick-start.bat
echo echo    cd testnet-setup\scripts ^&^& node monitor-bridge.js>> quick-start.bat
echo.>> quick-start.bat
echo echo.>> quick-start.bat
echo echo 5. 💸 Send Test Transactions (in new terminal):>> quick-start.bat
echo echo    cd testnet-setup\scripts>> quick-start.bat
echo echo    node send-eth-transaction.js>> quick-start.bat
echo echo    node send-sol-transaction.js>> quick-start.bat
echo.>> quick-start.bat
echo echo.>> quick-start.bat
echo echo 6. 📊 View Results:>> quick-start.bat
echo echo    - Bridge Dashboard: http://localhost:8084>> quick-start.bat
echo echo    - Logs: .\logs\>> quick-start.bat
echo echo    - Config: .\config\>> quick-start.bat
echo.>> quick-start.bat
echo pause>> quick-start.bat

echo ✅ Quick start script created

REM Create package.json for scripts
echo.
echo 📦 Creating package.json for scripts...

cd scripts
echo {> package.json
echo   "name": "blackhole-bridge-scripts",>> package.json
echo   "version": "1.0.0",>> package.json
echo   "description": "Scripts for BlackHole Bridge testnet demonstration",>> package.json
echo   "main": "monitor-bridge.js",>> package.json
echo   "scripts": {>> package.json
echo     "monitor": "node monitor-bridge.js",>> package.json
echo     "send-eth": "node send-eth-transaction.js",>> package.json
echo     "send-sol": "node send-sol-transaction.js",>> package.json
echo     "demo": "node ../demo.js">> package.json
echo   },>> package.json
echo   "dependencies": {>> package.json
echo     "ethers": "^6.8.0",>> package.json
echo     "@solana/web3.js": "^1.87.0",>> package.json
echo     "@solana/spl-token": "^0.3.9",>> package.json
echo     "dotenv": "^16.3.1",>> package.json
echo     "bs58": "^5.0.0">> package.json
echo   }>> package.json
echo }>> package.json

call npm install
cd ..

echo ✅ Scripts package.json created and dependencies installed

REM Final setup summary
echo.
echo 🎉 Setup Complete!
echo ==================
echo ✅ All components are ready for the end-to-end demo

echo.
echo 📋 Next Steps:
echo 1. Edit ethereum-contracts\.env with your private key
echo 2. Get Sepolia ETH from https://sepoliafaucet.com/
echo 3. Run: quick-start.bat to see the demo steps
echo 4. Or run: node demo.js for automated demo

echo.
echo 📁 Project Structure:
echo ├── ethereum-contracts\     # ERC-20 token deployment
echo ├── solana-contracts\       # SPL token deployment
echo ├── scripts\               # Transaction and monitoring scripts
echo ├── config\                # Network and deployment configs
echo ├── logs\                  # Demo logs and events
echo └── screenshots\           # For demo recording

echo.
echo 🔗 Important URLs:
echo - Sepolia Faucet: https://sepoliafaucet.com/
echo - Sepolia Explorer: https://sepolia.etherscan.io/
echo - Solana Explorer: https://explorer.solana.com/?cluster=devnet
echo - Bridge Dashboard: http://localhost:8084 (when running)

echo.
echo ℹ️  Ready for end-to-end testnet demonstration! 🚀

pause
