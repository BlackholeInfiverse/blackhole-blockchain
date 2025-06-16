@echo off
REM BlackHole Blockchain Deployment Script for Windows
REM This script deploys the complete BlackHole blockchain ecosystem using Docker

setlocal enabledelayedexpansion

echo 🚀 BlackHole Blockchain Deployment Script
echo ==========================================

REM Check if Docker is installed
echo [STEP] Checking Docker installation...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

echo [INFO] Docker and Docker Compose are installed

REM Create necessary directories
echo [STEP] Creating necessary directories...
if not exist "logs" mkdir logs
if not exist "data" mkdir data
if not exist "data\blockchain" mkdir data\blockchain
if not exist "data\wallet" mkdir data\wallet
if not exist "data\mongodb" mkdir data\mongodb
if not exist "config" mkdir config
echo [INFO] Directories created successfully

REM Generate configuration files
echo [STEP] Generating configuration files...
(
echo # BlackHole Blockchain Configuration
echo COMPOSE_PROJECT_NAME=blackhole-blockchain
echo.
echo # Database Configuration
echo MONGODB_ROOT_USERNAME=admin
echo MONGODB_ROOT_PASSWORD=blackhole123
echo MONGODB_DATABASE=blackhole_wallet
echo.
echo # Blockchain Configuration
echo BLOCKCHAIN_LOG_LEVEL=info
echo BLOCKCHAIN_BLOCK_TIME=6s
echo BLOCKCHAIN_MAX_BLOCK_SIZE=1048576
echo.
echo # Wallet Configuration
echo WALLET_LOG_LEVEL=info
echo WALLET_SESSION_TIMEOUT=3600
echo.
echo # Monitoring Configuration
echo PROMETHEUS_RETENTION=200h
echo GRAFANA_ADMIN_PASSWORD=blackhole123
echo.
echo # Network Configuration
echo NETWORK_SUBNET=172.20.0.0/16
) > .env
echo [INFO] Configuration files generated

REM Build Docker images
echo [STEP] Building Docker images...
echo [INFO] Building blockchain node image...
docker build -f Dockerfile.blockchain -t blackhole/blockchain:latest .
if errorlevel 1 (
    echo [ERROR] Failed to build blockchain image
    pause
    exit /b 1
)

echo [INFO] Building wallet service image...
docker build -f Dockerfile.wallet -t blackhole/wallet:latest .
if errorlevel 1 (
    echo [ERROR] Failed to build wallet image
    pause
    exit /b 1
)

echo [INFO] Docker images built successfully

REM Deploy services
echo [STEP] Deploying BlackHole blockchain services...
echo [INFO] Stopping existing services...
docker-compose down --remove-orphans 2>nul

echo [INFO] Starting services...
docker-compose up -d
if errorlevel 1 (
    echo [ERROR] Failed to start services
    pause
    exit /b 1
)

echo [INFO] Services deployment initiated

REM Wait for services to be healthy
echo [STEP] Waiting for services to be healthy...
echo [INFO] Waiting for services to start (this may take a few minutes)...

REM Wait 30 seconds for initial startup
timeout /t 30 /nobreak >nul

REM Check if services are running
docker-compose ps

echo [STEP] Deployment completed!
echo.
echo 🌐 Service URLs:
echo    Blockchain Node 1:  http://localhost:8080
echo    Blockchain Node 2:  http://localhost:8081
echo    Blockchain Node 3:  http://localhost:8082
echo    Wallet Service:     http://localhost:9000
echo    Load Balancer:      http://localhost:80
echo    Prometheus:         http://localhost:9090
echo    Grafana:           http://localhost:3000 (admin/blackhole123)
echo.
echo 📊 Monitoring:
echo    Blockchain API:     http://localhost/api/status
echo    Wallet API:         http://wallet.blackhole.local/api/status
echo    Metrics:           http://monitor.blackhole.local/metrics
echo.
echo 🔧 Management Commands:
echo    View logs:         docker-compose logs -f [service_name]
echo    Stop services:     docker-compose down
echo    Restart service:   docker-compose restart [service_name]
echo.
echo 📁 Data Locations:
echo    Blockchain data:   .\data\blockchain\
echo    Wallet data:       .\data\wallet\
echo    MongoDB data:      Docker volume 'mongodb_data'
echo    Logs:             .\logs\
echo.
echo [INFO] BlackHole Blockchain is now running!
echo.
echo Press any key to open the blockchain dashboard...
pause >nul

REM Open blockchain dashboard in default browser
start http://localhost:8080

echo.
echo Deployment completed successfully!
echo To stop the services, run: docker-compose down
pause
