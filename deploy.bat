@echo off
REM BlackHole Blockchain Deployment Script for Windows
REM This script deploys the complete BlackHole blockchain ecosystem using Docker

setlocal enabledelayedexpansion

echo 🚀 BlackHole Blockchain Deployment Script
echo ==========================================

REM Check if Docker Desktop is running properly
echo [STEP] Checking Docker installation and status...

REM First check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop first.
    echo [INFO] Download from: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Check if Docker daemon is accessible (Docker Desktop running)
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Desktop is not running or not accessible.
    echo [INFO] Please ensure:
    echo        1. Docker Desktop is installed and running
    echo        2. Check system tray for Docker Desktop icon
    echo        3. Wait for Docker Desktop to fully start (may take 2-3 minutes)
    echo        4. Try restarting Docker Desktop if needed
    echo.
    echo [INFO] Alternative: Use local deployment instead:
    echo        .\quick-start.bat
    echo.
    pause
    exit /b 1
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose is not available.
    echo [INFO] Please ensure Docker Desktop is fully started.
    pause
    exit /b 1
)

echo [INFO] Docker Desktop is running and ready

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

REM Check if enhanced modules are available (need to be in main branch)
echo [STEP] Checking project structure...
if not exist "core\relay-chain\governance" (
    echo [ERROR] Enhanced modules not found in current branch.
    echo [INFO] Please ensure your enhanced features are merged to main branch:
    echo        1. git checkout main
    echo        2. git merge your-feature-branch
    echo        3. git push origin main
    echo.
    echo [INFO] Alternative: Use local deployment which works with current code:
    echo        .\quick-start.bat
    echo.
    pause
    exit /b 1
)

REM Build Docker images with proper error handling
echo [STEP] Building Docker images...
echo [INFO] This may take several minutes for the first build...

REM Try building with the simple Dockerfile (most reliable)
echo [INFO] Building blockchain node image...
docker build -f Dockerfile.simple -t blackhole/blockchain:latest . 2>build.log
if errorlevel 1 (
    echo [ERROR] Docker build failed. Common causes:
    echo        1. Go module conflicts (enhanced modules not in GitHub main branch)
    echo        2. Docker Desktop not fully started
    echo        3. Network connectivity issues
    echo.
    echo [INFO] Check build.log for detailed error information
    echo [INFO] Recommended: Use local deployment instead:
    echo        .\quick-start.bat
    echo.
    pause
    exit /b 1
)

echo [INFO] Blockchain image built successfully
echo [INFO] Skipping wallet image build (using existing services)

REM Deploy services
echo [STEP] Deploying BlackHole blockchain services...
echo [INFO] Stopping existing services...
docker-compose down --remove-orphans 2>nul

echo [INFO] Starting services with docker-compose...
echo [INFO] This may take a few minutes for containers to start...
docker-compose up -d 2>deploy.log
if errorlevel 1 (
    echo [ERROR] Failed to start services. Common causes:
    echo        1. Port conflicts (8080, 3000, 80 already in use)
    echo        2. Docker image build issues
    echo        3. Docker Desktop resource limits
    echo.
    echo [INFO] Check deploy.log for detailed error information
    echo [INFO] Try stopping other services using these ports:
    echo        netstat -ano ^| findstr :8080
    echo        netstat -ano ^| findstr :3000
    echo.
    echo [INFO] Alternative: Use local deployment:
    echo        .\quick-start.bat
    echo.
    pause
    exit /b 1
)

echo [INFO] Services deployment initiated successfully

REM Wait for services to be healthy
echo [STEP] Waiting for services to be healthy...
echo [INFO] Waiting for services to start (this may take a few minutes)...

REM Wait 30 seconds for initial startup
timeout /t 30 /nobreak >nul

REM Check if services are running
docker-compose ps

REM Verify deployment
echo [STEP] Verifying deployment...
timeout /t 10 /nobreak >nul

REM Check container status
docker-compose ps > container_status.log 2>&1
findstr /C:"Up" container_status.log >nul
if errorlevel 1 (
    echo [WARNING] Some containers may not be running properly
    echo [INFO] Container status:
    type container_status.log
    echo.
    echo [INFO] Check logs with: docker-compose logs -f
    echo [INFO] If issues persist, try: .\quick-start.bat
) else (
    echo [INFO] Containers are running successfully
)

echo [STEP] Deployment completed!
echo.
echo 🌐 Service URLs:
echo    Blockchain Dashboard:   http://localhost:8080
echo    Load Balancer:          http://localhost:80
echo    API Status:             http://localhost:8080/api/status
echo.
echo 🔧 Enhanced Features Available:
echo    - Advanced Monitoring System
echo    - E2E Validation Framework
echo    - Governance Simulation
echo    - Load Testing Capabilities
echo    - P2P Networking
echo.
echo � Management Commands:
echo    View logs:              docker-compose logs -f
echo    Stop services:          docker-compose down
echo    Restart services:       docker-compose restart
echo    Check status:           docker-compose ps
echo.
echo 📁 Data Locations:
echo    Blockchain data:        .\data\blockchain\
echo    Logs:                   .\logs\
echo    Build logs:             build.log, deploy.log
echo.
echo [INFO] BlackHole Blockchain deployment completed!
echo.
echo Press any key to open the blockchain dashboard...
pause >nul

REM Open blockchain dashboard in default browser
start http://localhost:8080

echo.
echo Deployment completed successfully!
echo To stop the services, run: docker-compose down
pause
