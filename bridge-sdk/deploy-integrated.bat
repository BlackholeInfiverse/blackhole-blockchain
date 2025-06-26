@echo off
setlocal enabledelayedexpansion

REM BlackHole Bridge-SDK Integrated Deployment Script (Windows)
REM =============================================================

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                    🌉 BlackHole Bridge-SDK Integration                       ║
echo ║                          Production Deployment                              ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

REM Configuration
set SCRIPT_DIR=%~dp0
set COMPOSE_FILE=%SCRIPT_DIR%docker-compose.yml
set ENV_FILE=%SCRIPT_DIR%.env

REM Check prerequisites
echo [STEP] Checking prerequisites...

REM Check Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

REM Check Docker Compose
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

REM Check if Docker daemon is running
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker daemon is not running. Please start Docker Desktop first.
    pause
    exit /b 1
)

echo [SUCCESS] Prerequisites check passed

REM Setup environment
echo [STEP] Setting up environment...

REM Create .env file if it doesn't exist
if not exist "%ENV_FILE%" (
    echo [INFO] Creating .env file from template...
    copy "%SCRIPT_DIR%.env.example" "%ENV_FILE%" >nul
    echo [WARNING] Please edit .env file with your configuration before running again
    echo [INFO] Configuration file created at: %ENV_FILE%
    pause
    exit /b 0
)

echo [SUCCESS] Environment setup complete

REM Build and deploy
echo [STEP] Building and deploying integrated system...

REM Stop any existing containers
echo [INFO] Stopping existing containers...
docker-compose -f "%COMPOSE_FILE%" down --remove-orphans 2>nul

REM Build images
echo [INFO] Building Docker images...
docker-compose -f "%COMPOSE_FILE%" build --no-cache
if errorlevel 1 (
    echo [ERROR] Failed to build Docker images
    pause
    exit /b 1
)

REM Start services in correct order
echo [INFO] Starting BlackHole blockchain...
docker-compose -f "%COMPOSE_FILE%" up -d blackhole-blockchain
if errorlevel 1 (
    echo [ERROR] Failed to start BlackHole blockchain
    pause
    exit /b 1
)

REM Wait for blockchain to be ready
echo [INFO] Waiting for blockchain to initialize...
timeout /t 30 /nobreak >nul

REM Check blockchain health
set /a attempts=0
:check_blockchain
set /a attempts+=1
if !attempts! gtr 12 (
    echo [ERROR] BlackHole blockchain failed to start
    pause
    exit /b 1
)

curl -f http://localhost:8080/health >nul 2>&1
if errorlevel 1 (
    echo [INFO] Waiting for blockchain... (!attempts!/12)
    timeout /t 10 /nobreak >nul
    goto check_blockchain
)

echo [SUCCESS] BlackHole blockchain is ready

REM Start remaining services
echo [INFO] Starting bridge and supporting services...
docker-compose -f "%COMPOSE_FILE%" up -d
if errorlevel 1 (
    echo [ERROR] Failed to start services
    pause
    exit /b 1
)

echo [SUCCESS] System deployment complete

REM Verify deployment
echo [STEP] Verifying deployment...

REM Wait for services to start
timeout /t 10 /nobreak >nul

REM Check bridge health endpoint
curl -f http://localhost:8084/health >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Bridge health check failed - service may still be starting
) else (
    echo [SUCCESS] Bridge health check passed
)

echo [SUCCESS] Deployment verification complete

REM Display access information
echo.
echo [STEP] Deployment complete! Access information:
echo.
echo 🌉 BlackHole Bridge Dashboard:
echo    http://localhost:8084
echo.
echo 🧠 BlackHole Blockchain API:
echo    http://localhost:8080
echo.
echo 📊 Monitoring:
echo    Grafana: http://localhost:3000 (admin/admin123)
echo    Prometheus: http://localhost:9091
echo.
echo 💾 Database:
echo    PostgreSQL: localhost:5432 (bridge/bridge123)
echo    Redis: localhost:6379
echo.
echo 🔧 Management Commands:
echo    View logs: docker-compose -f "%COMPOSE_FILE%" logs -f
echo    Stop system: docker-compose -f "%COMPOSE_FILE%" down
echo    Restart: docker-compose -f "%COMPOSE_FILE%" restart
echo.
echo 📝 Configuration:
echo    Environment: %ENV_FILE%
echo    Blockchain Mode: Real Blockchain Integration
echo.
echo [SUCCESS] 🚀 BlackHole Bridge-SDK Integration deployed successfully!
echo.
echo Press any key to open the dashboard...
pause >nul

REM Open dashboard in default browser
start http://localhost:8084

echo.
echo Dashboard opened in your default browser.
echo Press any key to exit...
pause >nul
