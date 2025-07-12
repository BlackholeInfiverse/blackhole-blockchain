@echo off
setlocal enabledelayedexpansion

REM BlackHole Bridge - Ultimate One-Liner Deployment Script (Windows)
REM ===================================================================
REM 
REM This script provides a complete one-command deployment solution
REM Usage: deploy-one-liner.bat [environment]
REM 
REM Environments:
REM   dev        - Development with testnets
REM   staging    - Staging environment  
REM   prod       - Production deployment
REM   local      - Local development (default)

echo.
echo 🚀 BlackHole Bridge - One-Liner Deployment
echo ================================================
echo.

REM Environment setup
set ENVIRONMENT=%1
if "%ENVIRONMENT%"=="" set ENVIRONMENT=local
set PROJECT_NAME=blackhole-bridge
set COMPOSE_FILE=docker-compose.yml

echo Environment: %ENVIRONMENT%
echo Project: %PROJECT_NAME%
echo.

REM Check prerequisites
echo 🔍 Checking prerequisites...

docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

echo ✅ Docker and Docker Compose are installed
echo.

REM Environment-specific configuration
if "%ENVIRONMENT%"=="dev" (
    set ENV_FILE=.env.dev
    set COMPOSE_FILE=docker-compose.dev.yml
    echo ✅ Using development configuration with testnets
) else if "%ENVIRONMENT%"=="staging" (
    set ENV_FILE=.env.staging
    set COMPOSE_FILE=docker-compose.yml
    echo ✅ Using staging configuration
) else if "%ENVIRONMENT%"=="prod" (
    set ENV_FILE=.env.prod
    set COMPOSE_FILE=docker-compose.prod.yml
    echo ✅ Using production configuration
) else (
    set ENV_FILE=.env
    set COMPOSE_FILE=docker-compose.yml
    echo ✅ Using local development configuration
)

REM Create .env file if it doesn't exist
if not exist "%ENV_FILE%" (
    echo ⚠️  Environment file %ENV_FILE% not found. Creating from template...
    copy .env.example "%ENV_FILE%" >nul
    
    if "%ENVIRONMENT%"=="dev" (
        REM Configure for development/testnet
        powershell -Command "(gc '%ENV_FILE%') -replace 'USE_TESTNET=false', 'USE_TESTNET=true' | Out-File -encoding ASCII '%ENV_FILE%'"
        powershell -Command "(gc '%ENV_FILE%') -replace 'APP_ENV=production', 'APP_ENV=development' | Out-File -encoding ASCII '%ENV_FILE%'"
        powershell -Command "(gc '%ENV_FILE%') -replace 'DEBUG_MODE=false', 'DEBUG_MODE=true' | Out-File -encoding ASCII '%ENV_FILE%'"
        powershell -Command "(gc '%ENV_FILE%') -replace 'LOG_LEVEL=info', 'LOG_LEVEL=debug' | Out-File -encoding ASCII '%ENV_FILE%'"
    )
    
    echo ⚠️  Please edit %ENV_FILE% with your actual configuration values:
    echo   - Blockchain RPC endpoints
    echo   - Private keys
    echo   - Contract addresses
    echo   - API keys and secrets
    echo.
    pause
)

echo ✅ Environment configuration ready
echo.

REM Create required directories
echo 📁 Creating required directories...
if not exist "data" mkdir data
if not exist "logs" mkdir logs
if not exist "media" mkdir media
if not exist "monitoring\grafana\dashboards" mkdir monitoring\grafana\dashboards
if not exist "monitoring\grafana\datasources" mkdir monitoring\grafana\datasources
if not exist "nginx\ssl" mkdir nginx\ssl
if not exist "scripts" mkdir scripts
echo ✅ Directories created
echo.

REM Stop any existing containers
echo 🛑 Stopping existing containers...
docker-compose -f "%COMPOSE_FILE%" down --remove-orphans 2>nul
echo ✅ Existing containers stopped
echo.

REM Pull latest images
echo 📥 Pulling latest Docker images...
docker-compose -f "%COMPOSE_FILE%" pull
echo ✅ Docker images updated
echo.

REM Build the bridge application
echo 🔨 Building BlackHole Bridge...
docker-compose -f "%COMPOSE_FILE%" build --no-cache bridge-node
echo ✅ Bridge application built
echo.

REM Start all services
echo 🚀 Starting all services...
docker-compose -f "%COMPOSE_FILE%" up -d
echo ✅ All services started
echo.

REM Wait for services to be healthy
echo ⏳ Waiting for services to be ready...
timeout /t 10 /nobreak >nul

REM Check service health
echo 🏥 Checking service health...
set /a counter=0
:healthcheck
set /a counter+=1
curl -s http://localhost:8084/health >nul 2>&1
if errorlevel 1 (
    if !counter! geq 30 (
        echo ❌ Bridge service failed to start properly
        docker-compose -f "%COMPOSE_FILE%" logs bridge-node
        pause
        exit /b 1
    )
    timeout /t 2 /nobreak >nul
    goto healthcheck
)

echo ✅ Bridge service is healthy
echo.

REM Display service URLs
echo.
echo 🌟 BlackHole Bridge Deployment Complete!
echo ================================================
echo 📊 Dashboard:     http://localhost:8084
echo 🏥 Health Check:  http://localhost:8084/health
echo 📈 Grafana:       http://localhost:3000 (admin/admin123)
echo 📊 Prometheus:    http://localhost:9091
echo 🗄️  Redis:         localhost:6379
echo 🐘 PostgreSQL:    localhost:5432
echo.
echo 🔧 Management Commands:
echo   View logs:      docker-compose -f %COMPOSE_FILE% logs -f
echo   Stop services:  docker-compose -f %COMPOSE_FILE% down
echo   Restart:        docker-compose -f %COMPOSE_FILE% restart
echo   Update:         deploy-one-liner.bat %ENVIRONMENT%
echo.
echo ✨ Bridge is ready for cross-chain transactions!
echo.

REM Optional: Open browser
set /p OPEN_BROWSER="Open dashboard in browser? (y/n): "
if /i "%OPEN_BROWSER%"=="y" (
    start http://localhost:8084
)

pause
