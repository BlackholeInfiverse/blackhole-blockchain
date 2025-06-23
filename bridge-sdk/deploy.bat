@echo off
setlocal enabledelayedexpansion

REM BlackHole Bridge - One-Command Deployment Script (Windows)
REM ===========================================================
REM This script demonstrates the complete deployment process
REM Usage: deploy.bat [mode]
REM Modes: dev, prod, simulation

set MODE=%1
if "%MODE%"=="" set MODE=dev

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    BlackHole Bridge                         ║
echo ║                 One-Command Deployment                      ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

echo 🔧 Checking prerequisites...

REM Check Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not installed. Please install Docker first.
    exit /b 1
)

REM Check Docker Compose
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose first.
    exit /b 1
)

echo ✅ Prerequisites check completed

echo 🔧 Setting up environment...

REM Create necessary directories
if not exist "data" mkdir data
if not exist "logs" mkdir logs
if not exist "monitoring\grafana\dashboards" mkdir monitoring\grafana\dashboards
if not exist "monitoring\grafana\datasources" mkdir monitoring\grafana\datasources

REM Copy .env file if it doesn't exist
if not exist ".env" (
    if exist ".env.example" (
        copy ".env.example" ".env" >nul
        echo ℹ️  Created .env file from template
    ) else (
        echo ⚠️  No .env file found. Using default configuration.
    )
)

REM Set mode-specific environment variables
if "%MODE%"=="dev" (
    set APP_ENV=development
    set DEBUG_MODE=true
    set RUN_SIMULATION=true
    set ENABLE_COLORED_LOGS=true
) else if "%MODE%"=="prod" (
    set APP_ENV=production
    set DEBUG_MODE=false
    set RUN_SIMULATION=false
    set ENABLE_COLORED_LOGS=false
) else if "%MODE%"=="simulation" (
    set APP_ENV=development
    set DEBUG_MODE=true
    set RUN_SIMULATION=true
    set ENABLE_COLORED_LOGS=true
) else (
    echo ❌ Unknown mode: %MODE%
    echo ℹ️  Available modes: dev, prod, simulation
    exit /b 1
)

echo ✅ Environment setup completed

echo 🔧 Deploying BlackHole Bridge in %MODE% mode...

if "%MODE%"=="dev" (
    echo 🔧 Starting development environment...
    docker-compose -f docker-compose.dev.yml up --build -d
) else if "%MODE%"=="prod" (
    echo 🔧 Starting production environment...
    docker-compose -f docker-compose.prod.yml up --build -d
) else if "%MODE%"=="simulation" (
    echo 🔧 Starting simulation environment...
    docker-compose up --build -d
)

echo 🔧 Waiting for services to be ready...

REM Wait for bridge node to be ready
set /a counter=0
:wait_loop
if %counter% geq 30 goto wait_timeout
curl -s http://localhost:8084/health >nul 2>&1
if errorlevel 1 (
    echo|set /p="."
    timeout /t 2 /nobreak >nul
    set /a counter+=1
    goto wait_loop
)
echo.

echo ✅ Services are ready

if "%MODE%"=="simulation" (
    echo 🔧 Running end-to-end simulation...
    timeout /t 10 /nobreak >nul
    if exist "simulation_proof.json" (
        echo ✅ Simulation completed. Results saved to simulation_proof.json
    ) else (
        echo ⚠️  Simulation results not found
    )
)

echo ✅ %MODE% environment started

echo.
echo ℹ️  🌐 BlackHole Bridge is now running!
echo.
echo 📊 Dashboard:     http://localhost:8084
echo 🏥 Health Check:  http://localhost:8084/health
echo 📈 Statistics:    http://localhost:8084/stats
echo 💸 Transactions:  http://localhost:8084/transactions
echo 📜 Logs:          http://localhost:8084/logs
echo 📚 Documentation: http://localhost:8084/docs
echo 🧪 Simulation:    http://localhost:8084/simulation
echo.
echo 📊 Monitoring:    http://localhost:3000 (Grafana - admin/admin123)
echo 🔍 Metrics:       http://localhost:9091 (Prometheus)
echo.
echo 🛑 To stop: docker-compose down
echo.

goto end

:wait_timeout
echo.
echo ⚠️  Timeout waiting for services to be ready
echo ℹ️  Services may still be starting. Check http://localhost:8084/health

:end
echo 🎉 Deployment completed successfully!
pause
