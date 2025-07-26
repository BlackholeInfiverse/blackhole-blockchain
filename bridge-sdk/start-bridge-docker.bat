@echo off
setlocal enabledelayedexpansion

REM BlackHole Bridge Windows Docker Startup Script
REM ==============================================

set SCRIPT_DIR=%~dp0
set ENV_FILE=%SCRIPT_DIR%.env
set COMPOSE_FILE=%SCRIPT_DIR%docker-compose.yml

:banner
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    BlackHole Bridge                         ║
echo ║                 Windows Docker Deployment                   ║
echo ║                                                              ║
echo ║  🌉 Cross-Chain Bridge Infrastructure                       ║
echo ║  🚀 One-Command Docker Deployment                           ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

if "%1"=="" goto start
if "%1"=="start" goto start
if "%1"=="stop" goto stop
if "%1"=="restart" goto restart
if "%1"=="status" goto status
if "%1"=="logs" goto logs
if "%1"=="health" goto health
if "%1"=="setup" goto setup
if "%1"=="clean" goto clean
if "%1"=="help" goto help
goto help

:help
echo Usage: %0 [COMMAND]
echo.
echo Commands:
echo   start         Start the bridge in production mode
echo   stop          Stop all services
echo   restart       Restart all services
echo   status        Show status of all services
echo   logs          Show logs from all services
echo   health        Check health of all services
echo   setup         Initial setup and configuration
echo   clean         Clean up containers and volumes
echo   help          Show this help message
echo.
goto end

:check_docker
echo [INFO] Checking Docker installation...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed or not in PATH
    echo Please install Docker Desktop for Windows from:
    echo https://docs.docker.com/desktop/install/windows-install/
    goto end
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose is not installed or not in PATH
    echo Please install Docker Compose
    goto end
)
echo [SUCCESS] Docker and Docker Compose are available
goto :eof

:check_env
if not exist "%ENV_FILE%" (
    echo [WARNING] .env file not found. Creating default configuration...
    call :create_env
    echo [INFO] Please edit .env file with your blockchain RPC URLs and private keys
    echo [INFO] Default .env file created with placeholder values
)
goto :eof

:create_env
echo # BlackHole Bridge Configuration > "%ENV_FILE%"
echo APP_ENV=production >> "%ENV_FILE%"
echo SERVER_PORT=8084 >> "%ENV_FILE%"
echo ETHEREUM_RPC_URL=https://eth-mainnet.alchemyapi.io/v2/YOUR_ALCHEMY_KEY >> "%ENV_FILE%"
echo SOLANA_RPC_URL=https://api.mainnet-beta.solana.com >> "%ENV_FILE%"
echo BLACKHOLE_RPC_URL=http://blackhole-node:8545 >> "%ENV_FILE%"
echo LOG_LEVEL=info >> "%ENV_FILE%"
echo DEBUG_MODE=false >> "%ENV_FILE%"
echo ETHEREUM_PRIVATE_KEY=your_ethereum_private_key_here >> "%ENV_FILE%"
echo SOLANA_PRIVATE_KEY=your_solana_private_key_here >> "%ENV_FILE%"
echo BLACKHOLE_PRIVATE_KEY=your_blackhole_private_key_here >> "%ENV_FILE%"
goto :eof

:setup_dirs
echo [INFO] Setting up directories...
if not exist "%SCRIPT_DIR%data" mkdir "%SCRIPT_DIR%data"
if not exist "%SCRIPT_DIR%logs" mkdir "%SCRIPT_DIR%logs"
if not exist "%SCRIPT_DIR%backups" mkdir "%SCRIPT_DIR%backups"
if not exist "%SCRIPT_DIR%monitoring\grafana\dashboards" mkdir "%SCRIPT_DIR%monitoring\grafana\dashboards"
if not exist "%SCRIPT_DIR%monitoring\grafana\datasources" mkdir "%SCRIPT_DIR%monitoring\grafana\datasources"
if not exist "%SCRIPT_DIR%nginx\ssl" mkdir "%SCRIPT_DIR%nginx\ssl"
echo [SUCCESS] Directories created successfully
goto :eof

:start
echo [INFO] Starting BlackHole Bridge in Docker...
call :check_docker
if errorlevel 1 goto end

call :check_env
call :setup_dirs

echo [INFO] Building and starting Docker services...
docker-compose -f "%COMPOSE_FILE%" up -d --build

if errorlevel 1 (
    echo [ERROR] Failed to start services
    goto end
)

echo [INFO] Waiting for services to initialize...
timeout /t 15 /nobreak >nul

call :health

echo.
echo [SUCCESS] 🚀 BlackHole Bridge is now running!
echo ========================================
echo 📊 Bridge Dashboard: http://localhost:8084
echo 📈 Monitoring Dashboard: http://localhost:3000 (admin/admin123)
echo 🔍 View Logs: %0 logs
echo ❤️  Check Health: %0 health
echo 🛑 Stop Services: %0 stop
echo.
echo [INFO] Press Ctrl+C to return to command prompt
goto end

:stop
echo [INFO] Stopping BlackHole Bridge services...
docker-compose -f "%COMPOSE_FILE%" down
if errorlevel 1 (
    echo [ERROR] Failed to stop some services
) else (
    echo [SUCCESS] All services stopped successfully
)
goto end

:restart
echo [INFO] Restarting BlackHole Bridge services...
call :stop
timeout /t 5 /nobreak >nul
call :start
goto end

:status
echo [INFO] Service Status:
echo ==================
docker-compose -f "%COMPOSE_FILE%" ps
goto end

:logs
echo [INFO] Showing logs from all services...
echo Press Ctrl+C to stop viewing logs
echo =====================================
docker-compose -f "%COMPOSE_FILE%" logs -f
goto end

:health
echo [INFO] Checking service health...

REM Check bridge health
curl -s http://localhost:8084/health >nul 2>&1
if errorlevel 1 (
    echo [ERROR] ✗ Bridge service: Unhealthy or not responding
) else (
    echo [SUCCESS] ✓ Bridge service: Healthy
)

REM Check database
docker-compose -f "%COMPOSE_FILE%" exec -T postgres pg_isready -U bridge >nul 2>&1
if errorlevel 1 (
    echo [ERROR] ✗ PostgreSQL: Unhealthy or not responding
) else (
    echo [SUCCESS] ✓ PostgreSQL: Healthy
)

REM Check Redis
docker-compose -f "%COMPOSE_FILE%" exec -T redis redis-cli ping >nul 2>&1
if errorlevel 1 (
    echo [ERROR] ✗ Redis: Unhealthy or not responding
) else (
    echo [SUCCESS] ✓ Redis: Healthy
)

REM Check if Grafana is responding
curl -s http://localhost:3000/api/health >nul 2>&1
if errorlevel 1 (
    echo [WARNING] ✗ Grafana: Not responding (may still be starting)
) else (
    echo [SUCCESS] ✓ Grafana: Healthy
)
goto end

:setup
echo [INFO] Setting up BlackHole Bridge environment...
call :check_docker
if errorlevel 1 goto end

call :setup_dirs
call :check_env

echo [INFO] Building Docker images (this may take a few minutes)...
docker-compose -f "%COMPOSE_FILE%" build

if errorlevel 1 (
    echo [ERROR] Failed to build Docker images
    goto end
)

echo [SUCCESS] Environment setup completed successfully!
echo.
echo Next steps:
echo 1. Edit .env file with your blockchain configuration
echo 2. Run: %0 start
echo.
goto end

:clean
echo [WARNING] This will remove all containers, volumes, and data!
set /p confirm="Are you sure? (y/N): "
if /i not "%confirm%"=="y" (
    echo [INFO] Cleanup cancelled
    goto end
)

echo [INFO] Cleaning up containers, volumes, and data...
docker-compose -f "%COMPOSE_FILE%" down -v --remove-orphans
docker system prune -f
docker volume prune -f

echo [SUCCESS] Cleanup completed
goto end

:end
echo.
echo [INFO] Script execution completed
pause
