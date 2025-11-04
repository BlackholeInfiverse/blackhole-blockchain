@echo off
REM BlackHole Bridge SDK Deployment Script for Windows
REM This script deploys the bridge SDK with block explorer functionality

echo 🚀 Starting BlackHole Bridge SDK Deployment...

REM Configuration
set PROJECT_DIR=%~dp0
set MAIN_BRIDGE_DIR=%PROJECT_DIR%main_bridge
set DOCKER_COMPOSE_FILE=%PROJECT_DIR%docker-compose.yml
set ENV_FILE=%MAIN_BRIDGE_DIR%\.env

REM Colors (using Windows color codes)
REM Note: Windows CMD doesn't support ANSI colors well, so we'll use plain text

:print_status
echo [INFO] %~1
goto :eof

:print_success
echo [SUCCESS] %~1
goto :eof

:print_warning
echo [WARNING] %~1
goto :eof

:print_error
echo [ERROR] %~1
goto :eof

REM Check prerequisites
:check_prerequisites
call :print_status "Checking prerequisites..."

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    call :print_error "Docker is not installed. Please install Docker first."
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    REM Try newer Docker Compose syntax
    docker compose version >nul 2>&1
    if %errorlevel% neq 0 (
        call :print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit /b 1
    )
)

REM Check if Go is installed
go version >nul 2>&1
if %errorlevel% neq 0 (
    call :print_error "Go is not installed. Please install Go first."
    exit /b 1
)

call :print_success "Prerequisites check passed"
goto :eof

REM Setup environment
:setup_environment
call :print_status "Setting up environment..."

REM Create .env file if it doesn't exist
if not exist "%ENV_FILE%" (
    copy "%MAIN_BRIDGE_DIR%\.env.example" "%ENV_FILE%" >nul
    call :print_warning "Created .env file from example. Please edit it with your configuration."
)

REM Create necessary directories
if not exist "%MAIN_BRIDGE_DIR%\data" mkdir "%MAIN_BRIDGE_DIR%\data"
if not exist "%MAIN_BRIDGE_DIR%\logs" mkdir "%MAIN_BRIDGE_DIR%\logs"

call :print_success "Environment setup completed"
goto :eof

REM Build the application
:build_application
call :print_status "Building bridge application..."

cd /d "%MAIN_BRIDGE_DIR%"

REM Download dependencies
go mod download

REM Build the application
go build -o main.exe main.go

if %errorlevel% equ 0 (
    call :print_success "Application built successfully"
) else (
    call :print_error "Failed to build application"
    exit /b 1
)
goto :eof

REM Start services with Docker Compose
:start_services
call :print_status "Starting services with Docker Compose..."

cd /d "%PROJECT_DIR%"

REM Start services
docker-compose up -d
if %errorlevel% neq 0 (
    REM Try newer Docker Compose syntax
    docker compose up -d
)

if %errorlevel% equ 0 (
    call :print_success "Services started successfully"
) else (
    call :print_error "Failed to start services"
    exit /b 1
)
goto :eof

REM Wait for services to be ready
:wait_for_services
call :print_status "Waiting for services to be ready..."

REM Wait for bridge service
set max_attempts=30
set attempt=1

:wait_loop
curl -s http://localhost:8084/health >nul 2>&1
if %errorlevel% equ 0 (
    call :print_success "Bridge service is ready"
    goto :eof
)

call :print_status "Waiting for bridge service... (attempt %attempt%/%max_attempts%)"
timeout /t 2 /nobreak >nul
set /a attempt+=1

if %attempt% leq %max_attempts% goto wait_loop

call :print_warning "Bridge service may not be ready yet. Continuing..."
goto :eof

REM Test block explorer endpoints
:test_explorer_endpoints
call :print_status "Testing block explorer endpoints..."

REM Test health endpoint
curl -s http://localhost:8084/health | findstr "healthy" >nul
if %errorlevel% equ 0 (
    call :print_success "Health endpoint is working"
) else (
    call :print_warning "Health endpoint may not be responding correctly"
)

REM Test stats endpoint
curl -s http://localhost:8084/stats | findstr "success" >nul
if %errorlevel% equ 0 (
    call :print_success "Stats endpoint is working"
) else (
    call :print_warning "Stats endpoint may not be responding correctly"
)

REM Test transactions endpoint
curl -s http://localhost:8084/transactions | findstr "transactions" >nul
if %errorlevel% equ 0 (
    call :print_success "Transactions endpoint is working"
) else (
    call :print_warning "Transactions endpoint may not be responding correctly"
)
goto :eof

REM Display deployment information
:display_info
echo.
call :print_success "BlackHole Bridge SDK deployed successfully!"
echo.
echo 📊 Dashboard URLs:
echo    • Main Dashboard: http://localhost:8084
echo    • Health Check: http://localhost:8084/health
echo    • Statistics: http://localhost:8084/stats
echo    • Transactions: http://localhost:8084/transactions
echo.
echo 🔍 Block Explorer Endpoints:
echo    • Block by Height: http://localhost:8084/block/{height}
echo    • Transaction by Hash: http://localhost:8084/tx/{hash}
echo.
echo 📝 Logs:
echo    • View logs: docker-compose logs -f bridge
echo    • Log files: .\main_bridge\logs\
echo.
echo 🛠️  Management:
echo    • Stop: docker-compose down
echo    • Restart: docker-compose restart
echo    • Rebuild: docker-compose up -d --build
echo.
goto :eof

REM Main deployment function
:main
echo ==========================================
echo 🚀 BlackHole Bridge SDK Deployment Script
echo ==========================================
echo.

call :check_prerequisites
call :setup_environment
call :build_application
call :start_services
call :wait_for_services
call :test_explorer_endpoints
call :display_info

call :print_success "Deployment completed successfully!"
goto :eof

REM Handle command line arguments
if "%1"=="stop" goto stop_services
if "%1"=="restart" goto restart_services
if "%1"=="logs" goto show_logs
if "%1"=="status" goto show_status
goto main

:stop_services
call :print_status "Stopping services..."
cd /d "%PROJECT_DIR%"
docker-compose down
if %errorlevel% neq 0 docker compose down
call :print_success "Services stopped"
goto :eof

:restart_services
call :print_status "Restarting services..."
cd /d "%PROJECT_DIR%"
docker-compose restart
if %errorlevel% neq 0 docker compose restart
call :print_success "Services restarted"
goto :eof

:show_logs
call :print_status "Showing logs..."
cd /d "%PROJECT_DIR%"
docker-compose logs -f
if %errorlevel% neq 0 docker compose logs -f
goto :eof

:show_status
call :print_status "Checking service status..."
cd /d "%PROJECT_DIR%"
docker-compose ps
if %errorlevel% neq 0 docker compose ps
goto :eof