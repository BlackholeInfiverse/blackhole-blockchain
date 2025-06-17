@echo off
REM Simple BlackHole Blockchain Deployment Script for Windows

echo 🚀 BlackHole Blockchain - Simple Deployment
echo ============================================

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose is not installed.
    pause
    exit /b 1
)

echo [INFO] Docker is available

REM Stop any existing services
echo [INFO] Stopping existing services...
docker-compose -f docker-compose.simple.yml down 2>nul

REM Build and start services
echo [INFO] Building and starting BlackHole blockchain...
echo [INFO] Note: This may take a few minutes for the first build...

REM Try building with the updated Dockerfile
docker-compose -f docker-compose.simple.yml build

if errorlevel 1 (
    echo [ERROR] Docker build failed. Trying alternative approach...
    echo [INFO] Using docker-build.bat for compatibility...
    call docker-build.bat
    exit /b 0
)

echo [INFO] Starting services...
docker-compose -f docker-compose.simple.yml up -d

if errorlevel 1 (
    echo [ERROR] Failed to start services
    pause
    exit /b 1
)

echo [INFO] Services started successfully!

REM Wait for services to be ready
echo [INFO] Waiting for blockchain to be ready...
timeout /t 30 /nobreak >nul

REM Check service status
docker-compose -f docker-compose.simple.yml ps

echo.
echo ✅ BlackHole Blockchain is now running!
echo.
echo 🌐 Access Points:
echo    Blockchain Node:    http://localhost:8080
echo    Dashboard:          http://localhost:80
echo    API Status:         http://localhost:8080/api/status
echo.
echo 🔧 Management:
echo    View logs:          docker-compose -f docker-compose.simple.yml logs -f
echo    Stop services:      docker-compose -f docker-compose.simple.yml down
echo    Restart:            docker-compose -f docker-compose.simple.yml restart
echo.
echo Press any key to open the blockchain dashboard...
pause >nul

REM Open dashboard
start http://localhost:8080

echo.
echo Deployment completed! The blockchain is running in Docker.
pause
