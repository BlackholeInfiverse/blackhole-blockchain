@echo off
echo 🌉 BlackHole Bridge SDK - Docker Runner
echo ========================================

REM Stop any existing containers
echo 🛑 Stopping existing bridge containers...
docker stop $(docker ps -q --filter "ancestor=docker-bridge-sdk:latest") 2>nul

REM Remove stopped containers
echo 🧹 Cleaning up stopped containers...
docker container prune -f 2>nul

REM Check if image exists
docker image inspect docker-bridge-sdk:latest >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker image 'docker-bridge-sdk:latest' not found!
    echo 💡 Please build the image first using: docker-compose build bridge-sdk
    pause
    exit /b 1
)

REM Run the container
echo 🚀 Starting BlackHole Bridge SDK container...
docker run -d ^
    --name blackhole-bridge-sdk ^
    -p 8084:8084 ^
    -p 9090:9090 ^
    docker-bridge-sdk:latest

if %errorlevel% equ 0 (
    echo ✅ Bridge SDK container started successfully!
    echo 🌐 Dashboard: http://localhost:8084
    echo 📊 Infrastructure: http://localhost:8084/infra-dashboard
    echo 🔗 Relay Server: http://localhost:9090
    echo.
    echo 📋 Container Status:
    docker ps --filter "name=blackhole-bridge-sdk"
    echo.
    echo 💡 To view logs: docker logs blackhole-bridge-sdk
    echo 💡 To stop: docker stop blackhole-bridge-sdk
) else (
    echo ❌ Failed to start container!
    echo 💡 Check if port 8084 is already in use
)

pause
