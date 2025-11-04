@echo off
REM BlackHole Blockchain Docker Management Script for Windows

echo 🚀 BlackHole Blockchain Docker Manager
echo ======================================

if "%1"=="build" goto BUILD
if "%1"=="start" goto START
if "%1"=="stop" goto STOP
if "%1"=="restart" goto RESTART
if "%1"=="logs" goto LOGS
if "%1"=="status" goto STATUS
if "%1"=="clean" goto CLEAN
if "%1"=="test" goto TEST
goto USAGE

:BUILD
echo 🔨 Building Docker images...
docker-compose build --no-cache
echo ✅ Build completed!
goto END

:START
echo 🚀 Starting BlackHole Blockchain stack...
docker-compose up -d
echo ✅ Stack started! Access:
echo    🌐 Blockchain Dashboard: http://localhost:8080
echo    🌉 Bridge Dashboard: http://localhost:8084
goto END

:STOP
echo 🛑 Stopping BlackHole Blockchain stack...
docker-compose down
echo ✅ Stack stopped!
goto END

:RESTART
echo 🔄 Restarting BlackHole Blockchain stack...
docker-compose down
docker-compose up -d
echo ✅ Stack restarted!
goto END

:LOGS
if "%2"=="" (
    echo 📋 Showing all logs...
    docker-compose logs -f
) else (
    echo 📋 Showing logs for %2...
    docker-compose logs -f %2
)
goto END

:STATUS
echo 📊 BlackHole Blockchain Stack Status:
docker-compose ps
goto END

:CLEAN
echo 🧹 Cleaning up Docker resources...
docker-compose down -v
docker system prune -f
echo ✅ Cleanup completed!
goto END

:TEST
echo 🧪 Testing Docker setup...
echo 📝 Building images...
docker-compose build
echo 🚀 Starting services...
docker-compose up -d
timeout /t 10 /nobreak >nul
echo 🔍 Checking health...
curl -f http://localhost:8080/health || echo ❌ Blockchain health check failed
curl -f http://localhost:8084/health || echo ❌ Bridge health check failed
echo ✅ Test completed!
goto END

:USAGE
echo Usage: %0 {build^|start^|stop^|restart^|logs^|status^|clean^|test}
echo.
echo Commands:
echo   build    - Build Docker images
echo   start    - Start the blockchain stack
echo   stop     - Stop the blockchain stack
echo   restart  - Restart the blockchain stack
echo   logs     - Show logs (optionally specify service: blockchain^|bridge)
echo   status   - Show stack status
echo   clean    - Clean up Docker resources
echo   test     - Test the complete setup

:END