@echo off
echo 🚀 Starting BlackHole Bridge SDK...
echo =====================================

REM Change to the bridge directory
cd /d "%~dp0"

REM Check if Go is installed
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Go is not installed or not in PATH
    echo Please install Go from https://golang.org/dl/
    pause
    exit /b 1
)

echo ✅ Go is available
echo.

REM Clean and update dependencies
echo 📦 Updating dependencies...
go mod tidy
if %errorlevel% neq 0 (
    echo ❌ Failed to update dependencies
    pause
    exit /b 1
)

echo ✅ Dependencies updated
echo.

REM Build the bridge
echo 🔨 Building bridge...
go build -o bridge.exe main.go
if %errorlevel% neq 0 (
    echo ❌ Failed to build bridge
    pause
    exit /b 1
)

echo ✅ Bridge built successfully
echo.

REM Run the bridge
echo 🌉 Starting Bridge SDK Dashboard...
echo Dashboard will be available at: http://localhost:8084
echo Press Ctrl+C to stop the bridge
echo.

bridge.exe

pause
