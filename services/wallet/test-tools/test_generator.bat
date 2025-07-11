@echo off
echo Testing fake transaction generator compilation...
echo.

echo Checking Go modules...
go mod tidy

echo.
echo Attempting to build the generator...
go build fake_transaction_generator.go

if %ERRORLEVEL% EQU 0 (
    echo ✅ Build successful! The generator is ready to run.
    echo.
    echo To run the generator:
    echo   1. Make sure MongoDB is running on localhost:27017
    echo   2. Run: go run fake_transaction_generator.go
    echo.
    echo Cleaning up build artifacts...
    if exist fake_transaction_generator.exe del fake_transaction_generator.exe
) else (
    echo ❌ Build failed. Please check the error messages above.
    echo.
    echo Common issues:
    echo   - Missing Go dependencies (run 'go mod tidy')
    echo   - Import path issues
    echo   - Missing blockchain modules
)

echo.
pause
