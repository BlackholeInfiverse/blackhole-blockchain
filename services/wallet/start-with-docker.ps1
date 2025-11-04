# Start Wallet Service with Docker Databases
# This script loads environment variables and starts the wallet service connected to Docker

Write-Host "🚀 Starting Blackhole Wallet Service Connected to Blockchain Nodes..." -ForegroundColor Cyan
Write-Host ""

# Set environment variables for Docker databases
$env:POSTGRES_HOST = "localhost"
$env:POSTGRES_PORT = "5432"
$env:POSTGRES_DB = "blackhole_wallet"
$env:POSTGRES_USER = "postgres"
$env:POSTGRES_PASSWORD = "blackhole_secure_pass"
$env:POSTGRES_SSL_MODE = "disable"

$env:REDIS_ADDRESS = "localhost:6379"
$env:REDIS_PASSWORD = "blackhole_redis_pass"
$env:REDIS_DB = "0"

$env:BADGER_PATH = "./data/badger"
$env:BADGER_IN_MEMORY = "false"
$env:BADGER_ENCRYPTION = "false"

$env:APP_ENV = "development"
$env:LOG_LEVEL = "info"

# Blockchain node endpoints (your 5 running nodes)
$env:BLOCKCHAIN_API_ENDPOINTS = "http://localhost:8081,http://localhost:8082,http://localhost:8083,http://localhost:8084,http://localhost:8085"

Write-Host "✅ Environment configured:" -ForegroundColor Green
Write-Host "   PostgreSQL: localhost:5432/blackhole_wallet" -ForegroundColor Yellow
Write-Host "   Redis:      localhost:6379" -ForegroundColor Yellow
Write-Host "   BadgerDB:   ./data/badger (fallback)" -ForegroundColor Yellow
Write-Host "   Blockchain: 5 nodes (ports 8081-8085)" -ForegroundColor Yellow
Write-Host ""

# Check if Docker containers are running
Write-Host "🔍 Checking Docker containers..." -ForegroundColor Cyan
$postgresRunning = docker ps --filter "name=wallet-postgres" --filter "status=running" --format "{{.Names}}"
$redisRunning = docker ps --filter "name=wallet-redis" --filter "status=running" --format "{{.Names}}"
$blockchainNodes = docker ps --filter "name=blackhole-node" --filter "status=running" --format "{{.Names}}" | Measure-Object -Line

if ($postgresRunning) {
    Write-Host "   ✅ PostgreSQL container is running" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  PostgreSQL container not found - will use BadgerDB fallback" -ForegroundColor Yellow
}

if ($redisRunning) {
    Write-Host "   ✅ Redis container is running" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Redis container not found - will run without cache" -ForegroundColor Yellow
}

if ($blockchainNodes.Lines -gt 0) {
    Write-Host "   ✅ $($blockchainNodes.Lines) Blockchain nodes running" -ForegroundColor Green
    docker ps --filter "name=blackhole-node" --filter "status=running" --format "      - {{.Names}} ({{.Status}})" | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
} else {
    Write-Host "   ❌ No blockchain nodes found!" -ForegroundColor Red
    Write-Host "      Please start blockchain nodes first" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "🌐 Starting Wallet Service on http://localhost:9000" -ForegroundColor Cyan
Write-Host "   Press Ctrl+C to stop" -ForegroundColor Gray
Write-Host ""
Write-Host "================================================================" -ForegroundColor DarkGray
Write-Host ""

# Start the wallet service
.\wallet-service.exe -web -port 9000
