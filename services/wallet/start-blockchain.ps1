# Start Wallet Service Connected to Blockchain Nodes

Write-Host "Starting Blackhole Wallet Service..." -ForegroundColor Cyan
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

# Blockchain node endpoints (your 5 running nodes)
$env:BLOCKCHAIN_API_ENDPOINTS = "http://localhost:8081,http://localhost:8082,http://localhost:8083,http://localhost:8084,http://localhost:8085"

$env:APP_ENV = "development"
$env:LOG_LEVEL = "info"

Write-Host "Environment configured:" -ForegroundColor Green
Write-Host "  PostgreSQL: localhost:5432/blackhole_wallet" -ForegroundColor Yellow
Write-Host "  Redis:      localhost:6379" -ForegroundColor Yellow  
Write-Host "  BadgerDB:   ./data/badger (fallback)" -ForegroundColor Yellow
Write-Host "  Blockchain: 5 nodes (ports 8081-8085)" -ForegroundColor Yellow
Write-Host ""

# Check if Docker containers are running
Write-Host "Checking Docker containers..." -ForegroundColor Cyan

$postgresRunning = docker ps --filter "name=wallet-postgres" --filter "status=running" --format "{{.Names}}" 2>$null
$redisRunning = docker ps --filter "name=wallet-redis" --filter "status=running" --format "{{.Names}}" 2>$null
$blockchainNodes = @(docker ps --filter "name=blackhole-node" --filter "status=running" --format "{{.Names}}" 2>$null)

if ($postgresRunning) {
    Write-Host "  PostgreSQL: RUNNING" -ForegroundColor Green
} else {
    Write-Host "  PostgreSQL: NOT FOUND (will use BadgerDB fallback)" -ForegroundColor Yellow
}

if ($redisRunning) {
    Write-Host "  Redis: RUNNING" -ForegroundColor Green
} else {
    Write-Host "  Redis: NOT FOUND (will run without cache)" -ForegroundColor Yellow
}

if ($blockchainNodes.Count -gt 0) {
    Write-Host "  Blockchain Nodes: $($blockchainNodes.Count) RUNNING" -ForegroundColor Green
    foreach ($node in $blockchainNodes) {
        Write-Host "    - $node" -ForegroundColor Gray
    }
} else {
    Write-Host "  Blockchain Nodes: NONE FOUND!" -ForegroundColor Red
    Write-Host "    Please start blockchain nodes first" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host "Starting Wallet Service on http://localhost:9000" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop" -ForegroundColor Gray
Write-Host "===============================================" -ForegroundColor DarkGray
Write-Host ""

# Start the wallet service with blockchain connection
# Connect to node1 peer (you can change to any of your 5 nodes)
.\wallet-service.exe -web -port 9000 -peerAddr "/ip4/127.0.0.1/tcp/3001/p2p/12D3KooWFfcpYRUEQrQHucXJ3u9rH7DVb1C8mKoQXTxERcc7M7hA"
