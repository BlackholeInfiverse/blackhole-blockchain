# Quick start script for wallet service with blockchain
$env:POSTGRES_HOST="localhost"
$env:POSTGRES_PORT="5432"
$env:POSTGRES_DB="blackhole_wallet"
$env:POSTGRES_USER="postgres"
$env:POSTGRES_PASSWORD="blackhole_secure_pass"
$env:POSTGRES_SSL_MODE="disable"
$env:REDIS_ADDRESS="localhost:6379"
$env:REDIS_PASSWORD="blackhole_redis_pass"
$env:REDIS_DB="0"

Write-Host "Starting Wallet Service connected to blockchain..." -ForegroundColor Green
.\wallet-service.exe -web -port 9000 -peerAddr /ip4/127.0.0.1/tcp/3001/p2p/12D3KooWFfcpYRUEQrQHucXJ3u9rH7DVb1C8mKoQXTxERcc7M7hA
