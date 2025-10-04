# BlackHole Blockchain Testnet Bootstrap Script
# This script starts a 3-node testnet and executes the first transaction

param(
    [switch]$Clean = $false,
    [switch]$FirstTransaction = $true
)

# Color functions for output
function Write-Info { param($Message) Write-Host "[INFO] $Message" -ForegroundColor Blue }
function Write-Success { param($Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warning { param($Message) Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Error { param($Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

Write-Info "🚀 Starting BlackHole Blockchain Testnet..."

# Change to testnet directory
Set-Location $PSScriptRoot

# Clean up if requested
if ($Clean) {
    Write-Warning "🧹 Cleaning up existing testnet..."
    docker-compose -f docker-compose-testnet.yml down -v --remove-orphans
    docker system prune -f
}

# Check Docker is running
try {
    docker version | Out-Null
} catch {
    Write-Error "❌ Docker is not running. Please start Docker first."
    exit 1
}

Write-Info "🏗️ Building testnet images..."
docker-compose -f docker-compose-testnet.yml build --no-cache

Write-Info "🌐 Starting testnet validators..."
docker-compose -f docker-compose-testnet.yml up -d validator1 validator2 validator3

# Wait for validators to be healthy
Write-Info "⏳ Waiting for validators to become healthy..."
$maxAttempts = 60
$attempt = 0
$healthyNodes = 0

while ($attempt -lt $maxAttempts -and $healthyNodes -lt 3) {
    Start-Sleep 5
    $attempt++
    $healthStatus = docker-compose -f docker-compose-testnet.yml ps --format json | ConvertFrom-Json
    $healthyNodes = ($healthStatus | Where-Object { $_.Health -eq "healthy" }).Count
    
    Write-Info "📊 Healthy validators: $healthyNodes/3 (attempt $attempt/$maxAttempts)"
    
    if ($healthyNodes -eq 3) {
        Write-Success "✅ All validators are healthy!"
        break
    }
}

if ($healthyNodes -lt 3) {
    Write-Error "❌ Validators failed to become healthy within timeout"
    Write-Info "🔍 Checking validator logs..."
    docker-compose -f docker-compose-testnet.yml logs validator1 --tail=20
    exit 1
}

# Start additional services
Write-Info "🚰 Starting faucet and explorer services..."
docker-compose -f docker-compose-testnet.yml up -d faucet explorer

# Display network information
Write-Success "🎉 BlackHole Testnet is now running!"
Write-Info ""
Write-Info "📡 Network Information:"
Write-Info "  Chain ID: blackhole-testnet-1"
Write-Info "  Token: tBHX (Testnet BlackHole)"
Write-Info "  Block Time: 3 seconds"
Write-Info ""
Write-Info "🔗 API Endpoints:"
Write-Info "  Validator 1: http://localhost:8080"
Write-Info "  Validator 2: http://localhost:8081"
Write-Info "  Validator 3: http://localhost:8082"
Write-Info "  Faucet:      http://localhost:8083"
Write-Info "  Explorer:    http://localhost:8084"
Write-Info ""

# Health checks
Write-Info "🏥 Performing health checks..."
$endpoints = @{
    "Validator 1" = "http://localhost:8080/health"
    "Validator 2" = "http://localhost:8081/health" 
    "Validator 3" = "http://localhost:8082/health"
}

foreach ($endpoint in $endpoints.GetEnumerator()) {
    try {
        $response = Invoke-RestMethod -Uri $endpoint.Value -TimeoutSec 10
        Write-Success "  ✅ $($endpoint.Key): Healthy"
    } catch {
        Write-Warning "  ⚠️ $($endpoint.Key): $($_.Exception.Message)"
    }
}

# First transaction if requested
if ($FirstTransaction) {
    Write-Info ""
    Write-Info "💸 Executing first transaction on testnet..."
    
    Start-Sleep 10  # Give network time to fully sync
    
    try {
        # Get faucet tokens first
        Write-Info "🚰 Requesting tokens from faucet..."
        $faucetRequest = @{
            address = "tbhx1user000000000000000000000000000000"
            amount = "1000000000000000000000"
        } | ConvertTo-Json
        
        $faucetResponse = Invoke-RestMethod -Uri "http://localhost:8083/faucet/request" -Method POST -Body $faucetRequest -ContentType "application/json"
        Write-Success "  ✅ Faucet request successful: $($faucetResponse.tx_hash)"
        
        Start-Sleep 5  # Wait for faucet tx to be mined
        
        # Send first transaction
        Write-Info "📤 Sending first transaction..."
        $transaction = @{
            from = "tbhx1user000000000000000000000000000000"
            to = "tbhx1recipient000000000000000000000000"
            amount = "100000000000000000000"  # 100 tBHX
            token = "tBHX"
            memo = "First transaction on BlackHole Testnet! 🎉"
        } | ConvertTo-Json
        
        $txResponse = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/tx/send" -Method POST -Body $transaction -ContentType "application/json"
        
        Write-Success "🎉 FIRST TRANSACTION SUCCESSFUL!"
        Write-Info "  📝 Transaction Hash: $($txResponse.tx_hash)"
        Write-Info "  🔗 From: tbhx1user000000000000000000000000000000"
        Write-Info "  🔗 To: tbhx1recipient000000000000000000000000"
        Write-Info "  💰 Amount: 100 tBHX"
        Write-Info "  📄 Memo: First transaction on BlackHole Testnet! 🎉"
        
        # Get transaction details
        Start-Sleep 3
        try {
            $txDetails = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/tx/$($txResponse.tx_hash)" -Method GET
            Write-Info "  ⚡ Block Height: $($txDetails.block_height)"
            Write-Info "  ⏱️ Timestamp: $($txDetails.timestamp)"
            Write-Info "  ⛽ Gas Used: $($txDetails.gas_used)"
        } catch {
            Write-Warning "  ⚠️ Could not fetch transaction details yet (may still be mining)"
        }
        
    } catch {
        Write-Error "❌ First transaction failed: $($_.Exception.Message)"
        Write-Info "🔍 This is normal if the API endpoints are not fully implemented yet"
    }
}

# Show running containers
Write-Info ""
Write-Info "🐳 Running containers:"
docker-compose -f docker-compose-testnet.yml ps

Write-Info ""
Write-Info "📋 Useful commands:"
Write-Info "  View logs:        docker-compose -f docker-compose-testnet.yml logs -f [service]"
Write-Info "  Stop testnet:     docker-compose -f docker-compose-testnet.yml down"
Write-Info "  Clean restart:    docker-compose -f docker-compose-testnet.yml down -v && docker-compose -f docker-compose-testnet.yml up -d"
Write-Info "  Check status:     docker-compose -f docker-compose-testnet.yml ps"
Write-Info ""

Write-Success "🚀 BlackHole Testnet is ready for development and testing!"
Write-Info "🌐 Access the blockchain dashboard at: http://localhost:8080"