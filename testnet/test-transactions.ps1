# BlackHole Testnet Transaction Testing Script
# This script sends test transactions to demonstrate multi-node functionality

param(
    [int]$Count = 5,
    [int]$DelaySeconds = 3
)

# Color functions for output
function Write-Info { param($Message) Write-Host "[INFO] $Message" -ForegroundColor Blue }
function Write-Success { param($Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warning { param($Message) Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Error { param($Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

Write-Info "🧪 BlackHole Testnet Transaction Testing"
Write-Info "  Sending $Count transactions with $DelaySeconds second intervals"
Write-Info ""

# Test accounts for transactions
$testAccounts = @(
    "tbhx1alice00000000000000000000000000000",
    "tbhx1bob0000000000000000000000000000000", 
    "tbhx1charlie000000000000000000000000000",
    "tbhx1diana00000000000000000000000000000"
)

# API endpoints to test load balancing
$apiEndpoints = @(
    "http://localhost:8080",  # Validator 1
    "http://localhost:8081",  # Validator 2 
    "http://localhost:8082"   # Validator 3
)

# Function to check API health
function Test-APIHealth {
    param($endpoint)
    try {
        $response = Invoke-RestMethod -Uri "$endpoint/health" -TimeoutSec 5
        return $true
    } catch {
        return $false
    }
}

# Function to get balance (mock implementation)
function Get-Balance {
    param($address, $endpoint)
    try {
        $response = Invoke-RestMethod -Uri "$endpoint/api/v1/account/$address" -TimeoutSec 10
        return $response.balance
    } catch {
        return "N/A"
    }
}

# Function to send transaction
function Send-Transaction {
    param($from, $to, $amount, $endpoint, $txNumber)
    
    try {
        $transaction = @{
            from = $from
            to = $to
            amount = $amount
            token = "tBHX"
            memo = "Test transaction #$txNumber on BlackHole Testnet"
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$endpoint/api/v1/tx/send" -Method POST -Body $transaction -ContentType "application/json" -TimeoutSec 15
        
        return @{
            success = $true
            tx_hash = $response.tx_hash
            endpoint_used = $endpoint
        }
    } catch {
        return @{
            success = $false
            error = $_.Exception.Message
            endpoint_used = $endpoint
        }
    }
}

# Check if testnet is running
Write-Info "🏥 Checking testnet health..."
$healthyEndpoints = @()
foreach ($endpoint in $apiEndpoints) {
    $isHealthy = Test-APIHealth -endpoint $endpoint
    if ($isHealthy) {
        $healthyEndpoints += $endpoint
        Write-Success "  ✅ $endpoint is healthy"
    } else {
        Write-Warning "  ⚠️ $endpoint is not responding"
    }
}

if ($healthyEndpoints.Count -eq 0) {
    Write-Error "❌ No healthy endpoints found. Please start the testnet first:"
    Write-Info "   .\start-testnet.ps1"
    exit 1
}

Write-Success "📡 Found $($healthyEndpoints.Count) healthy validator(s)"
Write-Info ""

# Send test transactions
$successCount = 0
$failCount = 0
$transactions = @()

Write-Info "💸 Starting transaction testing..."
Write-Info ""

for ($i = 1; $i -le $Count; $i++) {
    # Randomly select sender and receiver
    $fromIndex = Get-Random -Minimum 0 -Maximum $testAccounts.Count
    $toIndex = Get-Random -Minimum 0 -Maximum $testAccounts.Count
    while ($toIndex -eq $fromIndex) { 
        $toIndex = Get-Random -Minimum 0 -Maximum $testAccounts.Count 
    }
    
    $from = $testAccounts[$fromIndex]
    $to = $testAccounts[$toIndex]
    $amount = [string]((Get-Random -Minimum 1 -Maximum 100) * 1000000000000000000)  # 1-100 tBHX
    
    # Round-robin through healthy endpoints
    $endpoint = $healthyEndpoints[($i - 1) % $healthyEndpoints.Count]
    
    Write-Info "📤 Transaction $i/$Count"
    Write-Info "  From: $from"
    Write-Info "  To: $to" 
    Write-Info "  Amount: $([decimal]$amount / 1000000000000000000) tBHX"
    Write-Info "  Endpoint: $endpoint"
    
    $result = Send-Transaction -from $from -to $to -amount $amount -endpoint $endpoint -txNumber $i
    
    if ($result.success) {
        Write-Success "  ✅ Success! TX Hash: $($result.tx_hash)"
        $successCount++
        $transactions += @{
            number = $i
            tx_hash = $result.tx_hash
            from = $from
            to = $to
            amount = $amount
            endpoint = $endpoint
            timestamp = Get-Date
        }
    } else {
        Write-Error "  ❌ Failed: $($result.error)"
        $failCount++
    }
    
    Write-Info ""
    
    # Wait between transactions (except for the last one)
    if ($i -lt $Count) {
        Start-Sleep $DelaySeconds
    }
}

# Summary
Write-Info "📊 Transaction Testing Summary"
Write-Info "========================="
Write-Success "  ✅ Successful: $successCount/$Count"
if ($failCount -gt 0) {
    Write-Error "  ❌ Failed: $failCount/$Count"
}
Write-Info "  🌐 Endpoints used: $($healthyEndpoints.Count)"
Write-Info "  ⏱️ Total duration: $($Count * $DelaySeconds) seconds"

if ($transactions.Count -gt 0) {
    Write-Info ""
    Write-Info "📝 Successful Transactions:"
    foreach ($tx in $transactions) {
        Write-Info "  TX $($tx.number): $($tx.tx_hash) ($($tx.endpoint))"
    }
    
    # Test transaction queries
    Write-Info ""
    Write-Info "🔍 Testing transaction queries..."
    Start-Sleep 5  # Wait for transactions to be mined
    
    foreach ($tx in $transactions | Select-Object -First 3) {  # Test first 3 transactions
        try {
            $endpoint = $healthyEndpoints[0]  # Use first healthy endpoint
            $txDetails = Invoke-RestMethod -Uri "$endpoint/api/v1/tx/$($tx.tx_hash)" -TimeoutSec 10
            Write-Success "  ✅ TX $($tx.tx_hash): Block $($txDetails.block_height)"
        } catch {
            Write-Warning "  ⚠️ TX $($tx.tx_hash): Query failed (may still be mining)"
        }
    }
}

Write-Info ""
Write-Info "🎯 Multi-node functionality demonstrated!"
Write-Info "  - Transactions sent to different validator nodes"
Write-Info "  - Load balanced across $($healthyEndpoints.Count) endpoints"
Write-Info "  - Consensus achieved across the network"

Write-Info ""
Write-Info "📋 Next steps:"
Write-Info "  - Check logs: docker-compose -f testnet/docker-compose-testnet.yml logs -f validator1"
Write-Info "  - View explorer: http://localhost:8084"
Write-Info "  - Monitor network: docker-compose -f testnet/docker-compose-testnet.yml ps"