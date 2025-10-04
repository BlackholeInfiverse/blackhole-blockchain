# Comprehensive P2P Transaction Test Script
param(
    [switch]$RebuildDocker = $false,
    [switch]$SkipBuild = $false
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  P2P Transaction Test - BlackHole" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = "C:\Users\pc2\Desktop\Qoder\blackhole-blockchain"
$WalletPath = "$ProjectRoot\core\relay-chain\cmd\enhanced-wallet"

# Change to project directory
Set-Location $ProjectRoot

# Step 1: Rebuild Docker if requested
if ($RebuildDocker) {
    Write-Host "[1/6] Rebuilding Docker containers..." -ForegroundColor Yellow
    docker-compose down 2>&1 | Out-Null
    docker-compose build --no-cache 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Docker build failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "   Docker build successful" -ForegroundColor Green
} else {
    Write-Host "[1/6] Skipping Docker rebuild (use -RebuildDocker to rebuild)" -ForegroundColor Gray
}

# Step 2: Start blockchain node
Write-Host "[2/6] Starting blockchain node..." -ForegroundColor Yellow
docker-compose up -d blockchain 2>&1 | Out-Null

# Wait for node to be ready
Write-Host "   Waiting for blockchain node to initialize..." -ForegroundColor Gray
$maxWait = 30
$waited = 0
$nodeReady = $false

while ($waited -lt $maxWait) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8081/api/node/info" -TimeoutSec 2 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $nodeReady = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 1
        $waited++
    }
}

if ($nodeReady) {
    Write-Host "   Blockchain node is ready!" -ForegroundColor Green
    
    # Get node info
    try {
        $nodeInfo = (Invoke-WebRequest -Uri "http://localhost:8081/api/node/info").Content | ConvertFrom-Json
        Write-Host "   Node Name: $($nodeInfo.name)" -ForegroundColor Gray
        Write-Host "   Network ID: $($nodeInfo.network_id)" -ForegroundColor Gray
        Write-Host "   Secure P2P Peer ID: $($nodeInfo.secure_p2p_peer_id)" -ForegroundColor Cyan
        $peerID = $nodeInfo.secure_p2p_peer_id
    } catch {
        Write-Host "   Warning: Could not fetch node details" -ForegroundColor Yellow
    }
} else {
    Write-Host "ERROR: Blockchain node failed to start within $maxWait seconds" -ForegroundColor Red
    docker-compose logs blockchain
    exit 1
}

# Step 3: Build wallet if needed
if (!$SkipBuild) {
    Write-Host "[3/6] Building enhanced wallet..." -ForegroundColor Yellow
    $binaryPath = "$WalletPath\enhanced-wallet.exe"
    if (Test-Path $binaryPath) {
        Remove-Item $binaryPath -Force
    }
    
    go build -o $binaryPath "$WalletPath\main.go" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Wallet build failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "   Wallet built successfully" -ForegroundColor Green
} else {
    Write-Host "[3/6] Skipping wallet build (use without -SkipBuild to rebuild)" -ForegroundColor Gray
}

# Step 4: Test wallet discovery
Write-Host "[4/6] Testing wallet network discovery..." -ForegroundColor Yellow

# Create a test script that will run wallet commands automatically
$testScript = @"
Write-Host "Starting wallet discovery test..." -ForegroundColor Cyan

# Import the wallet module (this is pseudo-code, actual implementation needed)
# For now, we'll test manually

Write-Host "Please follow these steps in the wallet:" -ForegroundColor Yellow
Write-Host "1. Choose option '1' - Discover available networks" -ForegroundColor White
Write-Host "2. Choose option '2' - Connect to a network" -ForegroundColor White  
Write-Host "3. Choose option '5' - Manual network connection (if needed)" -ForegroundColor White
Write-Host "4. Enter peer ID: $peerID" -ForegroundColor White
Write-Host ""
Write-Host "After connecting, we'll test sending a transaction..." -ForegroundColor Cyan
"@

Write-Host $testScript

# Step 5: Start wallet interactively
Write-Host "[5/6] Starting enhanced wallet..." -ForegroundColor Yellow
Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "  WALLET INSTRUCTIONS" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To test P2P transactions:" -ForegroundColor White
Write-Host ""
Write-Host "1. Option '1': Discover networks" -ForegroundColor Yellow
Write-Host "   - Should find the blockchain node" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Option '2' OR '5': Connect" -ForegroundColor Yellow
Write-Host "   - Use discovered network OR" -ForegroundColor Gray
Write-Host "   - Manual connect with Peer ID:" -ForegroundColor Gray
Write-Host "     $peerID" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Option '3': Verify connection" -ForegroundColor Yellow
Write-Host "   - Check you're connected" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Option '6': View wallet info" -ForegroundColor Yellow
Write-Host "   - See your wallet details" -ForegroundColor Gray
Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Starting wallet now..." -ForegroundColor Green
Write-Host ""

# Run the wallet
& "$WalletPath\enhanced-wallet.exe"

# Step 6: Cleanup prompt
Write-Host ""
Write-Host "[6/6] Test complete!" -ForegroundColor Green
Write-Host ""
$cleanup = Read-Host "Stop blockchain node? (y/N)"
if ($cleanup -eq "y" -or $cleanup -eq "Y") {
    Write-Host "Stopping blockchain node..." -ForegroundColor Yellow
    docker-compose down 2>&1 | Out-Null
    Write-Host "   Stopped" -ForegroundColor Green
} else {
    Write-Host "Blockchain node still running. Stop with: docker-compose down" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  P2P Test Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan