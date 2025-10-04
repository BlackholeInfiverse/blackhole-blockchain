# P2P Connectivity Diagnostic Script
param(
    [switch]$Detailed = $false
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  P2P CONNECTIVITY DIAGNOSTIC" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Start blockchain node
Write-Host "[1/5] Starting blockchain node..." -ForegroundColor Yellow
docker-compose down 2>&1 | Out-Null
docker-compose up -d blockchain 2>&1 | Out-Null

# Wait for startup
Write-Host "   Waiting 10 seconds for node initialization..." -ForegroundColor Gray
Start-Sleep -Seconds 10

# Check if container is running
$containerStatus = docker ps --filter "name=blackhole-blockchain" --format "{{.Status}}"
if ($containerStatus -match "healthy|Up") {
    Write-Host "   ✅ Container is running: $containerStatus" -ForegroundColor Green
} else {
    Write-Host "   ❌ Container issue: $containerStatus" -ForegroundColor Red
    docker logs blackhole-blockchain --tail=10
    exit 1
}

# Test HTTP API
Write-Host "[2/5] Testing HTTP API..." -ForegroundColor Yellow
try {
    $nodeInfo = (Invoke-WebRequest -Uri "http://localhost:8081/api/node/info" -TimeoutSec 5).Content | ConvertFrom-Json
    Write-Host "   ✅ API accessible" -ForegroundColor Green
    Write-Host "   Node: $($nodeInfo.name)" -ForegroundColor Gray
    Write-Host "   Network ID: $($nodeInfo.network_id)" -ForegroundColor Gray
    Write-Host "   Secure P2P Peer ID: $($nodeInfo.secure_p2p_peer_id)" -ForegroundColor Cyan
    $peerID = $nodeInfo.secure_p2p_peer_id
} catch {
    Write-Host "   ❌ API not accessible: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Check port bindings
Write-Host "[3/5] Checking port bindings..." -ForegroundColor Yellow
$ports = docker port blackhole-blockchain
Write-Host "   Docker port mappings:" -ForegroundColor Gray
$ports | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }

# Test individual P2P ports
Write-Host "[4/5] Testing P2P port connectivity..." -ForegroundColor Yellow
$testPorts = @(3001, 3100, 30303)
foreach ($port in $testPorts) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.ConnectAsync("127.0.0.1", $port).Wait(1000)
        if ($tcp.Connected) {
            Write-Host "   ✅ Port $port - OPEN" -ForegroundColor Green
            $tcp.Close()
        } else {
            Write-Host "   ❌ Port $port - CLOSED/TIMEOUT" -ForegroundColor Red
        }
    } catch {
        Write-Host "   ❌ Port $port - ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Test wallet connection
Write-Host "[5/5] Testing wallet P2P connection..." -ForegroundColor Yellow

# Build wallet quickly
$walletPath = "core\relay-chain\cmd\enhanced-wallet"
go build -o "$walletPath\enhanced-wallet.exe" "$walletPath\main.go" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "   ❌ Wallet build failed" -ForegroundColor Red
    exit 1
}

# Test basic P2P connection (this simulates what the wallet does)
Write-Host "   Testing P2P addresses for peer: $peerID" -ForegroundColor Gray
$testAddresses = @(
    "127.0.0.1:3001",
    "127.0.0.1:3100", 
    "127.0.0.1:30303"
)

foreach ($addr in $testAddresses) {
    Write-Host "   Testing $addr..." -ForegroundColor Gray
    $parts = $addr.Split(':')
    $ip = $parts[0]
    $port = [int]$parts[1]
    
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $result = $tcp.ConnectAsync($ip, $port).Wait(2000)
        if ($tcp.Connected) {
            Write-Host "      ✅ TCP connection successful" -ForegroundColor Green
            $tcp.Close()
        } else {
            Write-Host "      ❌ TCP connection failed" -ForegroundColor Red
        }
    } catch {
        Write-Host "      ❌ Connection error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan

if ($Detailed) {
    Write-Host "DETAILED DIAGNOSTICS:" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Show container logs
    Write-Host "`nContainer logs (last 20 lines):" -ForegroundColor Yellow
    docker logs blackhole-blockchain --tail=20
    
    # Show network info
    Write-Host "`nDocker network info:" -ForegroundColor Yellow
    docker network ls
    
    # Show processes listening on ports
    Write-Host "`nProcesses on P2P ports:" -ForegroundColor Yellow
    netstat -an | findstr ":3001 :3100 :30303" | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
}

Write-Host "`nNEXT STEPS:" -ForegroundColor Green
Write-Host "  If all tests passed, run the wallet:" -ForegroundColor White
Write-Host "    .\enhanced-wallet.exe" -ForegroundColor Gray
Write-Host ""
Write-Host "  In wallet, try:" -ForegroundColor White
Write-Host "    1. Option 1: Discover networks" -ForegroundColor Gray
Write-Host "    2. Option 5: Manual connect with peer ID:" -ForegroundColor Gray
Write-Host "       $peerID" -ForegroundColor Cyan
Write-Host "    3. Option 7: Send transaction" -ForegroundColor Gray
Write-Host ""

# Leave node running for testing
Write-Host "Blockchain node left running for testing." -ForegroundColor Green
Write-Host "Stop with: docker-compose down" -ForegroundColor Gray
Write-Host ""