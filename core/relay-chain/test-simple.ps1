# BlackHole Blockchain Enhanced Network Test

Write-Host "BlackHole Blockchain Enhanced Network Test" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "Building enhanced components..." -ForegroundColor Yellow
go build -o node.exe cmd/relay/main.go
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to build node" -ForegroundColor Red
    exit 1
}

go build -o enhanced-wallet.exe cmd/enhanced-wallet/main.go
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to build enhanced wallet" -ForegroundColor Red
    exit 1
}

Write-Host "Build successful!" -ForegroundColor Green

Write-Host ""
Write-Host "Starting blockchain nodes..." -ForegroundColor Yellow

# Start first node
Write-Host "Starting Node 1 (Port 3000)..." -ForegroundColor Cyan
$node1 = Start-Process -FilePath ".\node.exe" -ArgumentList "3000" -PassThru

# Wait a moment for first node to initialize
Start-Sleep 5

# Start second node
Write-Host "Starting Node 2 (Port 3001)..." -ForegroundColor Cyan
$node2 = Start-Process -FilePath ".\node.exe" -ArgumentList "3001" -PassThru

# Wait for nodes to discover each other
Write-Host ""
Write-Host "Waiting for P2P network formation..." -ForegroundColor Yellow
Start-Sleep 10

Write-Host ""
Write-Host "Network Status:" -ForegroundColor Green
Write-Host "  Node 1 Dashboard: http://localhost:8080" -ForegroundColor White
Write-Host "  Node 2 Dashboard: http://localhost:8081" -ForegroundColor White

Write-Host ""
Write-Host "Features Demonstrated:" -ForegroundColor Yellow
Write-Host "  - Automatic peer discovery via mDNS" -ForegroundColor Green
Write-Host "  - Secure P2P messaging with Ed25519 signatures" -ForegroundColor Green  
Write-Host "  - Network discovery service for wallets" -ForegroundColor Green
Write-Host "  - Enhanced dashboard with peer IDs" -ForegroundColor Green
Write-Host "  - Pub-sub block and transaction propagation" -ForegroundColor Green

Write-Host ""
Write-Host "Test the Enhanced Wallet:" -ForegroundColor Cyan
Write-Host "  1. Open new terminal and run: .\enhanced-wallet.exe" -ForegroundColor White
Write-Host "  2. Select option 1 to discover networks" -ForegroundColor White
Write-Host "  3. Select option 2 to connect to discovered network" -ForegroundColor White
Write-Host "  4. No need to manually enter peer IDs!" -ForegroundColor Green

Write-Host ""
Write-Host "Press any key to stop all nodes..." -ForegroundColor Red
[Console]::ReadKey() | Out-Null

Write-Host ""
Write-Host "Stopping nodes..." -ForegroundColor Red
if ($node1 -and !$node1.HasExited) {
    $node1.Kill()
    Write-Host "  Node 1 stopped" -ForegroundColor Yellow
}
if ($node2 -and !$node2.HasExited) {
    $node2.Kill()
    Write-Host "  Node 2 stopped" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Test completed!" -ForegroundColor Green