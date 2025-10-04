# Test Wallet Connectivity
Write-Host "BlackHole Wallet Connectivity Test" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan

# Build components
Write-Host "Building components..." -ForegroundColor Yellow
go build -o node.exe cmd/relay/main.go
go build -o enhanced-wallet.exe cmd/enhanced-wallet/main.go

# Start a test node
Write-Host "Starting test node on port 3000..." -ForegroundColor Green
$node = Start-Process -FilePath ".\node.exe" -ArgumentList "3000" -PassThru

# Wait for node to initialize
Write-Host "Waiting for node to initialize..." -ForegroundColor Yellow
Start-Sleep 8

Write-Host ""
Write-Host "Node is running. You can now:" -ForegroundColor Green
Write-Host "1. View dashboard at: http://localhost:8080" -ForegroundColor White
Write-Host "2. Copy the Secure P2P Peer ID from dashboard" -ForegroundColor White
Write-Host "3. Test the enhanced wallet:" -ForegroundColor White
Write-Host "   - Run: .\enhanced-wallet.exe" -ForegroundColor Cyan
Write-Host "   - Option 1: Discover networks (should find the running node)" -ForegroundColor Cyan
Write-Host "   - Option 2: Connect to discovered network" -ForegroundColor Cyan
Write-Host "   - Option 5: Manual connection using copied peer ID" -ForegroundColor Cyan

Write-Host ""
Write-Host "Key Improvements Made:" -ForegroundColor Magenta
Write-Host "- Fixed Docker Go version (now uses Go 1.23)" -ForegroundColor White
Write-Host "- Created real P2P wallet client with libp2p" -ForegroundColor White
Write-Host "- Added network discovery via UDP broadcast" -ForegroundColor White
Write-Host "- Enhanced wallet with connection management" -ForegroundColor White
Write-Host "- Added peer ID copying on dashboard" -ForegroundColor White
Write-Host "- Fixed wallet connectivity to blockchain nodes" -ForegroundColor White

Write-Host ""
Write-Host "Press Enter to stop the test node..."
Read-Host

if ($node -and !$node.HasExited) {
    $node.Kill()
    Write-Host "Test node stopped" -ForegroundColor Yellow
}

Write-Host "Test completed!" -ForegroundColor Green