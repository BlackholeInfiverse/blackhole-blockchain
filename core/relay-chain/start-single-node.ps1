# Simple Single Node Startup for Testing
# This starts just one node so you can test wallet connectivity

Write-Host "Starting Single BlackHole Blockchain Node" -ForegroundColor Green
Write-Host ""

# Build the blockchain binary
Write-Host "Building blockchain binary..." -ForegroundColor Blue
go build -o blockchain.exe ./cmd/relay/main.go

if (!(Test-Path "blockchain.exe")) {
    Write-Host "Failed to build blockchain binary" -ForegroundColor Red
    exit 1
}

Write-Host "Blockchain binary built successfully" -ForegroundColor Green

# Clean up old data
if (Test-Path "testnet-data") {
    Remove-Item testnet-data -Recurse -Force
}
if (Test-Path "blockchaindb_3001") {
    Remove-Item blockchaindb_3001 -Recurse -Force
}

Write-Host ""
Write-Host "Starting Node on port 3001..." -ForegroundColor Blue

# Start the node (this will run in foreground so you can see the output)
Write-Host "Starting blockchain node - you should see the peer ID below:" -ForegroundColor Cyan
Write-Host ""

# Run the blockchain node
.\blockchain.exe 3001