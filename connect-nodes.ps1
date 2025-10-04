# Script to connect Docker nodes to form a proper network
# Run this after starting the multinode Docker setup

Write-Host "Connecting Docker blockchain nodes..." -ForegroundColor Green

# Node 1 info (bootstrap node)
$node1PeerID = "12D3KooWGuHTwdwDkW4w3P4f7rw1771DnRSUMTwZeQKZ9hHYTDNi"
$node1ContainerIP = "172.18.0.2"
$node1Multiaddr = "/ip4/$node1ContainerIP/tcp/3001/p2p/$node1PeerID"

Write-Host "Node 1 multiaddr: $node1Multiaddr" -ForegroundColor Cyan

# Test if nodes are accessible
$nodes = @{
    "Node 1" = "http://localhost:8080"
    "Node 2" = "http://localhost:8081" 
    "Node 3" = "http://localhost:8082"
}

foreach ($node in $nodes.GetEnumerator()) {
    try {
        $response = Invoke-RestMethod "$($node.Value)/api/health" -TimeoutSec 3
        Write-Host "✅ $($node.Key) is healthy" -ForegroundColor Green
    } catch {
        Write-Host "❌ $($node.Key) not accessible: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Connect Node 2 to Node 1
Write-Host ""
Write-Host "Connecting Node 2 to Node 1..." -ForegroundColor Blue
try {
    $connectionData = @{
        peer_address = $node1Multiaddr
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod "http://localhost:8081/api/dev/connect-peer" -Method POST -Body $connectionData -ContentType "application/json" -TimeoutSec 5
    Write-Host "✅ Node 2 connected to Node 1" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Node 2 connection attempt: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Connect Node 3 to Node 1  
Write-Host "Connecting Node 3 to Node 1..." -ForegroundColor Blue
try {
    $connectionData = @{
        peer_address = $node1Multiaddr
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod "http://localhost:8082/api/dev/connect-peer" -Method POST -Body $connectionData -ContentType "application/json" -TimeoutSec 5
    Write-Host "✅ Node 3 connected to Node 1" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Node 3 connection attempt: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Connection attempts completed!" -ForegroundColor Green
Write-Host ""
Write-Host "Now test transactions between nodes:" -ForegroundColor Blue
Write-Host "1. Add tokens to an address on one node"
Write-Host "2. Check if the balance appears on other nodes"
Write-Host "3. Try transfers from different nodes"
Write-Host ""
Write-Host "Node URLs:" -ForegroundColor Blue
Write-Host "  Node 1: http://localhost:8080"
Write-Host "  Node 2: http://localhost:8081" 
Write-Host "  Node 3: http://localhost:8082"