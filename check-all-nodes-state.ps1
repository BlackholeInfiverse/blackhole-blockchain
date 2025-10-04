# Multi-Node Blockchain State Checker
param(
    [switch]$Detailed
)

Write-Host "🌐 Multi-Node Blockchain State Check" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

$nodes = @(
    @{ Name = "Node1"; Port = "8081"; P2PPort = "3001" },
    @{ Name = "Node2"; Port = "8082"; P2PPort = "3002" },
    @{ Name = "Node3"; Port = "8083"; P2PPort = "3003" },
    @{ Name = "Node4"; Port = "8084"; P2PPort = "3004" },
    @{ Name = "Node5"; Port = "8085"; P2PPort = "3005" }
)

$results = @()

foreach ($node in $nodes) {
    Write-Host "`n[$($node.Name)] Checking http://localhost:$($node.Port)..." -ForegroundColor Yellow
    
    try {
        # Get blockchain info
        $response = Invoke-WebRequest -Uri "http://localhost:$($node.Port)/api/blockchain/info" -UseBasicParsing -TimeoutSec 5
        $info = $response.Content | ConvertFrom-Json
        
        # Get node P2P info
        $nodeResponse = Invoke-WebRequest -Uri "http://localhost:$($node.Port)/api/node/info" -UseBasicParsing -TimeoutSec 5
        $nodeInfo = $nodeResponse.Content | ConvertFrom-Json
        
        $result = [PSCustomObject]@{
            NodeName = $node.Name
            Port = $node.Port
            Status = "✅ Online"
            BlockHeight = $info.blockHeight
            PendingTxs = $info.pendingTxs
            TotalSupply = $info.totalSupply
            ConnectedPeers = $nodeInfo.secure_p2p.connected_peers
            PeerID = $nodeInfo.secure_p2p.peer_id
            RecentBlocks = $info.recentBlocks.Count
        }
        
        $results += $result
        
        Write-Host "   ✅ Status: Online" -ForegroundColor Green
        Write-Host "   📊 Block Height: $($info.blockHeight)" -ForegroundColor White
        Write-Host "   📤 Pending Txs: $($info.pendingTxs)" -ForegroundColor White
        Write-Host "   🔗 Connected Peers: $($nodeInfo.secure_p2p.connected_peers)" -ForegroundColor White
        
        if ($Detailed) {
            Write-Host "   🆔 Peer ID: $($nodeInfo.secure_p2p.peer_id)" -ForegroundColor Gray
            Write-Host "   💰 Total Supply: $($info.totalSupply)" -ForegroundColor Gray
            
            if ($info.recentBlocks -and $info.recentBlocks.Count -gt 0) {
                Write-Host "   🔗 Recent Blocks:" -ForegroundColor Gray
                $info.recentBlocks | Sort-Object index -Descending | Select-Object -First 3 | ForEach-Object {
                    Write-Host "      Block $($_.index): $($_.txCount) txs - $($_.validator)" -ForegroundColor DarkGray
                }
            }
        }
        
    } catch {
        $result = [PSCustomObject]@{
            NodeName = $node.Name
            Port = $node.Port
            Status = "❌ Offline"
            BlockHeight = "N/A"
            PendingTxs = "N/A"
            TotalSupply = "N/A"
            ConnectedPeers = "N/A"
            PeerID = "N/A"
            RecentBlocks = "N/A"
        }
        
        $results += $result
        Write-Host "   ❌ Status: Offline or Error" -ForegroundColor Red
        Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n📊 CONSENSUS SUMMARY" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan

# Check for consensus
$onlineNodes = $results | Where-Object { $_.Status -eq "✅ Online" }
$blockHeights = $onlineNodes.BlockHeight | Group-Object
$totalSupplies = $onlineNodes.TotalSupply | Group-Object

Write-Host "Online Nodes: $($onlineNodes.Count)/$($results.Count)" -ForegroundColor White
Write-Host "Block Height Distribution:" -ForegroundColor White
foreach ($height in $blockHeights) {
    $color = if ($height.Count -eq $onlineNodes.Count) { "Green" } else { "Yellow" }
    Write-Host "   Height $($height.Name): $($height.Count) nodes" -ForegroundColor $color
}

Write-Host "Total Supply Distribution:" -ForegroundColor White  
foreach ($supply in $totalSupplies) {
    $color = if ($supply.Count -eq $onlineNodes.Count) { "Green" } else { "Yellow" }
    Write-Host "   Supply $($supply.Name): $($supply.Count) nodes" -ForegroundColor $color
}

# Network connectivity summary
$totalConnections = ($onlineNodes.ConnectedPeers | Measure-Object -Sum).Sum
$avgConnections = if ($onlineNodes.Count -gt 0) { [math]::Round($totalConnections / $onlineNodes.Count, 1) } else { 0 }

Write-Host "Network Connectivity:" -ForegroundColor White
Write-Host "   Total P2P Connections: $totalConnections" -ForegroundColor White
Write-Host "   Average per Node: $avgConnections" -ForegroundColor White

# Consensus check
$consensusHeight = $blockHeights | Where-Object { $_.Count -eq $onlineNodes.Count }
$consensusSupply = $totalSupplies | Where-Object { $_.Count -eq $onlineNodes.Count }

if ($consensusHeight -and $consensusSupply) {
    Write-Host "`n🎉 CONSENSUS ACHIEVED!" -ForegroundColor Green
    Write-Host "   All $($onlineNodes.Count) nodes agree on:" -ForegroundColor Green
    Write-Host "   - Block Height: $($consensusHeight.Name)" -ForegroundColor Green
    Write-Host "   - Total Supply: $($consensusSupply.Name)" -ForegroundColor Green
} else {
    Write-Host "`n⚠️  CONSENSUS ISSUES DETECTED!" -ForegroundColor Red
    if (-not $consensusHeight) {
        Write-Host "   Block heights differ across nodes" -ForegroundColor Red
    }
    if (-not $consensusSupply) {
        Write-Host "   Total supplies differ across nodes" -ForegroundColor Red
    }
}

Write-Host "`nDetailed Node Status:" -ForegroundColor Cyan
$results | Format-Table -AutoSize

return $results