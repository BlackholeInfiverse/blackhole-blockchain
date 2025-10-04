# Background Multi-Node BlackHole Blockchain Test
# This script starts the nodes in background for testing purposes

Write-Host "Starting BlackHole Multi-Node Test (Background)" -ForegroundColor Green
Write-Host ""

# Navigate to the blockchain binary directory
Set-Location "../core/relay-chain"

# Build the blockchain binary
Write-Host "Building blockchain binary..." -ForegroundColor Blue
go build -o blockchain.exe ./cmd/relay/main.go

if (!(Test-Path "blockchain.exe")) {
    Write-Host "Failed to build blockchain binary" -ForegroundColor Red
    exit 1
}

Write-Host "Blockchain binary built successfully" -ForegroundColor Green

# Create data directories
Write-Host "Creating node data directories..." -ForegroundColor Blue
$nodes = @("node1", "node2", "node3")
foreach ($node in $nodes) {
    $dataDir = "testnet-data/$node"
    if (Test-Path $dataDir) {
        Remove-Item $dataDir -Recurse -Force
    }
    New-Item -Path $dataDir -ItemType Directory -Force | Out-Null
}

Write-Host "Data directories created" -ForegroundColor Green

# Start Node 1 (Bootstrap node on port 3001) and capture its peer ID
Write-Host ""
Write-Host "Starting Node 1 (Bootstrap)..." -ForegroundColor Blue

# Start node 1 in background and capture output
$node1LogFile = "node1_output.log"
$node1Process = Start-Process -FilePath "./blockchain.exe" -ArgumentList @("3001") -PassThru -WindowStyle Hidden -RedirectStandardOutput $node1LogFile

Start-Sleep 10  # Wait for node to fully start

# Extract the real peer ID from node 1's output
$node1PeerID = $null
$attempts = 0
while ($attempts -lt 5 -and -not $node1PeerID) {
    if (Test-Path $node1LogFile) {
        $output = Get-Content $node1LogFile -ErrorAction SilentlyContinue
        foreach ($line in $output) {
            if ($line -match "Peer ID: (.+)") {
                $node1PeerID = $matches[1]
                break
            }
        }
    }
    if (-not $node1PeerID) {
        Start-Sleep 2
        $attempts++
    }
}

if (-not $node1PeerID) {
    Write-Host "Failed to get Node 1 peer ID after multiple attempts" -ForegroundColor Red
    exit 1
}

Write-Host "Node 1 Peer ID: $node1PeerID" -ForegroundColor Green

# Construct the proper multiaddr for node 1
$node1Multiaddr = "/ip4/127.0.0.1/tcp/3001/p2p/$node1PeerID"
Write-Host "Node 1 multiaddr: $node1Multiaddr" -ForegroundColor Cyan

# Check if Node 1 is running
Start-Sleep 3
$node1ApiPort = $null
for ($port = 8080; $port -le 8084; $port++) {
    try {
        $response = Invoke-RestMethod "http://localhost:$port" -TimeoutSec 2 -ErrorAction Stop
        $node1ApiPort = $port
        break
    } catch { }
}

if ($node1ApiPort) {
    Write-Host "Node 1 is running at http://localhost:$node1ApiPort (P2P: 3001)" -ForegroundColor Green
} else {
    Write-Host "Node 1 failed to start or API not accessible" -ForegroundColor Red
    exit 1
}

# Start Node 2
Write-Host ""
Write-Host "Starting Node 2..." -ForegroundColor Blue
$node2Process = Start-Process -FilePath "./blockchain.exe" -ArgumentList @("3002", $node1Multiaddr) -PassThru -WindowStyle Hidden

Start-Sleep 8

# Check Node 2
$node2ApiPort = $null
for ($port = 8080; $port -le 8084; $port++) {
    if ($port -eq $node1ApiPort) { continue }
    try {
        $response = Invoke-RestMethod "http://localhost:$port" -TimeoutSec 2 -ErrorAction Stop
        $node2ApiPort = $port
        break
    } catch { }
}

if ($node2ApiPort) {
    Write-Host "Node 2 is running at http://localhost:$node2ApiPort (P2P: 3002)" -ForegroundColor Green
} else {
    Write-Host "Node 2 failed to start properly" -ForegroundColor Yellow
}

# Start Node 3
Write-Host ""
Write-Host "Starting Node 3..." -ForegroundColor Blue
$node3Process = Start-Process -FilePath "./blockchain.exe" -ArgumentList @("3003", $node1Multiaddr) -PassThru -WindowStyle Hidden

Start-Sleep 8

# Check Node 3
$node3ApiPort = $null
for ($port = 8080; $port -le 8084; $port++) {
    if ($port -eq $node1ApiPort -or $port -eq $node2ApiPort) { continue }
    try {
        $response = Invoke-RestMethod "http://localhost:$port" -TimeoutSec 2 -ErrorAction Stop
        $node3ApiPort = $port
        break
    } catch { }
}

if ($node3ApiPort) {
    Write-Host "Node 3 is running at http://localhost:$node3ApiPort (P2P: 3003)" -ForegroundColor Green
} else {
    Write-Host "Node 3 failed to start properly" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Multi-Node BlackHole Testnet Started!" -ForegroundColor Green
Write-Host ""
Write-Host "Node Endpoints:" -ForegroundColor Blue
if ($node1ApiPort) { Write-Host "  Node 1: http://localhost:$node1ApiPort (P2P: 3001)" }
if ($node2ApiPort) { Write-Host "  Node 2: http://localhost:$node2ApiPort (P2P: 3002)" }
if ($node3ApiPort) { Write-Host "  Node 3: http://localhost:$node3ApiPort (P2P: 3003)" }
Write-Host ""
Write-Host "Node 1 Multiaddr for wallet: $node1Multiaddr" -ForegroundColor Cyan
Write-Host ""

# Save connection info for wallet service
$connectionInfo = @{
    node1_multiaddr = $node1Multiaddr
    node1_api = "http://localhost:$node1ApiPort"
    node2_api = if ($node2ApiPort) { "http://localhost:$node2ApiPort" } else { $null }
    node3_api = if ($node3ApiPort) { "http://localhost:$node3ApiPort" } else { $null }
    node1_process_id = $node1Process.Id
    node2_process_id = if ($node2Process) { $node2Process.Id } else { $null }
    node3_process_id = if ($node3Process) { $node3Process.Id } else { $null }
} | ConvertTo-Json

$connectionInfo | Out-File -FilePath "multinode_connection_info.json" -Encoding UTF8

Write-Host "Connection info saved to multinode_connection_info.json" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Blue
Write-Host "1. Start wallet service: cd ../services/wallet && go run main.go -web -port 9000 -peerAddr `"$node1Multiaddr`""
Write-Host "2. Open wallet UI: http://localhost:9000"
Write-Host "3. Create transactions and test cross-node propagation"
Write-Host ""
Write-Host "To stop all nodes later: Get-Process blockchain | Stop-Process -Force"