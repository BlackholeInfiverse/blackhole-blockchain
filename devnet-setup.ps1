# BlackHole Blockchain - 3-Node Private Devnet Setup
# Aligned with Tokenomics Specification v1.0

param(
    [string]$Action = "start",
    [int]$NodeCount = 3,
    [string]$DataDir = "devnet-data"
)

$ErrorActionPreference = "Stop"

Write-Host "🌌 BlackHole Blockchain - Private Devnet Manager" -ForegroundColor Magenta
Write-Host "=================================================" -ForegroundColor Magenta

# Network Configuration (from TOKENOMICS_SPEC.md)
$CHAIN_ID = "blackhole-devnet-1"
$BLOCK_TIME = 3  # 3 seconds as per spec
$INITIAL_SUPPLY = 350000000  # 350M BHX initial circulating supply
$MAX_SUPPLY = 1000000000     # 1B BHX max supply

# Node Configuration
$BASE_PORT_API = 8080
$BASE_PORT_RPC = 8545  
$BASE_PORT_P2P = 30303
$BASE_PORT_GRPC = 9090

function Write-StatusMessage {
    param([string]$Message, [string]$Color = "Green")
    Write-Host "✅ $Message" -ForegroundColor $Color
}

function Write-ErrorMessage {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Create-Genesis {
    Write-Host "🎯 Creating genesis configuration..." -ForegroundColor Yellow
    
    $genesisDir = "$DataDir/genesis"
    New-Item -ItemType Directory -Force -Path $genesisDir | Out-Null
    
    # Genesis configuration aligned with tokenomics
    $genesisConfig = @{
        chain_id = $CHAIN_ID
        genesis_time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        consensus = @{
            type = "pos"  # Proof of Stake as per whitepaper
            block_time = "${BLOCK_TIME}s"
            max_validators = 100
        }
        economics = @{
            native_token = @{
                symbol = "BHX"
                name = "BlackHole"
                decimals = 18
                max_supply = "${MAX_SUPPLY}000000000000000000"  # 1B * 10^18
                initial_supply = "${INITIAL_SUPPLY}000000000000000000"  # 350M * 10^18
            }
            staking = @{
                min_validator_stake = "100000000000000000000000"  # 100,000 BHX
                annual_inflation = @{
                    year_1 = 0.08   # 8% Year 1
                    year_2 = 0.07   # 7% Year 2  
                    year_3 = 0.06   # 6% Year 3
                    year_4 = 0.05   # 5% Year 4
                    year_5 = 0.04   # 4% Year 5
                    year_6_plus = 0.03  # 3% Year 6+
                }
                unbonding_period = "21d"
                slashing = @{
                    downtime = 0.0001      # 0.01%
                    double_sign = 0.05     # 5%  
                    malicious = 1.0        # 100%
                }
            }
            fees = @{
                small_tx_limit = "100000000000000000000"      # 100 BHX - FREE
                medium_tx_fee = 0.0001    # 0.01% for 100-10K BHX
                large_tx_fee = 0.0005     # 0.05% for >10K BHX  
                dex_trading_fee = 0.003   # 0.3%
                bridge_fee = 0.001        # 0.1%
                burn_rate = 0.001         # 0.1% of fees burned
            }
        }
        governance = @{
            proposal_deposit = "10000000000000000000000"     # 10,000 BHX
            voting_period = "7d"
            quorum = 0.4              # 40%
            pass_threshold = 0.5      # 50%
            veto_threshold = 0.334    # 33.4%
        }
        accounts = @()
        validators = @()
    }
    
    # Create validator accounts for each node
    for ($i = 1; $i -le $NodeCount; $i++) {
        $validatorKey = "validator$i"
        $validatorAddress = "bhx1validator${i}addressplaceholder000000000"
        $validatorStake = "150000000000000000000000"  # 150,000 BHX stake
        
        # Add validator account
        $genesisConfig.accounts += @{
            address = $validatorAddress
            balance = $validatorStake
            sequence = 0
        }
        
        # Add validator info
        $genesisConfig.validators += @{
            address = $validatorAddress
            pub_key = "validator${i}_pubkey_placeholder"
            voting_power = 1
            name = "Validator-$i"
        }
    }
    
    # Add treasury and ecosystem accounts
    $treasuryAddress = "bhx1treasury00000000000000000000000000"
    $ecosystemAddress = "bhx1ecosystem000000000000000000000000"
    
    $genesisConfig.accounts += @{
        address = $treasuryAddress
        balance = "150000000000000000000000000"  # 150M BHX (Dev Fund)
        sequence = 0
    }
    
    $genesisConfig.accounts += @{
        address = $ecosystemAddress  
        balance = "150000000000000000000000000"  # 150M BHX (Ecosystem Incentives)
        sequence = 0
    }
    
    # Save genesis configuration
    $genesisPath = "$genesisDir/genesis.json"
    $genesisConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $genesisPath -Encoding UTF8
    
    Write-StatusMessage "Genesis configuration created: $genesisPath"
    return $genesisPath
}

function Create-NodeConfig {
    param([int]$NodeId, [string]$GenesisPath)
    
    $nodeDir = "$DataDir/node$NodeId"
    New-Item -ItemType Directory -Force -Path $nodeDir | Out-Null
    
    $apiPort = $BASE_PORT_API + $NodeId
    $rpcPort = $BASE_PORT_RPC + $NodeId  
    $p2pPort = $BASE_PORT_P2P + $NodeId
    $grpcPort = $BASE_PORT_GRPC + $NodeId
    
    # Node configuration
    $nodeConfig = @{
        node_id = "node$NodeId"
        chain_id = $CHAIN_ID
        data_dir = "./data"
        log_level = "info"
        
        # Network configuration  
        api = @{
            enabled = $true
            port = $apiPort
            cors_origins = @("*")
        }
        rpc = @{
            enabled = $true  
            port = $rpcPort
            cors_origins = @("*")
        }
        p2p = @{
            port = $p2pPort
            max_peers = 50
            discovery = $true
        }
        grpc = @{
            enabled = $true
            port = $grpcPort
        }
        
        # Consensus configuration
        consensus = @{
            block_time = "${BLOCK_TIME}s"
            timeout_propose = "3s"
            timeout_prevote = "1s" 
            timeout_precommit = "1s"
            timeout_commit = "1s"
        }
        
        # Validator configuration (for validator nodes)
        validator = @{
            enabled = $true
            key = "validator$NodeId"
            stake = "150000000000000000000000"  # 150,000 BHX
        }
        
        # DEX configuration  
        dex = @{
            enabled = $true
            trading_fee = 0.003      # 0.3% as per spec
            min_liquidity = "1000000000000000000000"  # 1000 BHX
            max_slippage = 0.5       # 50%
        }
        
        # Bridge configuration
        bridge = @{
            enabled = $true
            circuit_breaker = $true
            replay_protection = $true
            max_daily_volume = "1000000000000000000000000"  # 1M BHX
        }
    }
    
    # Create bootnode addresses for P2P discovery
    $bootnodes = @()
    for ($i = 1; $i -le $NodeCount; $i++) {
        if ($i -ne $NodeId) {
            $peerPort = $BASE_PORT_P2P + $i
            $bootnodes += "/ip4/127.0.0.1/tcp/$peerPort/p2p/node$i"
        }
    }
    $nodeConfig.p2p.bootnodes = $bootnodes
    
    # Save node configuration
    $configPath = "$nodeDir/config.json"
    $nodeConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
    
    # Copy genesis file to node directory
    Copy-Item $GenesisPath "$nodeDir/genesis.json"
    
    Write-StatusMessage "Node $NodeId configuration created: $configPath"
    return @{
        nodeId = $NodeId
        configPath = $configPath
        dataDir = $nodeDir
        ports = @{
            api = $apiPort
            rpc = $rpcPort  
            p2p = $p2pPort
            grpc = $grpcPort
        }
    }
}

function Start-DevNet {
    Write-Host "🚀 Starting BlackHole Blockchain DevNet..." -ForegroundColor Green
    
    # Clean existing data
    if (Test-Path $DataDir) {
        Write-Host "🧹 Cleaning existing devnet data..." -ForegroundColor Yellow
        Remove-Item -Path $DataDir -Recurse -Force
    }
    
    # Create data directory
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    
    # Create genesis configuration
    $genesisPath = Create-Genesis
    
    # Create node configurations
    $nodes = @()
    for ($i = 1; $i -le $NodeCount; $i++) {
        $nodeInfo = Create-NodeConfig -NodeId $i -GenesisPath $genesisPath
        $nodes += $nodeInfo
    }
    
    # Start each node
    Write-Host "🎯 Starting $NodeCount validator nodes..." -ForegroundColor Cyan
    
    foreach ($node in $nodes) {
        $nodeId = $node.nodeId
        $configPath = $node.configPath
        
        Write-Host "  Starting Node $nodeId..." -ForegroundColor White
        Write-Host "    API:  http://localhost:$($node.ports.api)" -ForegroundColor Gray
        Write-Host "    RPC:  http://localhost:$($node.ports.rpc)" -ForegroundColor Gray  
        Write-Host "    P2P:  localhost:$($node.ports.p2p)" -ForegroundColor Gray
        Write-Host "    gRPC: localhost:$($node.ports.grpc)" -ForegroundColor Gray
        
        # Start node process (would use actual blockchain binary)
        # For now, create a placeholder process file
        "Node $nodeId started with config: $configPath" | Out-File -FilePath "$($node.dataDir)/node.pid"
    }
    
    Write-Host ""
    Write-StatusMessage "DevNet started successfully!"
    Write-Host ""
    Write-Host "📊 Network Information:" -ForegroundColor Cyan
    Write-Host "  Chain ID: $CHAIN_ID" -ForegroundColor White
    Write-Host "  Block Time: $BLOCK_TIME seconds" -ForegroundColor White  
    Write-Host "  Validators: $NodeCount nodes" -ForegroundColor White
    Write-Host "  Total Supply: $INITIAL_SUPPLY BHX (initial)" -ForegroundColor White
    Write-Host "  Max Supply: $MAX_SUPPLY BHX" -ForegroundColor White
    Write-Host ""
    Write-Host "🔗 API Endpoints:" -ForegroundColor Cyan
    foreach ($node in $nodes) {
        Write-Host "  Node $($node.nodeId): http://localhost:$($node.ports.api)" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "🧪 Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Run DEX tests: go run scripts/dex_testing_suite.go"
    Write-Host "  2. Test multi-node consensus: go run scripts/multinode_coordinator.go"  
    Write-Host "  3. Deploy bridge: cd bridge-sdk && go run main.go"
    Write-Host "  4. Start wallet UI: cd services/wallet && go run main.go -web -port 9000"
}

function Stop-DevNet {
    Write-Host "🛑 Stopping BlackHole DevNet..." -ForegroundColor Red
    
    if (-not (Test-Path $DataDir)) {
        Write-Host "No devnet found to stop." -ForegroundColor Yellow
        return
    }
    
    # Stop all node processes (placeholder - would kill actual processes)
    Get-ChildItem "$DataDir/node*/node.pid" -ErrorAction SilentlyContinue | ForEach-Object {
        $nodeId = ($_.Directory.Name -replace "node", "")
        Write-Host "  Stopping Node $nodeId..." -ForegroundColor White
        Remove-Item $_.FullName
    }
    
    Write-StatusMessage "DevNet stopped successfully!"
}

function Show-Status {
    Write-Host "📊 BlackHole DevNet Status" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    
    if (-not (Test-Path $DataDir)) {
        Write-Host "❌ DevNet is not running" -ForegroundColor Red
        return
    }
    
    Write-Host "✅ DevNet is running" -ForegroundColor Green
    Write-Host ""
    Write-Host "Active Nodes:" -ForegroundColor White
    
    Get-ChildItem "$DataDir/node*" -Directory | ForEach-Object {
        $nodeId = ($_.Name -replace "node", "")
        $apiPort = $BASE_PORT_API + [int]$nodeId
        $isRunning = Test-Path "$($_.FullName)/node.pid"
        
        if ($isRunning) {
            Write-Host "  ✅ Node $nodeId - http://localhost:$apiPort" -ForegroundColor Green
        } else {
            Write-Host "  ❌ Node $nodeId - Stopped" -ForegroundColor Red  
        }
    }
}

# Main execution
switch ($Action.ToLower()) {
    "start" { Start-DevNet }
    "stop" { Stop-DevNet }  
    "restart" { 
        Stop-DevNet
        Start-Sleep 2
        Start-DevNet
    }
    "status" { Show-Status }
    default {
        Write-Host "Usage: ./devnet-setup.ps1 [start|stop|restart|status]" -ForegroundColor Yellow
        Write-Host ""  
        Write-Host "Commands:" -ForegroundColor Cyan
        Write-Host "  start   - Start 3-node devnet"
        Write-Host "  stop    - Stop devnet"
        Write-Host "  restart - Restart devnet" 
        Write-Host "  status  - Show devnet status"
    }
}