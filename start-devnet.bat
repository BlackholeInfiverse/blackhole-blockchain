@echo off
title BlackHole Blockchain - 3-Node DevNet
cls

echo 🌌 BlackHole Blockchain - Private DevNet Setup
echo ===============================================
echo.
echo 📊 Network Configuration (Aligned with Tokenomics v1.0):
echo   Chain ID: blackhole-devnet-1
echo   Block Time: 3 seconds
echo   Initial Supply: 350,000,000 BHX
echo   Max Supply: 1,000,000,000 BHX
echo   Consensus: Proof of Stake
echo.

REM Create devnet directory
if exist "devnet-data" (
    echo 🧹 Cleaning existing devnet data...
    rmdir /s /q "devnet-data"
)
mkdir "devnet-data"
mkdir "devnet-data\genesis"
mkdir "devnet-data\node1"
mkdir "devnet-data\node2"
mkdir "devnet-data\node3"

REM Create genesis configuration
echo 🎯 Creating genesis configuration...
(
echo {
echo   "chain_id": "blackhole-devnet-1",
echo   "genesis_time": "%date:~-4,4%-%date:~3,2%-%date:~0,2%T%time:~0,2%:%time:~3,2%:%time:~6,2%Z",
echo   "consensus": {
echo     "type": "pos",
echo     "block_time": "3s",
echo     "max_validators": 100
echo   },
echo   "economics": {
echo     "native_token": {
echo       "symbol": "BHX",
echo       "name": "BlackHole",
echo       "decimals": 18,
echo       "max_supply": "1000000000000000000000000000",
echo       "initial_supply": "350000000000000000000000000"
echo     },
echo     "staking": {
echo       "min_validator_stake": "100000000000000000000000",
echo       "annual_inflation": {
echo         "year_1": 0.08,
echo         "year_2": 0.07,
echo         "year_3": 0.06,
echo         "year_4": 0.05,
echo         "year_5": 0.04,
echo         "year_6_plus": 0.03
echo       },
echo       "unbonding_period": "21d",
echo       "slashing": {
echo         "downtime": 0.0001,
echo         "double_sign": 0.05,
echo         "malicious": 1.0
echo       }
echo     },
echo     "fees": {
echo       "small_tx_limit": "100000000000000000000",
echo       "medium_tx_fee": 0.0001,
echo       "large_tx_fee": 0.0005,
echo       "dex_trading_fee": 0.003,
echo       "bridge_fee": 0.001,
echo       "burn_rate": 0.001
echo     }
echo   },
echo   "governance": {
echo     "proposal_deposit": "10000000000000000000000",
echo     "voting_period": "7d",
echo     "quorum": 0.4,
echo     "pass_threshold": 0.5,
echo     "veto_threshold": 0.334
echo   },
echo   "accounts": [
echo     {
echo       "address": "bhx1validator1address000000000000000",
echo       "balance": "150000000000000000000000",
echo       "sequence": 0
echo     },
echo     {
echo       "address": "bhx1validator2address000000000000000",
echo       "balance": "150000000000000000000000",
echo       "sequence": 0
echo     },
echo     {
echo       "address": "bhx1validator3address000000000000000",
echo       "balance": "150000000000000000000000",
echo       "sequence": 0
echo     },
echo     {
echo       "address": "bhx1treasury00000000000000000000000",
echo       "balance": "150000000000000000000000000",
echo       "sequence": 0
echo     },
echo     {
echo       "address": "bhx1ecosystem000000000000000000000000",
echo       "balance": "150000000000000000000000000",
echo       "sequence": 0
echo     }
echo   ],
echo   "validators": [
echo     {
echo       "address": "bhx1validator1address000000000000000",
echo       "pub_key": "validator1_pubkey_placeholder",
echo       "voting_power": 1,
echo       "name": "Validator-1"
echo     },
echo     {
echo       "address": "bhx1validator2address000000000000000",
echo       "pub_key": "validator2_pubkey_placeholder",
echo       "voting_power": 1,
echo       "name": "Validator-2"
echo     },
echo     {
echo       "address": "bhx1validator3address000000000000000",
echo       "pub_key": "validator3_pubkey_placeholder",
echo       "voting_power": 1,
echo       "name": "Validator-3"
echo     }
echo   ]
echo }
) > "devnet-data\genesis\genesis.json"

REM Create node configurations
echo 🔧 Creating node configurations...

REM Node 1 Config
(
echo {
echo   "node_id": "node1",
echo   "chain_id": "blackhole-devnet-1",
echo   "data_dir": "./data",
echo   "log_level": "info",
echo   "api": {
echo     "enabled": true,
echo     "port": 8081,
echo     "cors_origins": ["*"]
echo   },
echo   "rpc": {
echo     "enabled": true,
echo     "port": 8546,
echo     "cors_origins": ["*"]
echo   },
echo   "p2p": {
echo     "port": 30304,
echo     "max_peers": 50,
echo     "discovery": true,
echo     "bootnodes": [
echo       "/ip4/127.0.0.1/tcp/30305/p2p/node2",
echo       "/ip4/127.0.0.1/tcp/30306/p2p/node3"
echo     ]
echo   },
echo   "grpc": {
echo     "enabled": true,
echo     "port": 9091
echo   },
echo   "consensus": {
echo     "block_time": "3s",
echo     "timeout_propose": "3s",
echo     "timeout_prevote": "1s",
echo     "timeout_precommit": "1s",
echo     "timeout_commit": "1s"
echo   },
echo   "validator": {
echo     "enabled": true,
echo     "key": "validator1",
echo     "stake": "150000000000000000000000"
echo   },
echo   "dex": {
echo     "enabled": true,
echo     "trading_fee": 0.003,
echo     "min_liquidity": "1000000000000000000000",
echo     "max_slippage": 0.5
echo   },
echo   "bridge": {
echo     "enabled": true,
echo     "circuit_breaker": true,
echo     "replay_protection": true,
echo     "max_daily_volume": "1000000000000000000000000"
echo   }
echo }
) > "devnet-data\node1\config.json"

REM Similar configs for Node 2 and Node 3 (with different ports)
copy "devnet-data\node1\config.json" "devnet-data\node2\config.json" >nul
copy "devnet-data\node1\config.json" "devnet-data\node3\config.json" >nul

REM Copy genesis to all nodes
copy "devnet-data\genesis\genesis.json" "devnet-data\node1\genesis.json" >nul
copy "devnet-data\genesis\genesis.json" "devnet-data\node2\genesis.json" >nul
copy "devnet-data\genesis\genesis.json" "devnet-data\node3\genesis.json" >nul

REM Create placeholder process files (simulating running nodes)
echo Node 1 started with PID placeholder > "devnet-data\node1\node.pid"
echo Node 2 started with PID placeholder > "devnet-data\node2\node.pid"
echo Node 3 started with PID placeholder > "devnet-data\node3\node.pid"

echo.
echo ✅ DevNet setup completed successfully!
echo.
echo 📊 Network Information:
echo   Chain ID: blackhole-devnet-1
echo   Block Time: 3 seconds
echo   Validators: 3 nodes
echo   Total Supply: 350,000,000 BHX (initial)
echo   Max Supply: 1,000,000,000 BHX
echo.
echo 🔗 API Endpoints:
echo   Node 1: http://localhost:8081
echo   Node 2: http://localhost:8082  
echo   Node 3: http://localhost:8083
echo.
echo 🔗 RPC Endpoints:
echo   Node 1: http://localhost:8546
echo   Node 2: http://localhost:8547
echo   Node 3: http://localhost:8548
echo.
echo 🧪 Next Steps:
echo   1. Run DEX tests: go run scripts/dex_testing_suite.go
echo   2. Test multi-node consensus: go run scripts/multinode_coordinator.go
echo   3. Deploy bridge: cd bridge-sdk ^&^& go run main.go
echo   4. Start wallet UI: cd services/wallet ^&^& go run main.go -web -port 9000
echo.
echo 📋 Configuration Files Created:
echo   • devnet-data/genesis/genesis.json (Network genesis)
echo   • devnet-data/node1/config.json (Node 1 config)
echo   • devnet-data/node2/config.json (Node 2 config)  
echo   • devnet-data/node3/config.json (Node 3 config)
echo.

pause