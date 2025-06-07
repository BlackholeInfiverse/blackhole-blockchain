# Blackhole Blockchain - Project Structure Documentation

## 📁 Project Overview

The Blackhole Blockchain is a comprehensive blockchain ecosystem implementing a complete DeFi platform with advanced features including staking, DEX trading, escrow, multi-signature wallets, OTC trading, and cross-chain bridge capabilities.

## 🏗️ Directory Structure

```
blackhole-blockchain/
├── 📁 core/                          # Core blockchain implementation
│   ├── go.mod                        # Core module dependencies
│   └── relay-chain/                  # Main blockchain components
│       ├── api/                      # HTTP API server & HTML dashboard
│       ├── bridge/                   # Cross-chain bridge implementation
│       ├── chain/                    # Core blockchain logic
│       ├── cmd/relay/                # Blockchain node executable
│       ├── consensus/                # Proof-of-Stake consensus
│       ├── crypto/                   # Cryptographic utilities
│       ├── dex/                      # Decentralized exchange
│       ├── escrow/                   # Escrow system
│       ├── interoperability/         # Cross-chain functionality
│       ├── multisig/                 # Multi-signature wallets
│       ├── otc/                      # Over-the-counter trading
│       ├── smartcontracts/           # Smart contract system
│       └── token/                    # Token management system
├── 📁 services/                      # External services
│   ├── go.mod                        # Services module dependencies
│   └── wallet/                       # Wallet service
│       ├── main.go                   # Wallet CLI application
│       ├── transaction/              # Transaction utilities
│       ├── transaction_test/         # Transaction testing
│       └── wallet/                   # Wallet core functionality
├── 📁 libs/                          # Shared libraries
├── 📁 parachains/                    # Parachain implementation
├── 📁 scripts/                       # Utility scripts
├── 📁 docs/                          # Documentation & API specs
├── 📁 blockchain_logs/               # Blockchain state logs
├── 📁 blockchaindb_3000/             # LevelDB blockchain database
├── 🔧 go.work                        # Go workspace configuration
├── 🔧 go.work.sum                    # Go workspace checksums
├── 🚀 start_blockchain.bat           # Blockchain startup script
├── 🚀 start_wallet.bat               # Wallet startup script
└── 📚 *.md                           # Documentation files
```

## 🔧 Core Components Detail

### 📁 core/relay-chain/

#### 🌐 api/ - HTTP API & Dashboard
```
api/
└── server.go                        # HTTP server with embedded HTML UI
```
- **Purpose**: Provides REST API endpoints and real-time HTML dashboard
- **Features**: Blockchain monitoring, admin panel, token management
- **Port**: 8080 (HTTP server)

#### ⛓️ chain/ - Blockchain Core
```
chain/
├── blockchain.go                     # Main blockchain implementation
├── block.go                          # Block structure and validation
├── transaction.go                    # Transaction types and processing
├── stakeledger.go                    # Staking mechanism
├── validator_manager.go              # Validator selection logic
├── txpool.go                         # Transaction pool management
├── p2p.go                           # P2P networking
├── messages.go                       # P2P message protocols
├── gobtypes.go                       # Serialization types
└── blockchain_logger.go              # State logging utilities
```

#### 🏛️ consensus/ - Proof-of-Stake
```
consensus/
└── pos.go                           # PoS validator selection & rewards
```

#### 🪙 token/ - Token System
```
token/
├── token.go                         # Core token implementation
├── mint.go                          # Token minting logic
├── burn.go                          # Token burning logic
├── transfer.go                      # Token transfer logic
├── balance.go                       # Balance management
├── allowance.go                     # Token allowances
├── events.go                        # Token events
└── utils.go                         # Token utilities
```

#### 💱 dex/ - Decentralized Exchange
```
dex/
└── dex.go                           # AMM trading pairs & liquidity
```

#### 🔒 escrow/ - Escrow System
```
escrow/
└── escrow.go                        # Multi-party escrow contracts
```

#### 🔐 multisig/ - Multi-Signature Wallets
```
multisig/
└── multisig.go                      # N-of-M signature wallets
```

#### 🤝 otc/ - OTC Trading
```
otc/
└── otc.go                           # Over-the-counter trading
```

#### 🌉 bridge/ & interoperability/ - Cross-Chain
```
bridge/
└── bridge.go                        # Cross-chain bridge logic
interoperability/
└── cross_chain.go                   # Cross-chain protocols
```

#### 📜 smartcontracts/ - Smart Contracts
```
smartcontracts/
└── tokenx.go                        # Token smart contracts
```

#### 🔐 crypto/ - Cryptography
```
crypto/
└── crypto.go                        # Cryptographic utilities
```

#### 🚀 cmd/relay/ - Node Executable
```
cmd/relay/
├── main.go                          # Blockchain node entry point
├── relay.exe                        # Compiled executable
├── blockchain_logs/                 # Node-specific logs
├── blockchaindb_3000/              # Node database (port 3000)
└── blockchaindb_3001/              # Node database (port 3001)
```

### 📁 services/wallet/

#### 💼 Wallet Service
```
wallet/
├── main.go                          # Wallet CLI application
├── wallet/                          # Core wallet functionality
│   ├── wallet.go                    # User & wallet management
│   ├── blockchain_client.go         # P2P blockchain connection
│   ├── token_operations.go          # Token operations
│   └── transaction_history.go       # Transaction tracking
├── transaction/                     # Transaction utilities
└── transaction_test/                # Testing utilities
```

## 🔗 Module Dependencies

### Go Modules Structure
```
📦 Root Workspace (go.work)
├── 📦 core/ (core blockchain)
├── 📦 services/ (wallet service)
└── 📦 libs/ (shared libraries)
```

### Key Dependencies
- **libp2p**: P2P networking
- **leveldb**: Blockchain database
- **mongodb**: Wallet database
- **btcec**: Cryptographic operations
- **bip32/bip39**: HD wallet generation

## 🌊 Data Flow Architecture

```
┌─────────────────┐    P2P/libp2p    ┌─────────────────┐    HTTP/REST    ┌─────────────────┐
│   Wallet CLI    │◄─────────────────►│ Blockchain Node │◄───────────────►│  HTML Dashboard │
│                 │                   │                 │                 │                 │
│ • User Mgmt     │                   │ • Mining        │                 │ • Real-time UI  │
│ • Wallet Ops    │                   │ • Validation    │                 │ • Admin Panel   │
│ • Token Ops     │                   │ • P2P Network   │                 │ • Monitoring    │
│ • History       │                   │ • DEX           │                 │ • Testing       │
│ • Import/Export │                   │ • Escrow        │                 │                 │
│                 │                   │ • Multi-sig     │                 │                 │
│                 │                   │ • OTC           │                 │                 │
│                 │                   │ • Bridge        │                 │                 │
└─────────────────┘                   └─────────────────┘                 └─────────────────┘
        │                                       │                                   │
        │ MongoDB                               │ LevelDB                           │ Browser
        ▼                                       ▼                                   ▼
┌─────────────────┐                   ┌─────────────────┐                 ┌─────────────────┐
│   Wallet DB     │                   │  Blockchain DB  │                 │   Web Browser   │
│                 │                   │                 │                 │                 │
│ • Users         │                   │ • Blocks        │                 │ • Dashboard     │
│ • Wallets       │                   │ • Transactions  │                 │ • Admin Tools   │
│ • Transactions  │                   │ • State         │                 │ • Monitoring    │
└─────────────────┘                   └─────────────────┘                 └─────────────────┘
```

## 🔧 Configuration Files

### Build & Runtime Configuration
- **go.work**: Go workspace configuration
- **go.mod**: Module dependencies per component
- **start_blockchain.bat**: Blockchain node startup
- **start_wallet.bat**: Wallet service startup

### Database Configuration
- **LevelDB**: Blockchain state storage (blockchaindb_*)
- **MongoDB**: Wallet and user data (localhost:27017)

## 🚀 Executable Components

### 1. Blockchain Node
- **Location**: `core/relay-chain/cmd/relay/main.go`
- **Purpose**: Core blockchain with mining, validation, P2P
- **Ports**: 3000 (P2P), 8080 (HTTP API)

### 2. Wallet Service
- **Location**: `services/wallet/main.go`
- **Purpose**: User wallet management and blockchain interaction
- **Ports**: 4000+ (P2P client)

### 3. HTML Dashboard
- **Location**: Embedded in API server
- **Purpose**: Real-time monitoring and admin functions
- **Access**: http://localhost:8080

## 📊 Storage Systems

### Blockchain Storage (LevelDB)
- **Path**: `blockchaindb_<port>/`
- **Content**: Blocks, transactions, state
- **Persistence**: Permanent blockchain data

### Wallet Storage (MongoDB)
- **Collections**: users, wallets, transactions
- **Content**: Encrypted wallet data, user accounts
- **Security**: Argon2id password hashing, AES-256-GCM encryption

### Logs Storage
- **Path**: `blockchain_logs/`
- **Content**: JSON blockchain state snapshots
- **Purpose**: Debugging and state analysis
