# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

BlackHole Blockchain is a multi-component Layer 1 blockchain ecosystem featuring:
- Native Layer 1 blockchain with PoS consensus
- Cross-chain bridge supporting Ethereum, Solana, and BSC
- Built-in DEX with AMM functionality
- ERC20 token (BHX) for exchange listings
- Wallet services with MongoDB integration
- NEAR smart contract integration

## Architecture

### Core Components

- **Core Blockchain** (`core/relay-chain/`): Main blockchain node implementation
- **Bridge SDK** (`bridge-sdk/`): Cross-chain bridge with circuit breakers and replay protection
- **Wallet Service** (`services/wallet/`): Wallet CLI and web interface with MongoDB backend
- **Smart Contracts** (`contracts/`): ERC20 token contracts for exchange listings
- **NEAR Integration** (`SmartCont/`): NEAR blockchain smart contract support
- **Parachains** (`parachains/`): Simple Go backend service

### Key Technologies
- **Backend**: Go (multiple modules with separate go.mod files)
- **Smart Contracts**: Solidity (Hardhat framework)
- **Database**: MongoDB (wallet service), BoltDB (bridge), LevelDB (blockchain)
- **Frontend**: Web interfaces in Go services
- **Deployment**: Docker Compose, batch scripts for Windows

## Development Commands

### Blockchain Operations

```bash
# Start main blockchain node
go run core/relay-chain/cmd/relay/main.go

# Start wallet service (CLI mode)
cd services/wallet
go run main.go -peerAddr "/ip4/127.0.0.1/tcp/3000/p2p/NODE_ID"

# Start wallet web interface
cd services/wallet
go run main.go -web -port 9000

# Start bridge service
cd bridge-sdk
go run main.go
```

### Smart Contract Development

```bash
# Install dependencies
cd contracts
npm install

# Compile contracts
npm run compile

# Deploy to testnet
npm run deploy:sepolia

# Deploy to mainnet
npm run deploy:mainnet

# Verify contract
npm run verify:mainnet CONTRACT_ADDRESS "10000000000000000000000000"
```

### DEX Testing

```bash
# Run comprehensive DEX testing suite
go run scripts/dex_testing_suite.go

# Quick DEX functionality test
.\quick-dex-test.bat

# Full DEX validation with load testing
.\test-dex.bat
```

### Quick Deployment

```bash
# Deploy BHX token with guided setup
.\deploy-bhx.bat

# Deploy with budget constraints
.\deploy-bhx-budget.bat

# Check wallet balances
.\check-wallet-balance.bat

# Get free testnet tokens
.\get-free-testnet-tokens.bat
```

### Docker Operations

```bash
# Start full blockchain stack
docker-compose up -d

# Manage Docker services
.\docker-manage.bat

# Linux Docker management
./docker-manage.sh
```

### Development Testing

```bash
# Test NEAR smart contracts
cd SmartCont
go run scripts/deploy.go

# Build and test individual modules
go build ./...
go test ./...
```

## Project Structure

```
├── core/                     # Main blockchain implementation
│   ├── relay-chain/         # Core blockchain node
│   └── go.mod              # Core module dependencies
├── bridge-sdk/              # Cross-chain bridge system
│   ├── core/               # Bridge core functionality
│   ├── dashboard_components.go
│   └── go.mod              # Bridge module dependencies
├── services/                # Service layer
│   ├── wallet/             # Wallet service with web UI
│   └── go.mod              # Services module dependencies
├── contracts/               # Smart contracts (Ethereum/BSC/Polygon)
│   ├── BHX_ERC20.sol       # Main BHX token contract
│   ├── hardhat.config.js   # Multi-network deployment config
│   └── package.json        # Node.js dependencies
├── SmartCont/              # NEAR smart contract integration
│   ├── Contract/           # NEAR contract implementations
│   └── go.mod              # NEAR module dependencies
├── scripts/                # Development and testing scripts
├── docker-compose.yml      # Full stack deployment
└── *.bat/*.sh             # Quick deployment scripts
```

## Key Development Workflows

### Exchange Listing Workflow
1. Deploy BHX token using `.\deploy-bhx.bat`
2. Add liquidity to Uniswap/PancakeSwap
3. Submit to CoinGecko and CoinMarketCap
4. Apply to centralized exchanges (MEXC, Gate.io, etc.)

### DEX Development Workflow
1. Start local blockchain: `go run core/relay-chain/cmd/relay/main.go`
2. Run DEX tests: `go run scripts/dex_testing_suite.go`
3. Test web interface: `go run services/wallet/main.go -web`
4. Validate cross-chain functionality

### Bridge Development Workflow
1. Configure environment variables in `.env` files
2. Start bridge service: `cd bridge-sdk && go run main.go`
3. Test cross-chain transfers between supported networks
4. Monitor bridge health via dashboard

## Environment Configuration

### Required Environment Variables
```bash
# Bridge Configuration
ETHEREUM_RPC="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
SOLANA_RPC="https://api.mainnet-beta.solana.com"
BLACKHOLE_RPC="ws://localhost:8545"

# Smart Contract Deployment
PRIVATE_KEY="your_private_key_here"
ETHERSCAN_API_KEY="your_etherscan_key"
BSCSCAN_API_KEY="your_bscscan_key"

# Database
MONGODB_URI="mongodb+srv://user:pass@cluster.mongodb.net/db"
```

### Development Ports
- Blockchain node: `8080`
- Wallet web UI: `9000`
- Bridge dashboard: `8084`
- Bridge relay: `9090`
- Parachain service: `8080`

## Testing Strategy

### Local Testing (Free)
- Use local blockchain nodes for development
- Test DEX functionality with mock liquidity
- Validate bridge operations between local instances

### Testnet Testing (Nearly Free)
- Deploy to Sepolia (Ethereum), BSC Testnet, Polygon Mumbai
- Use faucets for test tokens
- Test real network interactions

### Mainnet Deployment (Production)
- Follow guided deployment scripts
- Ensure sufficient gas funds
- Monitor all transactions and contract interactions

## Key Features

### Bridge System
- Circuit breaker pattern for safety
- Replay protection against duplicate transactions
- Event recovery for failed operations
- Retry queue with exponential backoff

### DEX Functionality
- AMM-style liquidity pools
- Multi-chain token support
- Price impact calculation
- Slippage protection

### Wallet System
- HD wallet generation from mnemonic
- Private key import/export
- Transaction history tracking
- Multi-network support

## Production Deployment

### Docker Deployment
```bash
docker-compose up -d
```

### Manual Service Start
```bash
# Terminal 1: Blockchain
go run core/relay-chain/cmd/relay/main.go

# Terminal 2: Bridge
cd bridge-sdk && go run main.go

# Terminal 3: Wallet Service
cd services/wallet && go run main.go -web -port 9000
```

### Smart Contract Deployment
```bash
cd contracts
npm run deploy:mainnet  # or deploy:bsc, deploy:polygon
```

## Security Considerations

- Private keys are handled securely in the wallet service
- Bridge implements replay protection and circuit breakers
- Smart contracts include pausable functionality
- Multi-signature support in development
- Environment variables for sensitive configuration

## Development Notes

- Each major component has its own `go.mod` file for modular development
- Windows batch files provide quick deployment options
- Comprehensive testing suite validates DEX functionality before deployment
- MongoDB integration for persistent wallet storage
- Docker Compose setup for production deployment
- Multi-network smart contract support (Ethereum, BSC, Polygon)
