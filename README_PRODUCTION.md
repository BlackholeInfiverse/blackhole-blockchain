# 🌌 Blackhole Blockchain - Production Ready

A complete blockchain ecosystem with native token support, DeFi features, and professional web interface.

## 🚀 Quick Start

### Prerequisites
- **Go 1.19+** - [Download](https://golang.org/dl/)
- **MongoDB** - [Download](https://www.mongodb.com/try/download/community)
- **Windows 10/11** (for .bat scripts)

### 1. Deploy the System
```bash
# Build production binaries
deploy.bat

# Start all services
start_production.bat
```

### 2. Access the System
- **Wallet Dashboard**: http://localhost:9000
- **Blockchain API**: http://localhost:8080
- **Health Check**: http://localhost:8080/api/health

### 3. Stop the System
```bash
stop_production.bat
```

## 🏗️ System Architecture

### Core Components
- **Blockchain Node** (`core/relay-chain/`) - P2P blockchain with consensus
- **Wallet Service** (`services/wallet/`) - User management and token operations
- **Web UI** (`services/wallet/wallet-web-ui/`) - Professional dashboard
- **Database** - MongoDB for user data and wallet storage

### Token System
- **BHX** - Native blockchain token
- **ETH/USDT** - Supported external tokens
- **Staking** - Validator staking system
- **DeFi Features** - DEX, OTC trading, escrow

## 📊 Features

### ✅ Implemented & Working
- **User Management** - Registration, login, session management
- **Wallet Operations** - Create, import, export wallets
- **Token Transfers** - Send/receive tokens with history
- **Balance Queries** - Real-time balance checking with caching
- **Staking System** - Stake tokens for validation rewards
- **OTC Trading** - Over-the-counter token trading
- **Multi-signature** - Multi-party transaction approval
- **Escrow Services** - Secure multi-party transactions
- **P2P Network** - LibP2P-based node communication
- **Persistence** - Blockchain state and user data storage
- **API System** - RESTful APIs with error handling
- **Web Dashboard** - Professional HTML/CSS/JS interface

### 🔧 Technical Features
- **Consensus** - Proof-of-Stake with validator rotation
- **Database** - LevelDB (blockchain) + MongoDB (users)
- **Networking** - LibP2P with peer discovery
- **Security** - Encrypted wallet storage, session management
- **Monitoring** - Health checks and system metrics
- **Error Handling** - User-friendly error messages
- **Caching** - Balance caching for performance

## 🎯 User Workflows

### New User Journey
1. **Register** - Create account at http://localhost:9000/register
2. **Login** - Access dashboard at http://localhost:9000
3. **Create Wallet** - Generate new wallet with mnemonic
4. **Check Balance** - View token balances
5. **Transfer Tokens** - Send tokens to other addresses
6. **Stake Tokens** - Participate in validation

### Advanced Features
- **Import Wallet** - Import existing wallet via private key
- **Export Wallet** - Export private key for backup
- **OTC Trading** - Create and match trading orders
- **Multi-sig** - Create multi-party wallets
- **Transaction History** - View all past transactions

## 🛠️ Development

### Project Structure
```
blackhole-blockchain/
├── core/relay-chain/          # Blockchain core
│   ├── chain/                 # Blockchain logic
│   ├── api/                   # HTTP API server
│   └── cmd/relay/             # Main executable
├── services/wallet/           # Wallet service
│   ├── wallet/                # Wallet operations
│   └── wallet-web-ui/         # Web interface
├── bin/                       # Production binaries
├── data/                      # Blockchain data
└── logs/                      # Log files
```

### Building from Source
```bash
# Build blockchain
cd core/relay-chain/cmd/relay
go build -o ../../../../bin/blockchain.exe main.go

# Build wallet
cd services/wallet
go build -o ../../bin/wallet.exe main.go
```

### Configuration
- **Blockchain Port**: 3000 (P2P), 8080 (API)
- **Wallet Port**: 9000 (Web UI)
- **Database**: MongoDB on default port (27017)
- **Data Directory**: `./data/`
- **Logs Directory**: `./logs/`

## 🔒 Security

### Wallet Security
- **Encryption** - All private keys encrypted with user passwords
- **Session Management** - Secure session tokens with expiration
- **Input Validation** - All user inputs validated and sanitized

### Network Security
- **P2P Encryption** - LibP2P handles encrypted peer communication
- **API Security** - CORS enabled, input validation
- **Database Security** - MongoDB with authentication

## 📈 Performance

### Optimizations
- **Balance Caching** - Blockchain balance queries cached for speed
- **Connection Pooling** - Database connections pooled
- **Async Operations** - Non-blocking API operations
- **Retry Logic** - Automatic retry for failed operations

### Monitoring
- **Health Checks** - `/api/health` endpoint for system status
- **Logging** - Comprehensive logging to `./logs/`
- **Metrics** - Block height, transaction count, validator status

## 🐛 Troubleshooting

### Common Issues

**"MongoDB not running"**
- Start MongoDB service: `net start MongoDB`
- Check connection: `mongosh --eval "db.runCommand('ping')"`

**"Port already in use"**
- Check what's using the port: `netstat -ano | findstr :8080`
- Kill the process or change port configuration

**"Balance queries failing"**
- Ensure blockchain is running: Check http://localhost:8080/api/health
- Restart services: `stop_production.bat` then `start_production.bat`

**"Wallet won't connect to blockchain"**
- Check peer address in logs
- Ensure both services are running
- Verify firewall isn't blocking ports

### Log Files
- **Blockchain**: `logs/blockchain.log`
- **Wallet**: `logs/wallet.log`
- **Build**: `build.log`
- **Deploy**: `deploy.log`

## 🎉 Success Metrics

Your Blackhole Blockchain is **production ready** when:
- ✅ All services start without errors
- ✅ Wallet dashboard loads at http://localhost:9000
- ✅ User can register, login, and create wallets
- ✅ Balance queries return results quickly
- ✅ Token transfers complete successfully
- ✅ System persists data across restarts
- ✅ Health check returns "healthy" status

## 📞 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review log files in `./logs/`
3. Ensure all prerequisites are installed
4. Try restarting services with `stop_production.bat` then `start_production.bat`

---

**🌌 Congratulations! You have a fully functional blockchain ecosystem!**
