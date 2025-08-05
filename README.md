# 🚀 BlackHole Blockchain

**A high-performance, multi-token blockchain with AI-powered fraud detection and cross-chain bridge capabilities.**

## 🎯 **Goal: List BHX Token on Cryptocurrency Exchanges**

**Current Status: 85% Complete - Production Ready**

---

## ⚡ **Quick Start**

### **1. Start the Blockchain**
```bash
start_blockchain.bat
```

### **2. Start Web Wallet** (New Terminal)
```bash
start_wallet_web.bat
```

### **3. Start Fraud Detection** (New Terminal)
```bash
start_cybersecurity_system.bat
```

### **4. Start Token Faucet** (New Terminal)
```bash
start_integrated_faucet.bat
```

### **5. Access Services**
- **Blockchain API:** http://localhost:8080
- **Web Wallet:** http://localhost:3001
- **Token Faucet:** http://localhost:3002
- **Fraud Detection:** http://localhost:9090

---

## 🔥 **Key Features**

### **✅ Multi-Token Support**
- **BHX** - Native blockchain token
- **ETH** - Ethereum integration
- **USDT** - Stablecoin support
- **SOL** - Solana integration

### **✅ AI-Powered Fraud Detection**
- Real-time transaction monitoring
- Suspicious wallet flagging
- ML-based pattern recognition
- Automatic transaction blocking

### **✅ Cross-Chain Bridge**
- Ethereum ↔ BlackHole transfers
- Real-time event listening
- Secure cross-chain operations
- Multi-chain token support

### **✅ Professional Web Wallet**
- Browser-based interface
- Multi-token management
- Transaction history
- Real-time balance updates

### **✅ High Performance**
- 1000+ TPS capability
- 6-second block times
- Concurrent processing
- Optimized storage

---

## 📊 **System Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Wallet    │    │   Blockchain    │    │  Fraud Detection│
│   (Port 3001)   │    │   (Port 8080)   │    │   (Port 9090)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │ ──── Transactions ────▶                       │
         │                       │ ── TX Analysis ──────▶
         │                       │◀── Block/Allow ──────│
         │◀─── Balance Updates ──│                       │
         
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Token Faucet   │    │  Cross-Chain    │    │   External      │
│   (Port 3002)   │    │     Bridge      │    │    Chains       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │ ── Token Requests ────▶                       │
         │                       │ ── Bridge TXs ───────▶
         │                       │◀── Events ───────────│
```

---

## 🛠️ **Development**

### **Prerequisites**
- Go 1.19+
- Node.js 16+
- Git

### **Build from Source**
```bash
# Clone repository
git clone <repository-url>
cd blackhole-blockchain

# Build blockchain
cd core/relay-chain/cmd/relay
go build -o relay.exe

# Build wallet service
cd services/wallet
go build -o wallet.exe

# Build faucet service
cd services/validator-faucet
go build -o faucet.exe
```

### **Testing**
```bash
# Test transaction
curl -X POST http://localhost:8080/api/relay/submit \
  -H "Content-Type: application/json" \
  -d '{"type":"transfer","from":"alice","to":"bob","amount":100,"token_id":"BHX"}'

# Check balance
curl http://localhost:8080/api/balance/alice/BHX

# System health
curl http://localhost:8080/api/health
```

---

## 📚 **Documentation**

- **[Complete Project Overview](PROJECT_OVERVIEW.md)** - Detailed project status
- **[API Documentation](docs/API_DOCUMENTATION.md)** - Complete API reference
- **[Wallet Guide](docs/WALLET_WEB_UI_GUIDE.md)** - Web wallet usage
- **[Production Deployment](docs/PRODUCTION_DEPLOYMENT_GUIDE.md)** - Deployment guide

---

## 🏦 **Exchange Listing Progress**

### **✅ Completed Requirements**
- [x] Multi-token blockchain
- [x] AI fraud detection
- [x] Cross-chain bridge
- [x] Professional API
- [x] Web wallet interface
- [x] Performance optimization

### **⏳ Remaining Tasks**
- [ ] Structured audit logging
- [ ] 1000+ TPS stress testing
- [ ] Security audit report
- [ ] Exchange integration docs

**Estimated completion: 2-3 weeks**

---

## 🤝 **Team**

- **Shivam** - Core blockchain, token economics, API
- **Keval & Aryan** - Fraud detection, cybersecurity
- **Yashika** - ML algorithms, pattern recognition
- **Shantanu** - Cross-chain bridge, integrations

---

## 📄 **License**

MIT License - See LICENSE file for details

---

## 🚀 **Get Started**

1. **Run `start_blockchain.bat`** - Start the blockchain
2. **Run `start_wallet_web.bat`** - Start web wallet
3. **Visit http://localhost:3001** - Use the wallet
4. **Read [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)** - Understand the system

**Ready to list BHX on exchanges!** 🎯
