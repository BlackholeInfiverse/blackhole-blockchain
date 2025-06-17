# 🌐 Full End-to-End Testnet Simulation

This directory contains everything needed for a complete end-to-end bridge demonstration using real testnets.

## 🎯 **Simulation Overview**

### **Flow**: 
`ERC-20 Token (Sepolia) → Bridge Capture → Relay → SPL Token (Devnet) → Go Blockchain`

### **Components**:
1. **ERC-20 Token Contract** on Ethereum Sepolia Testnet
2. **SPL Token Program** on Solana Devnet  
3. **Real-time Bridge Listeners** monitoring both chains
4. **Cross-chain Relay System** with replay protection
5. **Go Blockchain Integration** with token minting/burning

## 📋 **Prerequisites**

### **Ethereum Sepolia Setup**:
- MetaMask wallet with Sepolia ETH
- Get free Sepolia ETH: https://sepoliafaucet.com/
- Infura/Alchemy account (optional, using public RPC)

### **Solana Devnet Setup**:
- Solana CLI installed: `sh -c "$(curl -sSfL https://release.solana.com/v1.17.0/install)"`
- Phantom wallet or Solana CLI keypair
- Get free Devnet SOL: `solana airdrop 2`

### **Development Tools**:
- Node.js 18+ for contract deployment
- Go 1.21+ for bridge system
- Git for version control

## 🚀 **Quick Start**

### **1. Deploy Testnet Tokens**
```bash
# Deploy ERC-20 on Sepolia
cd ethereum-contracts
npm install
npm run deploy:sepolia

# Deploy SPL Token on Devnet  
cd ../solana-contracts
npm install
npm run deploy:devnet
```

### **2. Start Bridge System**
```bash
cd ../bridge-sdk/example
go run main.go
```

### **3. Monitor Dashboard**
- Open: http://localhost:8084
- View real-time transactions
- Monitor replay protection
- Track cross-chain relays

### **4. Execute Test Transactions**
```bash
# Send ERC-20 tokens on Sepolia
cd ../testnet-setup/scripts
node send-eth-transaction.js

# Send SPL tokens on Devnet
node send-sol-transaction.js
```

## 📊 **Expected Results**

1. **Real Transaction Capture**: Bridge detects actual testnet transactions
2. **Cross-chain Relay**: Automatic relay to destination chain
3. **Replay Protection**: Duplicate prevention with BoltDB
4. **Go Blockchain Integration**: Token minting/burning on custom chain
5. **Dashboard Monitoring**: Real-time visualization of entire flow

## 🎥 **Demo Recording Checklist**

- [ ] Show token deployment on both testnets
- [ ] Demonstrate real transaction sending
- [ ] Capture bridge detection and processing
- [ ] Show cross-chain relay execution
- [ ] Verify replay protection working
- [ ] Display final token balances
- [ ] Record dashboard metrics and logs

## 📁 **Directory Structure**

```
testnet-setup/
├── README.md                    # This file
├── ethereum-contracts/          # ERC-20 deployment
│   ├── contracts/
│   ├── scripts/
│   └── package.json
├── solana-contracts/           # SPL token deployment  
│   ├── programs/
│   ├── scripts/
│   └── package.json
├── scripts/                    # Transaction execution
│   ├── send-eth-transaction.js
│   ├── send-sol-transaction.js
│   └── monitor-bridge.js
└── config/                     # Network configurations
    ├── ethereum-sepolia.json
    ├── solana-devnet.json
    └── bridge-config.json
```

## 🔧 **Configuration Files**

All network endpoints, contract addresses, and bridge settings are stored in the `config/` directory for easy management and updates.

## 🐛 **Troubleshooting**

### **Common Issues**:
- **RPC Connection Errors**: Switch to alternative public RPCs
- **Insufficient Testnet Funds**: Use faucets to get more tokens
- **Transaction Failures**: Check gas/fee settings
- **Bridge Delays**: Normal for testnet congestion

### **Support**:
- Check logs in bridge dashboard
- Monitor network status pages
- Verify testnet faucet availability
