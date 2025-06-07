# Blackhole Blockchain - Testing Guide

## 🧪 Module Testing Instructions

### 🔧 Prerequisites

#### System Requirements
- **Go**: Version 1.19 or higher
- **MongoDB**: Version 4.4 or higher
- **Operating System**: Windows, macOS, or Linux
- **Memory**: Minimum 4GB RAM
- **Storage**: Minimum 2GB free space

#### Environment Setup
```bash
# Install Go dependencies
go mod download

# Start MongoDB
mongod --dbpath /path/to/mongodb/data

# Verify MongoDB connection
mongo --eval "db.adminCommand('ismaster')"
```

## 🌐 Core Blockchain Testing

### 1. Blockchain Node Testing

#### Start Blockchain Node
```bash
cd core/relay-chain/cmd/relay
go run main.go 3000
```

#### Expected Output
```
🚀 Your peer multiaddr:
   /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R
🌐 API Server starting on port 8080
🌐 Open http://localhost:8080 in your browser
🏗️ Mining block 1 with validator: genesis-validator
✅ Block 1 added successfully
```

#### Test Cases
1. **Genesis Block Creation**
   - Verify genesis block is created
   - Check initial token balances
   - Confirm system account setup

2. **P2P Node Initialization**
   - Verify peer ID generation
   - Check multiaddr display
   - Test port binding

3. **API Server Startup**
   - Access http://localhost:8080
   - Verify dashboard loads
   - Check API endpoints respond

#### Validation Commands
```bash
# Check blockchain status via CLI
> status

# Expected output:
📊 Blockchain Status
  Block height       : 1
  Pending Tx count   : 0
  Total Supply       : 1000000000 BHX
  Latest Block Hash  : [hash]
```

### 2. Mining & Consensus Testing

#### Test Automatic Mining
1. **Start blockchain node**
2. **Wait for automatic mining** (every 6 seconds)
3. **Verify block creation** in logs

#### Expected Mining Output
```
🚫 No pending transactions, skipping block mining
⛏️ Mining new block...
🏗️ Mining block 2 with validator: genesis-validator
✅ Block 2 added successfully
💰 Validator genesis-validator received reward: 10 BHX
```

#### Test Manual Mining
```bash
# In blockchain CLI
> mine

# Expected output:
⛏️ Mining new block...
✅ Block [number] added successfully
```

#### Consensus Validation
1. **Verify validator selection** based on stakes
2. **Check block time intervals** (6-second minimum)
3. **Validate block structure** and hashing

### 3. Token System Testing

#### Test Token Operations via Dashboard
1. **Access dashboard**: http://localhost:8080
2. **Navigate to Admin Panel**
3. **Add tokens to address**:
   - Address: `test_address_123`
   - Token: `BHX`
   - Amount: `1000`
4. **Click "Add Tokens"**
5. **Verify balance update** in Token Balances section

#### Expected Dashboard Updates
- Token Balances table shows new entry
- Total Supply increases
- Real-time updates every 3 seconds

#### API Testing
```bash
# Test blockchain info endpoint
curl http://localhost:8080/api/blockchain/info

# Expected response:
{
  "blockHeight": 5,
  "pendingTxs": 0,
  "totalSupply": 1000000000,
  "blockReward": 10,
  "tokenBalances": {
    "BHX": {
      "system": 10000000,
      "test_address_123": 1000
    }
  }
}
```

## 💼 Wallet Service Testing

### 1. Wallet Connection Testing

#### Start Wallet with Peer Address
```bash
cd services/wallet
go run main.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R
```

#### Expected Connection Output
```
🔗 Connecting to blockchain node: /ip4/127.0.0.1/tcp/3000/p2p/12D3KooW...
✅ Connected to blockchain node: /ip4/127.0.0.1/tcp/3000/p2p/12D3KooW...
✅ Successfully connected to blockchain node!
Welcome to the Wallet CLI
```

#### Test Offline Mode
```bash
go run main.go
```

#### Expected Offline Output
```
⚠️ No peer address provided. Use -peerAddr flag to connect to blockchain node.
⚠️ Example: go run main.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/12D3KooW...
⚠️ Wallet will work in offline mode.
```

### 2. User & Wallet Management Testing

#### Test User Registration
1. **Choose option 1** (Register)
2. **Enter username**: `testuser`
3. **Enter password**: `securepassword123`
4. **Verify registration success**

#### Test User Login
1. **Choose option 2** (Login)
2. **Enter credentials**
3. **Verify login success**

#### Test Wallet Creation
1. **Choose option 1** (Generate Wallet from Mnemonic)
2. **Enter wallet name**: `my_test_wallet`
3. **Enter password**: `walletpassword123`
4. **Verify wallet creation**
5. **Note wallet address** for testing

#### Expected Wallet Output
```
Wallet generated successfully!
Wallet Name: my_test_wallet
Mnemonic (store safely!): [encrypted_mnemonic]
```

### 3. Token Operations Testing

#### Test Token Balance Check
1. **Choose option 6** (Check Token Balance)
2. **Enter wallet name**: `my_test_wallet`
3. **Enter password**: `walletpassword123`
4. **Enter token symbol**: `BHX`
5. **Verify balance display** (placeholder: 1000)

#### Test Token Transfer
**Prerequisites**: Add tokens to wallet address via dashboard

1. **Choose option 7** (Transfer Tokens)
2. **Enter wallet name**: `my_test_wallet`
3. **Enter password**: `walletpassword123`
4. **Enter recipient**: `recipient_address_123`
5. **Enter token symbol**: `BHX`
6. **Enter amount**: `100`
7. **Verify transfer success**

#### Expected Transfer Output
```
✅ Transaction recorded with ID: [transaction_hash]
Successfully transferred 100 BHX tokens to recipient_address_123
```

#### Verify Transfer in Blockchain
1. **Check blockchain logs** for transaction reception
2. **Verify dashboard updates** with new transaction
3. **Check balance changes** in Token Balances

### 4. Staking Testing

#### Test Token Staking
1. **Choose option 8** (Stake Tokens)
2. **Enter wallet details**
3. **Enter token symbol**: `BHX`
4. **Enter amount**: `500`
5. **Verify staking success**

#### Expected Staking Output
```
✅ Staking transaction recorded with ID: [transaction_hash]
Successfully staked 500 BHX tokens
```

#### Verify Staking in Dashboard
1. **Check Staking Information** section
2. **Verify wallet address** appears in staking table
3. **Confirm stake amount**: 500
4. **Check tokens moved** to staking_contract

## 🔄 Integration Testing

### 1. Complete Workflow Test

#### End-to-End Transaction Flow
1. **Start blockchain node**
2. **Start wallet service** with peer address
3. **Create user and wallet**
4. **Add tokens via dashboard**
5. **Transfer tokens via wallet**
6. **Verify transaction in blockchain**
7. **Check balance updates**

#### Expected Integration Points
- Wallet → P2P → Blockchain → Database → Dashboard
- Real-time updates across all interfaces
- Consistent state across components

### 2. Multi-Node Testing

#### Setup Second Node
```bash
# Terminal 1: Start first node
go run main.go 3000

# Terminal 2: Start second node with peer connection
go run main.go 3001 /ip4/127.0.0.1/tcp/3000/p2p/12D3KooW...
```

#### Test P2P Synchronization
1. **Send transaction** from wallet to first node
2. **Verify transaction propagation** to second node
3. **Check block synchronization** between nodes

## 🧪 Advanced Module Testing

### 1. DEX Testing
**Note**: DEX functionality is implemented but requires API integration

#### Test Trading Pair Creation
```go
// Via code testing
dex := NewDEX()
err := dex.CreatePair("BHX", "USDT", 10000, 50000)
// Verify pair creation
```

### 2. Escrow Testing
```go
// Via code testing
escrow := NewEscrow()
escrowID := escrow.CreateEscrow(sender, receiver, arbitrator, "BHX", 1000)
// Test escrow workflow
```

### 3. Multi-Signature Testing
```go
// Via code testing
multisig := NewMultiSig()
walletID := multisig.CreateWallet([]string{"owner1", "owner2", "owner3"}, 2)
// Test multi-sig operations
```

## 🚨 Error Testing

### 1. Connection Failure Testing
```bash
# Start wallet without blockchain running
go run main.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/invalid_peer_id
```

#### Expected Error Output
```
⚠️ Failed to connect to blockchain node: failed to dial...
⚠️ Wallet will work in offline mode. Check the peer address and try again.
```

### 2. Invalid Transaction Testing
1. **Try transferring more tokens than available**
2. **Use invalid addresses**
3. **Test with empty amounts**
4. **Verify proper error handling**

### 3. Database Failure Testing
1. **Stop MongoDB during wallet operation**
2. **Verify graceful error handling**
3. **Test reconnection capabilities**

## 📊 Performance Testing

### 1. Transaction Throughput
1. **Create multiple wallets**
2. **Send concurrent transactions**
3. **Measure processing time**
4. **Monitor system resources**

### 2. Block Mining Performance
1. **Monitor block creation times**
2. **Test with varying transaction loads**
3. **Measure validation performance**

### 3. P2P Network Performance
1. **Test with multiple connected peers**
2. **Measure message propagation times**
3. **Monitor network bandwidth usage**

## ✅ Test Validation Checklist

### Core Functionality
- [ ] Blockchain node starts successfully
- [ ] Genesis block created with correct balances
- [ ] P2P networking operational
- [ ] API server responds correctly
- [ ] Dashboard displays real-time data

### Wallet Operations
- [ ] User registration and login working
- [ ] Wallet creation and management functional
- [ ] P2P connection to blockchain successful
- [ ] Token operations execute correctly
- [ ] Transaction history tracking working

### Integration
- [ ] End-to-end transaction flow complete
- [ ] Real-time updates across all interfaces
- [ ] Multi-node synchronization working
- [ ] Error handling graceful and informative

### Performance
- [ ] Block mining within expected timeframes
- [ ] Transaction processing responsive
- [ ] Dashboard updates smoothly
- [ ] System stable under normal load
