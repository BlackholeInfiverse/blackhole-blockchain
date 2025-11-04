# Fake Transaction Generator

This tool generates fake transactions for testing the Blackhole Blockchain network. It connects to a blockchain node as a P2P peer and submits real transactions to the network.

## 🏗️ Architecture

The fake transaction generator now properly integrates with the blockchain's P2P network:

1. **P2P Connection**: Connects to a blockchain node as a peer (like the wallet service does)
2. **Real Transaction Submission**: Submits transactions through the blockchain client to the network
3. **Network Broadcasting**: Transactions are broadcast to all connected peers for mining
4. **Database Tracking**: Also saves transaction records to MongoDB for local tracking

## 📋 Prerequisites

Before running the fake transaction generator, ensure you have:

1. **MongoDB** running on `localhost:27017`
2. **Blockchain Node** running (relay chain)
3. **Peer Address** from the blockchain node

## 🚀 Quick Start

### Step 1: Start the Blockchain Node

First, start a blockchain relay chain node:

```bash
cd blackhole-blockchain/core/relay-chain/cmd/relay
go run main.go
```

The node will output something like:
```
🚀 Your peer multiaddr:
   /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R
```

Copy this peer address for the next step.

### Step 2: Run the Fake Transaction Generator

#### Option A: Using Scripts (Recommended)

**Windows:**
```cmd
run_fake_transactions.bat /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R 4.0
```

**Linux/Mac:**
```bash
./run_fake_transactions.sh /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R 4.0
```

#### Option B: Direct Go Command

```bash
cd test-tools
go run fake_transaction_generator.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R -rate 4.0
```

## ⚙️ Configuration Options

### Command Line Flags

- `-peerAddr`: **Required** - Blockchain node peer address
- `-rate`: Optional - Transaction generation rate per second (default: 4.0)

### Examples

```bash
# Generate 3 transactions per second
go run fake_transaction_generator.go -peerAddr <peer_address> -rate 3.0

# Generate 5 transactions per second
go run fake_transaction_generator.go -peerAddr <peer_address> -rate 5.0

# Use default rate (4 tx/sec)
go run fake_transaction_generator.go -peerAddr <peer_address>
```

## 🔄 Transaction Flow

The generator creates transactions between two test wallets:

- **Shivam**: `03d0f85fe18231c5aa28cb3b405652a9f3ee1e9ef08aad36ad4c850c52f7bed10f`
- **Shivam2**: `02dc2e3faa525d9a343742e625a1e192560100288635d803a8883e22f7b65eef59`

### Transaction Types Generated

1. **Token Transfer** (70% probability)
2. **Regular Transfer** (20% probability)  
3. **Stake Deposit** (10% probability)

### Token Types

- **BHX** (Blackhole Token) - 60% probability
- **ETH** (Ethereum) - 25% probability
- **BTC** (Bitcoin) - 15% probability

## 📊 Output and Monitoring

The generator provides real-time feedback:

```
✅ Transaction Submitted #42
   🔄 Direction: shivam → shivam2
   💰 Amount: 150 BHX
   📝 Type: Token Transfer
   🆔 TX ID: a1b2c3d4e5f6...
   🌐 Network: Submitted to blockchain
   ⏰ Time: 14:32:15
```

Statistics are displayed every 10 seconds:
```
📊 === TRANSACTION STATISTICS ===
⏱️  Runtime: 1m 30s
📈 Generated: 127 transactions
🚀 Current Rate: 4.2 tx/sec
```

## 🛑 Stopping the Generator

Press `Ctrl+C` to gracefully stop the generator. It will display final statistics before exiting.

## 🔧 Troubleshooting

### Common Issues

1. **"Peer address is required"**
   - Make sure you provide the `-peerAddr` flag
   - Verify the blockchain node is running and outputting the peer address

2. **"Failed to connect to blockchain node"**
   - Check that the blockchain node is running
   - Verify the peer address is correct and reachable
   - Ensure no firewall is blocking the connection

3. **"MongoDB connection error"**
   - Start MongoDB: `mongod` or `brew services start mongodb-community`
   - Verify MongoDB is running on `localhost:27017`

4. **Go module errors**
   - Run `go mod tidy` in the `test-tools` directory
   - Ensure you're in the correct directory

### Verification

To verify transactions are being processed:

1. Check the blockchain node logs for incoming transactions
2. Monitor MongoDB collections for transaction records
3. Use the wallet CLI to check balances (if implemented)

## 📁 Files

- `fake_transaction_generator.go` - Main P2P-enabled generator
- `simple_fake_generator.go` - Simplified database-only version
- `run_fake_transactions.bat` - Windows script
- `run_fake_transactions.sh` - Unix script
- `go.mod` - Go module dependencies
