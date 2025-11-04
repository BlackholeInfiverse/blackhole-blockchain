# 🚀 Fake Transaction Generator

This tool generates fake transactions between two specified wallet addresses at a rate of 3-5 transactions per second for testing purposes.

## 📋 Overview

The fake transaction generator creates realistic-looking transactions between:
- **Shivam**: `03d0f85fe18231c5aa28cb3b405652a9f3ee1e9ef08aad36ad4c850c52f7bed10f`
- **Shivam2**: `02dc2e3faa525d9a343742e625a1e192560100288635d803a8883e22f7b65eef59`

## ✨ Features

- **Realistic Transactions**: Generates transactions with proper structure, signatures, and metadata
- **Multiple Token Types**: Supports BHX, USDT, ETH, BTC, DOT tokens
- **Various Transaction Types**: Token transfers, regular transfers, and stake deposits
- **Database Integration**: Saves transactions to MongoDB for persistence
- **Real-time Statistics**: Shows generation rate, transaction counts, and breakdowns
- **Alternating Direction**: Transactions alternate between shivam → shivam2 and shivam2 → shivam

## 🛠️ Prerequisites

1. **MongoDB**: Must be running on `localhost:27017`
2. **Go**: Go runtime environment
3. **Dependencies**: All Go modules should be installed

## 🚀 Quick Start

### Windows
```bash
# Navigate to the wallet directory
cd blackhole-blockchain/services/wallet

# Run the generator
run_fake_transactions.bat
```

### Linux/Mac
```bash
# Navigate to the wallet directory
cd blackhole-blockchain/services/wallet

# Make script executable (if needed)
chmod +x run_fake_transactions.sh

# Run the generator
./run_fake_transactions.sh
```

### Direct Go Command
```bash
cd blackhole-blockchain/services/wallet/test-tools
go run fake_transaction_generator.go
```

## 📊 Sample Output

```
🌌 Blackhole Blockchain - Fake Transaction Generator
==================================================

🚀 Starting Fake Transaction Generator
📍 Shivam Wallet: 03d0f85fe18231c5aa28cb3b405652a9f3ee1e9ef08aad36ad4c850c52f7bed10f
📍 Shivam2 Wallet: 02dc2e3faa525d9a343742e625a1e192560100288635d803a8883e22f7b65eef59
🎯 Target: 3-5 transactions per second

🎬 Generation started! Press Ctrl+C to stop...

✅ Generated Transaction #1
   🔄 Direction: shivam → shivam2
   💰 Amount: 1250 BHX
   📝 Type: Token Transfer
   🆔 TX ID: a1b2c3d4e5f6g7h8...
   ⏰ Time: 14:30:15

✅ Generated Transaction #2
   🔄 Direction: shivam2 → shivam
   💰 Amount: 750 USDT
   📝 Type: Regular Transfer
   🆔 TX ID: h8g7f6e5d4c3b2a1...
   ⏰ Time: 14:30:15

📊 === TRANSACTION GENERATION STATISTICS ===
⏱️  Runtime: 10s
📈 Total Generated: 42 transactions
🚀 Generation Rate: 4.20 tx/sec

📋 By Transaction Type:
   Token Transfer: 28
   Regular Transfer: 10
   Stake Deposit: 4

🪙 By Token Symbol:
   BHX: 15
   USDT: 12
   ETH: 8
   BTC: 4
   DOT: 3
=============================================
```

## 🔧 Configuration

You can modify the following constants in `test-tools/fake_transaction_generator.go`:

```go
// Wallet addresses
const (
    SHIVAM_ADDRESS  = "03d0f85fe18231c5aa28cb3b405652a9f3ee1e9ef08aad36ad4c850c52f7bed10f"
    SHIVAM2_ADDRESS = "02dc2e3faa525d9a343742e625a1e192560100288635d803a8883e22f7b65eef59"
)

// Available tokens and transaction types
var (
    TOKEN_SYMBOLS = []string{"BHX", "USDT", "ETH", "BTC", "DOT"}
    TX_TYPES      = []int{chain.TokenTransfer, chain.RegularTransfer, chain.StakeDeposit}
)
```

## 📝 Transaction Details

Each generated transaction includes:
- **Unique Transaction ID**: SHA-256 hash
- **Random Amount**: Between 1 and 10,000 tokens
- **Random Token**: From the configured token list
- **Transaction Type**: Token transfer, regular transfer, or stake deposit
- **Realistic Metadata**: Nonce, timestamp, gas fees, etc.
- **Mock Signatures**: Properly formatted but fake signatures
- **Database Record**: Saved to MongoDB for persistence

## 🛑 Stopping the Generator

Press `Ctrl+C` to stop the transaction generator. It will display final statistics before exiting.

## 🔍 Monitoring

- **Real-time Logs**: Each transaction is logged with details
- **Statistics**: Updated every 10 seconds
- **Database**: Check MongoDB `walletdb.transactions` collection
- **Rate Monitoring**: Generation rate is displayed in statistics

## ⚠️ Important Notes

1. **Test Environment Only**: This is for testing purposes only
2. **Fake Signatures**: Transactions have mock signatures and won't pass real verification
3. **MongoDB Required**: Ensure MongoDB is running before starting
4. **Resource Usage**: Monitor system resources during extended runs
5. **Data Cleanup**: Consider cleaning test data periodically

## 🐛 Troubleshooting

### MongoDB Connection Issues
```
❌ Failed to initialize generator: failed to connect to MongoDB
```
**Solution**: Ensure MongoDB is running on `localhost:27017`

### Go Module Issues
```
❌ Package not found errors
```
**Solution**: Run `go mod tidy` in the project root

### Permission Issues (Linux/Mac)
```
❌ Permission denied
```
**Solution**: Run `chmod +x run_fake_transactions.sh`

## 📚 Related Files

- `test-tools/fake_transaction_generator.go` - Main generator code
- `test-tools/go.mod` - Go module configuration for the generator
- `run_fake_transactions.bat` - Windows runner script
- `run_fake_transactions.sh` - Linux/Mac runner script
- `main.go` - Main wallet application
- `wallet/transaction_history.go` - Transaction history functionality
