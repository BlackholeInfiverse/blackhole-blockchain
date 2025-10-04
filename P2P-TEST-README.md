# P2P Transaction Testing Guide

## 🚀 Quick Start

### Option 1: Automated Test Script (Recommended)
```powershell
.\test-p2p-transaction.ps1
```

This will:
1. Start the blockchain node
2. Build the wallet
3. Guide you through testing P2P transactions

### Option 2: Manual Testing

#### Step 1: Start Blockchain Node
```powershell
docker-compose up -d blockchain
```

Wait for it to be healthy (~10 seconds):
```powershell
docker-compose ps
```

#### Step 2: Get Node Peer ID
```powershell
$nodeInfo = (Invoke-WebRequest -Uri "http://localhost:8081/api/node/info").Content | ConvertFrom-Json
Write-Host "Peer ID: $($nodeInfo.secure_p2p_peer_id)"
```

#### Step 3: Build & Run Wallet
```powershell
cd core\relay-chain\cmd\enhanced-wallet
go build -o enhanced-wallet.exe main.go
.\enhanced-wallet.exe
```

## 📝 Testing P2P Transactions

### In the Wallet Menu:

1. **Option 1**: Discover networks
   - Should automatically find the running blockchain node
   - You'll see node details including Peer ID

2. **Option 2** or **Option 5**: Connect
   - **Option 2**: Select from discovered networks
   - **Option 5**: Manual connect (paste the Peer ID from Step 2)

3. **Option 3**: Verify connection
   - Confirms you're connected to the blockchain

4. **Option 7**: Send P2P Transaction
   - Enter sender address (or press Enter for default)
   - Enter recipient address (or press Enter for default)
   - Enter amount (e.g., `10.5`)
   - Confirm the transaction
   - Transaction will be sent over P2P to the blockchain node

5. **Option 6**: View wallet info
   - See your wallet's P2P peer ID and connected networks

## 🔍 Troubleshooting

### Wallet can't discover networks
- Check if blockchain node is running: `docker-compose ps`
- Check node logs: `docker-compose logs blockchain`
- Try manual connection (Option 5) with the Peer ID

### Connection fails
The wallet tries these ports in order:
1. **3001** - Docker-exposed secure P2P
2. **3100** - Docker-exposed legacy P2P  
3. **30303** - Docker-exposed P2P networking
4. **3002, 3101** - Direct local node ports

**Fix**: Ensure Docker ports are exposed:
```powershell
# Check docker-compose.yml has these port mappings:
# - "3001:3001"   # Secure P2P
# - "3100:3100"   # Legacy P2P
# - "30303:30303" # P2P networking
```

### Transaction sending fails
- Ensure you're connected first (Option 3 to verify)
- Check blockchain node logs: `docker-compose logs -f blockchain`
- Try reconnecting (Option 8 to disconnect, then Option 2 to reconnect)

## 🧹 Cleanup

Stop blockchain node:
```powershell
docker-compose down
```

## 📊 What to Expect

### Successful P2P Transaction Flow:
1. ✅ Wallet discovers blockchain node
2. ✅ Wallet connects to node via P2P (libp2p)
3. ✅ Transaction is sent over P2P stream
4. ✅ Blockchain node receives and processes transaction
5. ✅ Transaction hash is returned to wallet

### Transaction Data Format:
```json
{
  "from": "wallet_12345678",
  "to": "node_blackhole",
  "amount": 10.5,
  "timestamp": 1699999999
}
```

## 🎯 Success Indicators

- [ ] Wallet discovers blockchain node automatically
- [ ] Wallet connects successfully (check with Option 3)
- [ ] Option 7 sends transaction without errors
- [ ] Transaction hash is returned
- [ ] No "connection failed" or "stream error" messages

## 📚 Advanced Usage

### Test with Multiple Nodes
```powershell
# Start multiple blockchain nodes
docker-compose up -d

# Wallet will discover all running nodes
# Connect to any node and send transactions
```

### Rebuild Everything
```powershell
.\test-p2p-transaction.ps1 -RebuildDocker
```

## 🐛 Debug Mode

Check wallet P2P connection details:
```powershell
# In wallet, use Option 6 (Show wallet info)
# Shows: Wallet Peer ID, Addresses, Connected Networks
```

Check blockchain node P2P status:
```powershell
# Visit dashboard
Start-Process "http://localhost:8081"
# Look for "P2P Network Information" section
```