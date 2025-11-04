# Blackhole Blockchain Wallet Usage Guide

## Quick Start

### 1. Start the Blockchain Node
```bash
cd core/relay-chain/cmd/relay
go run main.go 3000
```

Copy the peer multiaddr from the output, for example:
```
🚀 Your peer multiaddr:
   /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R
```

### 2. Start the Wallet Service

#### Option A: With Blockchain Connection (Recommended)
```bash
cd services/wallet
go run main.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R
```

#### Option B: Offline Mode
```bash
cd services/wallet
go run main.go
```

## Command-Line Options

### -peerAddr
Specifies the blockchain node peer address to connect to.

**Format**: `/ip4/<IP>/tcp/<PORT>/p2p/<PEER_ID>`

**Examples**:
- `/ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R`
- `/ip4/192.168.1.100/tcp/3001/p2p/12D3KooWKzQh2siF6pAidubw16GrZDhRZqFSeEJFA7BCcKvpopmG`

## Connection Status

### Successful Connection
```
🔗 Connecting to blockchain node: /ip4/127.0.0.1/tcp/3000/p2p/12D3KooW...
✅ Connected to blockchain node: /ip4/127.0.0.1/tcp/3000/p2p/12D3KooW...
✅ Successfully connected to blockchain node!
```

### Failed Connection
```
🔗 Connecting to blockchain node: /ip4/127.0.0.1/tcp/3000/p2p/12D3KooW...
⚠️ Failed to connect to blockchain node: failed to connect to peer
⚠️ Wallet will work in offline mode. Check the peer address and try again.
```

### No Peer Address Provided
```
⚠️ No peer address provided. Use -peerAddr flag to connect to blockchain node.
⚠️ Example: go run main.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R
⚠️ Wallet will work in offline mode.
```

## Wallet Features

### Online Mode (Connected to Blockchain)
- ✅ Real token transfers
- ✅ Real staking operations
- ✅ Transaction broadcasting to network
- ✅ Balance validation
- ✅ Transaction history recording

### Offline Mode
- ✅ Wallet creation and management
- ✅ Private key import/export
- ✅ User registration and login
- ❌ Token transfers (will fail)
- ❌ Staking operations (will fail)
- ❌ Real balance checking

## Troubleshooting

### "Failed to connect to blockchain node"
1. Ensure the blockchain node is running
2. Copy the exact peer multiaddr from the blockchain node output
3. Check that the IP address and port are correct
4. Verify no firewall is blocking the connection

### "Invalid multiaddr"
1. Check the peer address format
2. Ensure it starts with `/ip4/`
3. Verify the peer ID is correct (starts with `12D3KooW`)

### "MongoDB connection error"
1. Start MongoDB: `mongod`
2. Check MongoDB is running on `localhost:27017`
3. Verify MongoDB service is accessible

## Advanced Usage

### Multiple Blockchain Nodes
You can connect to different blockchain nodes by changing the peer address:

```bash
# Connect to node on port 3000
go run main.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/12D3KooW...

# Connect to node on port 3001
go run main.go -peerAddr /ip4/127.0.0.1/tcp/3001/p2p/12D3KooW...

# Connect to remote node
go run main.go -peerAddr /ip4/192.168.1.100/tcp/3000/p2p/12D3KooW...
```

### Batch File Usage
Use the provided `start_wallet.bat` for interactive peer address input:

```cmd
start_wallet.bat
```

This will prompt you to enter the peer address or run in offline mode.

## Integration with HTML Dashboard

When connected to a blockchain node, you can:

1. **Monitor transactions** in real-time at `http://localhost:8080`
2. **Add test tokens** using the admin panel
3. **View wallet balances** and staking information
4. **Track transaction history** and block mining

The wallet CLI and HTML dashboard work together to provide a complete blockchain experience.
