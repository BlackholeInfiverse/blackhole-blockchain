# Complete Blockchain Workflow Test with UI Dashboard

This guide demonstrates how to test the complete blockchain workflow including wallet operations, staking, validators, rewards, and the new HTML UI dashboard.

## ✅ Fixed Issues

1. **✅ Balance Validation**: Transactions now properly validate balances before processing
2. **✅ Staking Mechanism**: Proper staking/unstaking with token locking implemented
3. **✅ Transaction Types**: Different transaction types (Regular, Token, Staking) handled correctly
4. **✅ HTML UI Dashboard**: Real-time blockchain monitoring and admin panel
5. **✅ Token Management**: Proper token minting, burning, and balance tracking

## Prerequisites

1. **MongoDB**: Make sure MongoDB is running on `localhost:27017`
2. **Go**: Ensure Go is installed and dependencies are available

## Step 1: Start the Blockchain Node

First, start the main blockchain node that will handle mining, validation, and P2P networking:

```bash
cd core/relay-chain/cmd/relay
go run main.go 3000
```

This will:
- Start a blockchain node on port 3000
- Initialize the genesis block with proper token balances
- Start the mining loop with validators
- **Start HTML UI dashboard on port 8080**
- Display the peer multiaddr (copy this for wallet connection)

Example output:
```
🚀 Your peer multiaddr:
   /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWKzQh2siF6pAidubw16GrZDhRZqFSeEJFA7BCcKvpopmG
```

## Step 2: Update Wallet Configuration

Before starting the wallet service, update the peer address in `services/wallet/main.go`:

1. Copy the peer multiaddr from Step 1
2. Replace the placeholder address in line 54 of `services/wallet/main.go`

## Step 3: Start the Wallet Service

In a new terminal, start the wallet service:

```bash
cd services/wallet
go run main.go
```

This will:
- Connect to MongoDB
- Initialize the blockchain client
- Attempt to connect to the blockchain node
- Start the wallet CLI

## Step 4: Access the HTML UI Dashboard

**Open your browser and go to: `http://localhost:8080`**

The dashboard provides:
- **Real-time blockchain stats** (block height, pending transactions, total supply)
- **Token balances** for all addresses
- **Staking information** showing who has staked tokens
- **Recent blocks** with validator and transaction info
- **Admin panel** to add tokens to any address

## Step 5: Test Wallet Operations

### 5.1 Create User and Wallet

1. Register a new user
2. Login with the user
3. Generate a wallet from mnemonic
4. Note the wallet address

### 5.2 Add Initial Balance (Using UI)

1. Go to the HTML dashboard (`http://localhost:8080`)
2. In the Admin Panel, enter your wallet address
3. Set Token Symbol to "BHX"
4. Add some tokens (e.g., 1000)
5. Click "Add Tokens"

### 5.3 Check Balance

Use option "6. Check Token Balance" in the wallet CLI (will show placeholder for now)
**OR** check the real balance in the HTML dashboard

### 5.4 Transfer Tokens

1. Create another wallet or use a different address
2. Use option "7. Transfer Tokens" to transfer tokens
3. **Watch the HTML dashboard** - you'll see:
   - Pending transactions increase
   - Token balances update after block is mined
   - New block appears in recent blocks

### 5.5 Stake Tokens

1. Use option "8. Stake Tokens" to stake some tokens
2. **Watch the HTML dashboard** - you'll see:
   - Staking information update
   - Tokens moved to staking contract
   - Your address appears in staking table

## Step 6: Observe Blockchain Activity

### In the Blockchain Node Terminal:

1. **Transaction Reception**:
   ```
   📥 Added transaction [hash] from peer [wallet] to pending
   ✅ Transaction validated and added to pending pool
   ```

2. **Balance Validation**:
   ```
   🔄 Applying transaction:
   ➤ Type: 1 (TokenTransfer)
   ➤ From: [address]
   ➤ To: [address]
   ➤ Amount: 100
   ➤ TokenID: BHX
   ✅ Token transfer applied successfully
   ```

3. **Block Mining**:
   ```
   🏗️ Mining block 1 with validator: genesis-validator
   ✅ Block 1 added successfully
   ```

4. **Validator Rewards**:
   ```
   💰 Validator genesis-validator received reward: 10 BHX
   ```

5. **Stake Updates**:
   ```
   ✅ Stake deposit applied successfully: 500 BHX staked by [address]
   📊 New stake for [address]: 500
   ```

### In the HTML Dashboard:

- **Real-time updates** every 3 seconds
- **Token balances** change immediately after transactions
- **Staking table** updates when users stake/unstake
- **Block list** shows new blocks as they're mined
- **Pending transactions** counter updates

## Step 6: Test Multiple Nodes (Optional)

To test the P2P network:

1. Start a second blockchain node:
   ```bash
   go run main.go 3001 /ip4/127.0.0.1/tcp/3000/p2p/[PEER_ID_FROM_FIRST_NODE]
   ```

2. Both nodes should sync and share transactions/blocks

## Expected Workflow

1. **Wallet creates transaction** → Sends via P2P to blockchain node
2. **Blockchain node receives transaction** → Adds to pending pool
3. **Mining loop selects validator** → Creates block with pending transactions
4. **Block is mined** → Transactions are applied to state
5. **Validator receives reward** → New tokens are minted
6. **Stake ledger is updated** → Staking rewards are distributed

## Troubleshooting

### Wallet Can't Connect to Blockchain
- Ensure blockchain node is running first
- Check the peer multiaddr is correct
- Verify ports are not blocked

### Transactions Not Appearing
- Check P2P connection status
- Verify transaction format is correct
- Look for error messages in blockchain node logs

### MongoDB Connection Issues
- Ensure MongoDB is running: `mongod`
- Check connection string in wallet main.go

## Current Limitations

1. **Balance Queries**: Wallet shows placeholder balance (not real blockchain state)
2. **Transaction Signing**: Simplified signing (not cryptographically secure)
3. **Error Handling**: Basic error handling for P2P failures

## Next Steps for Full Implementation

1. Implement proper RPC interface for balance queries
2. Add cryptographic transaction signing
3. Implement transaction confirmation tracking
4. Add proper error handling and retry logic
5. Create a web interface for easier testing
