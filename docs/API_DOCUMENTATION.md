# Blackhole Blockchain API Documentation

## Overview
Complete API documentation for the Blackhole Blockchain ecosystem including wallet operations, DEX trading, staking, escrow, multi-signature wallets, OTC trading, and cross-chain bridge functionality.

## Base URLs
- **Blockchain Node**: `http://localhost:8080`
- **Wallet Service**: `http://localhost:4000`

## Authentication
Most wallet operations require user authentication. Use the login endpoint to obtain session credentials.

---

## 🏦 Wallet APIs

### User Management

#### Register User
```http
POST /api/users/register
Content-Type: application/json

{
  "username": "alice",
  "password": "secure_password"
}
```

#### Login User
```http
POST /api/users/login
Content-Type: application/json

{
  "username": "alice",
  "password": "secure_password"
}
```

### Wallet Operations

#### Create Wallet from Mnemonic
```http
POST /api/wallets/create
Authorization: Bearer <token>
Content-Type: application/json

{
  "wallet_name": "my_wallet",
  "password": "wallet_password"
}
```

#### Import Wallet from Private Key
```http
POST /api/wallets/import
Authorization: Bearer <token>
Content-Type: application/json

{
  "wallet_name": "imported_wallet",
  "password": "wallet_password",
  "private_key": "0x1234567890abcdef..."
}
```

#### Export Wallet Private Key
```http
POST /api/wallets/export
Authorization: Bearer <token>
Content-Type: application/json

{
  "wallet_name": "my_wallet",
  "password": "wallet_password"
}
```

#### List User Wallets
```http
GET /api/wallets
Authorization: Bearer <token>
```

#### Get Wallet Details
```http
GET /api/wallets/{wallet_name}
Authorization: Bearer <token>
```

### Token Operations

#### Check Token Balance
```http
GET /api/wallets/{wallet_name}/balance/{token_symbol}
Authorization: Bearer <token>
```

#### Transfer Tokens
```http
POST /api/wallets/transfer
Authorization: Bearer <token>
Content-Type: application/json

{
  "wallet_name": "my_wallet",
  "password": "wallet_password",
  "to_address": "recipient_address",
  "token_symbol": "BHX",
  "amount": 100
}
```

#### Stake Tokens
```http
POST /api/wallets/stake
Authorization: Bearer <token>
Content-Type: application/json

{
  "wallet_name": "my_wallet",
  "password": "wallet_password",
  "token_symbol": "BHX",
  "amount": 500
}
```

#### Transaction History
```http
GET /api/wallets/{wallet_name}/transactions?limit=50
Authorization: Bearer <token>
```

---

## 🏛️ Blockchain APIs

### Blockchain Information

#### Get Blockchain Stats
```http
GET /api/blockchain/info
```

**Response:**
```json
{
  "blockHeight": 1234,
  "pendingTxs": 5,
  "totalSupply": 1000000000,
  "blockReward": 10,
  "accounts": {...},
  "tokenBalances": {...},
  "stakes": {...},
  "recentBlocks": [...]
}
```

#### Get Node Information
```http
GET /api/node/info
```

**Response:**
```json
{
  "peer_id": "12D3KooW...",
  "addresses": [
    "/ip4/127.0.0.1/tcp/3000/p2p/12D3KooW..."
  ]
}
```

### Admin Operations

#### Add Tokens to Address
```http
POST /api/admin/add-tokens
Content-Type: application/json

{
  "address": "wallet_address",
  "token": "BHX",
  "amount": 1000
}
```

---

## 💱 DEX APIs

### Pool Operations

#### Create Trading Pair
```http
POST /api/dex/pairs
Content-Type: application/json

{
  "token_a": "BHX",
  "token_b": "USDT",
  "initial_reserve_a": 10000,
  "initial_reserve_b": 50000
}
```

#### Add Liquidity
```http
POST /api/dex/liquidity/add
Content-Type: application/json

{
  "token_a": "BHX",
  "token_b": "USDT",
  "amount_a": 1000,
  "amount_b": 5000,
  "provider": "provider_address"
}
```

#### Get Swap Quote
```http
GET /api/dex/quote?token_in=BHX&token_out=USDT&amount_in=100
```

#### Execute Swap
```http
POST /api/dex/swap
Content-Type: application/json

{
  "token_in": "BHX",
  "token_out": "USDT",
  "amount_in": 100,
  "min_amount_out": 450,
  "trader": "trader_address"
}
```

#### Get Pool Status
```http
GET /api/dex/pools/{token_a}-{token_b}
```

#### Get All Pools
```http
GET /api/dex/pools
```

---

## 🔒 Escrow APIs

### Escrow Operations

#### Create Escrow
```http
POST /api/escrow/create
Content-Type: application/json

{
  "sender": "sender_address",
  "receiver": "receiver_address",
  "arbitrator": "arbitrator_address",
  "token_symbol": "BHX",
  "amount": 1000,
  "expiration_hours": 24,
  "description": "Payment for services"
}
```

#### Confirm Escrow
```http
POST /api/escrow/{escrow_id}/confirm
Content-Type: application/json

{
  "signer": "signer_address"
}
```

#### Release Escrow
```http
POST /api/escrow/{escrow_id}/release
Content-Type: application/json

{
  "releaser": "releaser_address"
}
```

#### Cancel Escrow
```http
POST /api/escrow/{escrow_id}/cancel
Content-Type: application/json

{
  "canceller": "canceller_address"
}
```

#### Get Escrow Details
```http
GET /api/escrow/{escrow_id}
```

#### Get User Escrows
```http
GET /api/escrow/user/{user_address}
```

---

## 🔐 Multi-Signature Wallet APIs

### Multi-Sig Operations

#### Create Multi-Sig Wallet
```http
POST /api/multisig/wallets
Content-Type: application/json

{
  "owners": ["owner1", "owner2", "owner3"],
  "required_sigs": 2
}
```

#### Propose Transaction
```http
POST /api/multisig/transactions/propose
Content-Type: application/json

{
  "wallet_id": "multisig_wallet_id",
  "proposer": "proposer_address",
  "to": "recipient_address",
  "token_symbol": "BHX",
  "amount": 1000,
  "expiration_hours": 48
}
```

#### Sign Transaction
```http
POST /api/multisig/transactions/{tx_id}/sign
Content-Type: application/json

{
  "signer": "signer_address"
}
```

#### Get Wallet Details
```http
GET /api/multisig/wallets/{wallet_id}
```

#### Get Pending Transactions
```http
GET /api/multisig/wallets/{wallet_id}/pending
```

---

## 🤝 OTC Trading APIs

### OTC Operations

#### Create OTC Order
```http
POST /api/otc/orders
Content-Type: application/json

{
  "creator": "creator_address",
  "token_offered": "BHX",
  "amount_offered": 1000,
  "token_requested": "USDT",
  "amount_requested": 5000,
  "expiration_hours": 24,
  "is_multisig": false,
  "required_sigs": []
}
```

#### Match Order
```http
POST /api/otc/orders/{order_id}/match
Content-Type: application/json

{
  "counterparty": "counterparty_address"
}
```

#### Sign Order (Multi-Sig)
```http
POST /api/otc/orders/{order_id}/sign
Content-Type: application/json

{
  "signer": "signer_address"
}
```

#### Cancel Order
```http
POST /api/otc/orders/{order_id}/cancel
Content-Type: application/json

{
  "canceller": "canceller_address"
}
```

#### Get Open Orders
```http
GET /api/otc/orders/open
```

#### Get User Orders
```http
GET /api/otc/orders/user/{user_address}
```

#### Get User Trades
```http
GET /api/otc/trades/user/{user_address}
```

---

## 🌉 Cross-Chain Bridge APIs

### Bridge Operations

#### Initiate Bridge Transfer
```http
POST /api/bridge/transfer
Content-Type: application/json

{
  "source_chain": "blackhole",
  "dest_chain": "ethereum",
  "source_address": "blackhole_address",
  "dest_address": "0x742d35Cc...",
  "token_symbol": "BHX",
  "amount": 1000
}
```

#### Get Bridge Transaction
```http
GET /api/bridge/transactions/{bridge_tx_id}
```

#### Get User Bridge Transactions
```http
GET /api/bridge/transactions/user/{user_address}
```

#### Get Supported Chains
```http
GET /api/bridge/chains
```

#### Get Token Mappings
```http
GET /api/bridge/tokens/{chain_type}
```

---

## 📊 Testing Endpoints

### Health Check
```http
GET /api/health
```

### Generate Test Data
```http
POST /api/test/generate-data
```

### Reset Test Environment
```http
POST /api/test/reset
```

---

## Error Responses

All APIs return errors in the following format:

```json
{
  "success": false,
  "error": "Error message description",
  "code": "ERROR_CODE"
}
```

## Success Responses

Successful operations return:

```json
{
  "success": true,
  "data": {...},
  "message": "Operation completed successfully"
}
```

---

## Rate Limiting

- **Wallet APIs**: 100 requests per minute per user
- **Blockchain APIs**: 1000 requests per minute
- **Admin APIs**: 10 requests per minute

## WebSocket Endpoints

### Real-time Updates
```
ws://localhost:8080/ws/blockchain
ws://localhost:8080/ws/dex
ws://localhost:8080/ws/escrow
```

---

This documentation covers all implemented features. Use the HTML dashboard at `http://localhost:8080` for interactive testing and monitoring.
