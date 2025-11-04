# 🔗 Blockchain API Reference

Complete API reference for core blockchain operations.

**Base URL**: `http://localhost:8080/api`

## 📊 **Health & Status**

### GET /health
Get blockchain health status.

**Response**:
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "block_height": 12345,
    "validator_count": 5,
    "pending_txs": 3,
    "timestamp": 1703123456,
    "version": "1.0.0"
  }
}
```

### GET /status
Get detailed blockchain status.

**Response**:
```json
{
  "success": true,
  "data": {
    "chain_id": "blackhole-mainnet",
    "latest_block_hash": "0x1234...",
    "latest_block_height": 12345,
    "latest_block_time": "2024-12-01T10:00:00Z",
    "total_supply": 1000000000,
    "circulating_supply": 800000000,
    "validator_count": 5,
    "active_validators": 4,
    "pending_transactions": 3,
    "network_hash_rate": "1.5 TH/s"
  }
}
```

## 🧱 **Block Operations**

### GET /blocks/latest
Get the latest block.

**Response**:
```json
{
  "success": true,
  "data": {
    "index": 12345,
    "hash": "0x1234567890abcdef...",
    "previous_hash": "0xabcdef1234567890...",
    "timestamp": "2024-12-01T10:00:00Z",
    "validator": "0x742d35Cc6634C0532925a3b8D4",
    "transactions": [
      {
        "id": "tx_1234567890",
        "type": "transfer",
        "from": "0x742d35Cc6634C0532925a3b8D4",
        "to": "0x8ba1f109551bD432803012645",
        "amount": 1000000,
        "token": "BHX",
        "fee": 1000,
        "status": "confirmed"
      }
    ],
    "transaction_count": 5,
    "size": 2048,
    "gas_used": 21000,
    "gas_limit": 8000000
  }
}
```

### GET /blocks/{height}
Get block by height.

**Parameters**:
- `height` (path): Block height number

**Response**: Same as `/blocks/latest`

### GET /blocks/{hash}
Get block by hash.

**Parameters**:
- `hash` (path): Block hash

**Response**: Same as `/blocks/latest`

### GET /blocks
Get blocks with pagination.

**Query Parameters**:
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 10, max: 100)
- `order` (optional): Sort order - `asc` or `desc` (default: desc)

**Response**:
```json
{
  "success": true,
  "data": {
    "blocks": [
      // Array of block objects
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 12345,
      "pages": 1235
    }
  }
}
```

## 💸 **Transaction Operations**

### POST /transactions
Submit a new transaction.

**Request Body**:
```json
{
  "type": "transfer",
  "from": "0x742d35Cc6634C0532925a3b8D4",
  "to": "0x8ba1f109551bD432803012645",
  "amount": 1000000,
  "token": "BHX",
  "gas_limit": 21000,
  "gas_price": 20,
  "nonce": 42,
  "signature": "0x1234567890abcdef..."
}
```

**Response**:
```json
{
  "success": true,
  "data": {
    "transaction_id": "tx_1234567890",
    "hash": "0xabcdef1234567890...",
    "status": "pending",
    "submitted_at": "2024-12-01T10:00:00Z"
  }
}
```

### GET /transactions/{id}
Get transaction by ID.

**Parameters**:
- `id` (path): Transaction ID

**Response**:
```json
{
  "success": true,
  "data": {
    "id": "tx_1234567890",
    "hash": "0xabcdef1234567890...",
    "type": "transfer",
    "from": "0x742d35Cc6634C0532925a3b8D4",
    "to": "0x8ba1f109551bD432803012645",
    "amount": 1000000,
    "token": "BHX",
    "fee": 1000,
    "gas_used": 21000,
    "gas_price": 20,
    "nonce": 42,
    "status": "confirmed",
    "block_height": 12345,
    "block_hash": "0x1234567890abcdef...",
    "timestamp": "2024-12-01T10:00:00Z",
    "confirmations": 6
  }
}
```

### GET /transactions
Get transactions with filtering.

**Query Parameters**:
- `address` (optional): Filter by from/to address
- `type` (optional): Filter by transaction type
- `status` (optional): Filter by status
- `page` (optional): Page number
- `limit` (optional): Items per page

**Response**:
```json
{
  "success": true,
  "data": {
    "transactions": [
      // Array of transaction objects
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 5432,
      "pages": 544
    }
  }
}
```

### GET /transactions/pending
Get pending transactions.

**Response**:
```json
{
  "success": true,
  "data": {
    "pending_transactions": [
      // Array of pending transaction objects
    ],
    "count": 15
  }
}
```

## 💰 **Balance & Account Operations**

### GET /accounts/{address}/balance
Get account balance.

**Parameters**:
- `address` (path): Account address

**Query Parameters**:
- `token` (optional): Specific token symbol (default: all tokens)

**Response**:
```json
{
  "success": true,
  "data": {
    "address": "0x742d35Cc6634C0532925a3b8D4",
    "balances": {
      "BHX": 1000000000,
      "USDT": 500000000,
      "ETH": 100000000
    },
    "total_value_usd": 15000.50,
    "last_updated": "2024-12-01T10:00:00Z"
  }
}
```

### GET /accounts/{address}/transactions
Get account transaction history.

**Parameters**:
- `address` (path): Account address

**Query Parameters**:
- `type` (optional): Transaction type filter
- `page` (optional): Page number
- `limit` (optional): Items per page

**Response**: Same format as `/transactions`

## 🏛️ **Validator Operations**

### GET /validators
Get all validators.

**Response**:
```json
{
  "success": true,
  "data": {
    "validators": [
      {
        "address": "0x742d35Cc6634C0532925a3b8D4",
        "stake": 1000000000,
        "status": "active",
        "commission": 0.05,
        "uptime": 0.99,
        "blocks_produced": 1234,
        "last_block_time": "2024-12-01T09:55:00Z",
        "jailed": false,
        "strikes": 0
      }
    ],
    "total_stake": 5000000000,
    "active_count": 4,
    "total_count": 5
  }
}
```

### GET /validators/{address}
Get specific validator details.

**Parameters**:
- `address` (path): Validator address

**Response**:
```json
{
  "success": true,
  "data": {
    "address": "0x742d35Cc6634C0532925a3b8D4",
    "stake": 1000000000,
    "status": "active",
    "commission": 0.05,
    "uptime": 0.99,
    "blocks_produced": 1234,
    "last_block_time": "2024-12-01T09:55:00Z",
    "jailed": false,
    "strikes": 0,
    "delegators": 150,
    "total_delegated": 500000000,
    "rewards_earned": 50000000,
    "slashing_events": []
  }
}
```

## 🌐 **Network Operations**

### GET /network/peers
Get network peer information.

**Response**:
```json
{
  "success": true,
  "data": {
    "peers": [
      {
        "id": "12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R",
        "address": "/ip4/127.0.0.1/tcp/3000",
        "connected": true,
        "latency": "15ms",
        "version": "1.0.0"
      }
    ],
    "connected_count": 8,
    "max_peers": 50
  }
}
```

### GET /network/stats
Get network statistics.

**Response**:
```json
{
  "success": true,
  "data": {
    "total_transactions": 1234567,
    "total_blocks": 12345,
    "average_block_time": 5.2,
    "transactions_per_second": 150,
    "network_hash_rate": "1.5 TH/s",
    "difficulty": 1000000,
    "total_supply": 1000000000,
    "circulating_supply": 800000000,
    "market_cap_usd": 12000000
  }
}
```
