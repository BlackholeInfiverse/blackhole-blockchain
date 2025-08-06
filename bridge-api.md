# BlackHole Bridge API Documentation

## Overview

The BlackHole Bridge API provides comprehensive cross-chain transaction processing, wallet monitoring, and system management capabilities. This document covers both REST and gRPC endpoints with detailed examples and usage guidelines.

## Base URL
- **REST API**: `http://localhost:8084/api`
- **gRPC Service**: `localhost:9090`
- **WebSocket**: `ws://localhost:8084/ws`

## Authentication
Currently, the bridge operates without authentication for development purposes. Production deployments should implement proper authentication mechanisms.

---

## REST API Endpoints

### Transaction Processing

#### POST /api/bridge/transfer
Process a cross-chain transaction through the bridge.

**Request Body:**
```json
{
  "sourceChain": "ethereum",
  "destChain": "solana", 
  "sourceAddress": "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87",
  "destAddress": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
  "amount": "100.5",
  "tokenSymbol": "USDT",
  "priority": "normal",
  "confirmations": 12,
  "timeout": 300
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "transaction_id": "tx_1754454567890",
    "hash": "0xabc123...",
    "status": "pending",
    "estimated_completion": "2025-08-06T10:15:00Z",
    "tracking_url": "/api/transactions/tx_1754454567890"
  },
  "message": "Transaction initiated successfully"
}
```

#### GET /api/transactions/{id}
Retrieve transaction details by ID.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "tx_1754454567890",
    "hash": "0xabc123...",
    "sourceChain": "ethereum",
    "destChain": "solana",
    "amount": "100.5",
    "tokenSymbol": "USDT",
    "status": "completed",
    "confirmations": 15,
    "processingTime": "45.2s",
    "createdAt": "2025-08-06T10:00:00Z",
    "completedAt": "2025-08-06T10:00:45Z"
  }
}
```

### Wallet Operations

#### GET /api/wallet/transactions
Retrieve wallet transaction history with real-time updates.

**Query Parameters:**
- `address` (optional): Filter by wallet address
- `token` (optional): Filter by token symbol
- `limit` (optional): Number of transactions to return (default: 50)
- `since` (optional): Timestamp to get transactions since

**Response:**
```json
{
  "success": true,
  "total_count": 25,
  "new_transfers": 3,
  "source": "persistent_database",
  "transactions": [
    {
      "id": "NEW_TRANSFER_BHX_0222fa8467658c6b58e4e957ea0a34a3f8ffcc80472d89c66dd3d7c690f56f5dd1_19_1754369984",
      "hash": "0x123...",
      "from": "admin",
      "to": "0222fa8467658c6b58e4e957ea0a34a3f8ffcc80472d89c66dd3d7c690f56f5dd1",
      "amount": "19",
      "token": "BHX",
      "status": "confirmed",
      "timestamp": 1754369984,
      "type": "real_transfer",
      "isNew": true
    }
  ]
}
```

#### POST /api/wallet/transactions/mark-read
Mark a transaction as read (changes isNew status).

**Request Body:**
```json
{
  "transactionId": "NEW_TRANSFER_BHX_0222fa8467658c6b58e4e957ea0a34a3f8ffcc80472d89c66dd3d7c690f56f5dd1_19_1754369984"
}
```

### System Monitoring

#### GET /api/log/status
Get comprehensive system status and health information.

**Response:**
```json
{
  "success": true,
  "data": {
    "bridge_healthy": true,
    "database_connected": true,
    "uptime_seconds": 3600,
    "version": "1.0.0",
    "listeners": {
      "ethereum": true,
      "solana": true,
      "blackhole": true
    },
    "performance": {
      "cpu_usage": 15.2,
      "memory_usage": 45.8,
      "active_connections": 12,
      "events_per_second": 2.5,
      "average_response_time": 150.3,
      "error_count": 2
    }
  },
  "timestamp": "2025-08-06T10:00:00Z"
}
```

#### GET /api/log/retry
Get detailed retry queue information and statistics.

**Response:**
```json
{
  "success": true,
  "data": {
    "active_items": [
      {
        "id": "retry_1754454567890",
        "type": "ethereum_event",
        "attempts": 2,
        "max_attempts": 5,
        "next_retry": "2025-08-06T10:05:00Z",
        "created_at": "2025-08-06T10:00:00Z",
        "last_error": "RPC connection timeout",
        "status": "pending"
      }
    ],
    "dead_letter_items": [
      {
        "id": "retry_1754454567891",
        "type": "solana_event", 
        "attempts": 5,
        "max_attempts": 5,
        "status": "dead_letter",
        "final_error": "Maximum retry attempts exceeded"
      }
    ],
    "stats": {
      "total_items": 15,
      "pending_items": 3,
      "processing_items": 1,
      "failed_items": 2,
      "dead_letter_items": 1,
      "success_rate": 87.5
    }
  }
}
```

### Bridge Statistics

#### GET /api/bridge/stats
Get comprehensive bridge performance statistics.

**Response:**
```json
{
  "success": true,
  "data": {
    "total_transactions": 1250,
    "pending_transactions": 5,
    "completed_transactions": 1200,
    "failed_transactions": 45,
    "total_volume": "2,450,000 USD",
    "success_rate": 96.0,
    "average_processing_time": 42.5,
    "chain_stats": {
      "ethereum": {
        "transactions": 450,
        "volume": "1,200,000 USD",
        "avg_confirmation_time": 45.2,
        "is_healthy": true
      },
      "solana": {
        "transactions": 380,
        "volume": "850,000 USD", 
        "avg_confirmation_time": 12.8,
        "is_healthy": true
      },
      "blackhole": {
        "transactions": 420,
        "volume": "400,000 USD",
        "avg_confirmation_time": 8.5,
        "is_healthy": true
      }
    }
  }
}
```

### Admin Operations

#### GET /api/main-dashboard/activities
Get admin dashboard activities showing wallet balances and system events.

**Response:**
```json
{
  "success": true,
  "data": {
    "activities": [
      {
        "id": "wallet_1",
        "action": "Wallet Balance",
        "details": {
          "address": "0222fa8467658c6b58e4e957ea0a34a3f8ffcc80472d89c66dd3d7c690f56f5dd1",
          "token": "BHX",
          "amount": 10216
        },
        "timestamp": "2025-08-06T10:00:00Z",
        "source": "blockchain_monitor"
      }
    ],
    "total_count": 2,
    "last_updated": "2025-08-06T10:00:00Z"
  }
}
```

---

## WebSocket Events

### Connection
Connect to `ws://localhost:8084/ws` for real-time event streaming.

### Event Types

#### Transaction Updates
```json
{
  "type": "transaction_update",
  "transaction_id": "tx_1754454567890",
  "status": "completed",
  "confirmations": 15,
  "timestamp": "2025-08-06T10:00:45Z"
}
```

#### Wallet Events
```json
{
  "type": "wallet_transaction",
  "wallet_address": "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87",
  "transaction": {
    "amount": "50.0",
    "token": "BHX",
    "type": "real_transfer"
  },
  "timestamp": "2025-08-06T10:00:00Z"
}
```

#### System Alerts
```json
{
  "type": "system_alert",
  "severity": "warning",
  "message": "Low throughput detected",
  "details": {
    "events_per_second": 0.5,
    "threshold": 1.0
  },
  "timestamp": "2025-08-06T10:00:00Z"
}
```

---

## gRPC Service Methods

### Transaction Processing
- `ProcessTransaction`: Initiate cross-chain transaction
- `GetTransaction`: Retrieve transaction by ID
- `ListTransactions`: Get paginated transaction list
- `GetTransactionStatus`: Get current transaction status

### Wallet Operations  
- `GetWalletTransactions`: Retrieve wallet transaction history
- `GetWalletBalance`: Get current wallet balances
- `MonitorWallet`: Stream wallet events in real-time

### Bridge Operations
- `RelayToChain`: Relay transaction to target chain
- `GetBridgeStats`: Retrieve bridge performance statistics
- `GetChainStatus`: Get individual chain health status

### System Monitoring
- `GetSystemStatus`: Comprehensive system health check
- `GetPerformanceMetrics`: Detailed performance statistics
- `StreamEvents`: Real-time event streaming
- `GetRetryQueue`: Retry mechanism status
- `GetDeadLetterQueue`: Failed transaction queue

---

## Error Handling

### HTTP Status Codes
- `200`: Success
- `400`: Bad Request - Invalid parameters
- `404`: Not Found - Resource doesn't exist
- `500`: Internal Server Error
- `503`: Service Unavailable - System maintenance

### Error Response Format
```json
{
  "success": false,
  "error": {
    "code": "INVALID_TRANSACTION",
    "message": "Transaction amount must be positive",
    "details": {
      "field": "amount",
      "value": "-10"
    }
  },
  "timestamp": "2025-08-06T10:00:00Z"
}
```

---

## Rate Limiting
- Default: 100 requests per minute per IP
- Burst: Up to 20 requests in 10 seconds
- WebSocket: 1000 events per minute

## SDK Usage Examples

### JavaScript/Node.js
```javascript
const bridge = new BridgeClient('http://localhost:8084');

// Process transaction
const result = await bridge.processTransaction({
  sourceChain: 'ethereum',
  destChain: 'solana',
  amount: '100.0',
  tokenSymbol: 'USDT'
});

// Monitor wallet
bridge.monitorWallet('0x742d35...', (event) => {
  console.log('Wallet event:', event);
});
```

### Go
```go
client := bridge.NewClient("localhost:9090")
resp, err := client.ProcessTransaction(ctx, &bridge.ProcessTransactionRequest{
    SourceChain: "ethereum",
    DestChain:   "solana", 
    Amount:      "100.0",
    TokenSymbol: "USDT",
})
```
