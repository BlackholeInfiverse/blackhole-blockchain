# BlackHole Bridge SDK - API Documentation

## 🔌 REST API Reference

The BlackHole Bridge SDK provides a comprehensive REST API for monitoring, managing, and interacting with the cross-chain bridge system.

## 📡 Base URL

```
http://localhost:8084
```

## 🔐 Authentication

Currently, the API does not require authentication for read operations. Write operations may require API key authentication in production environments.

## 📊 Response Format

All API responses follow a consistent JSON format:

```json
{
  "success": true,
  "data": {},
  "error": null,
  "timestamp": "2023-12-01T12:00:00Z"
}
```

## 🏠 Dashboard Endpoints

### GET /
**Description**: Main dashboard interface
**Response**: HTML dashboard page

```bash
curl http://localhost:8084/
```

## 🏥 Health & Status Endpoints

### GET /health
**Description**: System health status
**Response**: Health information for all components

```bash
curl http://localhost:8084/health
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2023-12-01T12:00:00Z",
    "components": {
      "ethereum_listener": "healthy",
      "solana_listener": "healthy",
      "blackhole_listener": "healthy",
      "database": "healthy",
      "relay_system": "healthy"
    },
    "uptime": "24h30m15s",
    "version": "1.0.0"
  }
}
```

### GET /stats
**Description**: Bridge statistics and metrics
**Response**: Comprehensive bridge statistics

```bash
curl http://localhost:8084/stats
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "total_transactions": 1250,
    "pending_transactions": 5,
    "completed_transactions": 1200,
    "failed_transactions": 45,
    "success_rate": 96.0,
    "total_volume": "125.5",
    "chains": {
      "ethereum": {
        "transactions": 500,
        "volume": "75.2"
      },
      "solana": {
        "transactions": 400,
        "volume": "30.1"
      },
      "blackhole": {
        "transactions": 350,
        "volume": "20.2"
      }
    },
    "last_24h": {
      "transactions": 150,
      "volume": "15.5"
    }
  }
}
```

## 💸 Transaction Endpoints

### GET /transactions
**Description**: Get all transactions with optional filtering
**Query Parameters**:
- `status` (optional): Filter by status (pending, completed, failed)
- `chain` (optional): Filter by source chain (ethereum, solana, blackhole)
- `limit` (optional): Limit number of results (default: 100)
- `offset` (optional): Offset for pagination (default: 0)

```bash
# Get all transactions
curl http://localhost:8084/transactions

# Get pending transactions
curl http://localhost:8084/transactions?status=pending

# Get Ethereum transactions
curl http://localhost:8084/transactions?chain=ethereum

# Get with pagination
curl http://localhost:8084/transactions?limit=50&offset=100
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "transactions": [
      {
        "id": "tx_123456789",
        "hash": "0xabc123...",
        "source_chain": "ethereum",
        "dest_chain": "solana",
        "source_address": "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87",
        "dest_address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        "token_symbol": "ETH",
        "amount": "1.5",
        "fee": "0.001",
        "status": "completed",
        "created_at": "2023-12-01T10:30:00Z",
        "completed_at": "2023-12-01T10:32:15Z",
        "confirmations": 12,
        "block_number": 18500000
      }
    ],
    "total": 1250,
    "limit": 100,
    "offset": 0
  }
}
```

### GET /transaction/{id}
**Description**: Get specific transaction details
**Path Parameters**:
- `id`: Transaction ID or hash

```bash
curl http://localhost:8084/transaction/tx_123456789
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "id": "tx_123456789",
    "hash": "0xabc123...",
    "source_chain": "ethereum",
    "dest_chain": "solana",
    "source_address": "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87",
    "dest_address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    "token_symbol": "ETH",
    "amount": "1.5",
    "fee": "0.001",
    "status": "completed",
    "created_at": "2023-12-01T10:30:00Z",
    "completed_at": "2023-12-01T10:32:15Z",
    "confirmations": 12,
    "block_number": 18500000,
    "gas_used": 21000,
    "gas_price": "20000000000",
    "events": [
      {
        "type": "deposit_detected",
        "timestamp": "2023-12-01T10:30:00Z",
        "data": {}
      },
      {
        "type": "relay_initiated",
        "timestamp": "2023-12-01T10:30:30Z",
        "data": {}
      },
      {
        "type": "relay_completed",
        "timestamp": "2023-12-01T10:32:15Z",
        "data": {}
      }
    ]
  }
}
```

## 🔄 Relay Endpoints

### POST /relay
**Description**: Manually trigger transaction relay
**Request Body**: Transaction details for manual relay

```bash
curl -X POST http://localhost:8084/relay \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id": "tx_123456789",
    "target_chain": "solana",
    "force": false
  }'
```

**Request Body Schema**:
```json
{
  "transaction_id": "string",
  "target_chain": "string",
  "force": "boolean"
}
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "relay_id": "relay_987654321",
    "status": "initiated",
    "estimated_completion": "2023-12-01T12:05:00Z"
  }
}
```

## ⚠️ Error & Monitoring Endpoints

### GET /errors
**Description**: Get error metrics and recent errors
**Query Parameters**:
- `limit` (optional): Limit number of errors (default: 100)
- `severity` (optional): Filter by severity (low, medium, high, critical)

```bash
curl http://localhost:8084/errors
curl http://localhost:8084/errors?severity=high&limit=50
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "error_rate": 2.5,
    "total_errors": 45,
    "errors_by_type": {
      "network_error": 20,
      "validation_error": 15,
      "timeout_error": 10
    },
    "recent_errors": [
      {
        "id": "err_123",
        "type": "network_error",
        "severity": "medium",
        "message": "Connection timeout to Ethereum RPC",
        "timestamp": "2023-12-01T11:45:00Z",
        "component": "ethereum_listener",
        "resolved": false
      }
    ]
  }
}
```

### GET /circuit-breakers
**Description**: Get circuit breaker status for all components

```bash
curl http://localhost:8084/circuit-breakers
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "circuit_breakers": [
      {
        "name": "ethereum_listener",
        "state": "closed",
        "failure_count": 0,
        "failure_threshold": 5,
        "last_failure": null,
        "next_attempt": null
      },
      {
        "name": "solana_relay",
        "state": "half_open",
        "failure_count": 3,
        "failure_threshold": 5,
        "last_failure": "2023-12-01T11:30:00Z",
        "next_attempt": "2023-12-01T12:00:00Z"
      }
    ]
  }
}
```

### GET /failed-events
**Description**: Get failed events that require attention

```bash
curl http://localhost:8084/failed-events
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "failed_events": [
      {
        "id": "event_456",
        "event_type": "transfer",
        "chain": "ethereum",
        "transaction_hash": "0xdef456...",
        "error_message": "Insufficient gas for transaction",
        "retry_count": 2,
        "max_retries": 3,
        "next_retry": "2023-12-01T12:15:00Z",
        "created_at": "2023-12-01T11:00:00Z"
      }
    ],
    "total": 8
  }
}
```

## 🔒 Security Endpoints

### GET /replay-protection
**Description**: Get replay protection status and statistics

```bash
curl http://localhost:8084/replay-protection
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "enabled": true,
    "processed_hashes": 15420,
    "blocked_replays": 23,
    "cache_size": 10000,
    "oldest_entry": "2023-11-30T12:00:00Z",
    "cleanup_interval": "1h"
  }
}
```

### GET /processed-events
**Description**: Get recently processed events

```bash
curl http://localhost:8084/processed-events
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "processed_events": [
      {
        "id": "event_789",
        "event_type": "transfer",
        "chain": "ethereum",
        "block_number": 18500000,
        "transaction_hash": "0x123abc...",
        "processed_at": "2023-12-01T11:55:00Z",
        "processing_time": "2.5s"
      }
    ],
    "total_processed": 15420,
    "average_processing_time": "1.8s"
  }
}
```

## 🔧 Management Endpoints

### POST /force-recovery
**Description**: Force recovery of failed transactions

```bash
curl -X POST http://localhost:8084/force-recovery \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_ids": ["tx_123", "tx_456"],
    "force_retry": true
  }'
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "recovery_job_id": "recovery_123",
    "transactions_queued": 2,
    "estimated_completion": "2023-12-01T12:10:00Z"
  }
}
```

### POST /cleanup-events
**Description**: Cleanup old processed events

```bash
curl -X POST http://localhost:8084/cleanup-events \
  -H "Content-Type: application/json" \
  -d '{
    "older_than": "7d",
    "dry_run": false
  }'
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "cleaned_events": 1250,
    "freed_space": "15.2MB",
    "cleanup_duration": "2.3s"
  }
}
```

## 📜 Logging Endpoints

### GET /logs
**Description**: Get recent log entries
**Query Parameters**:
- `level` (optional): Filter by log level (debug, info, warn, error)
- `component` (optional): Filter by component
- `limit` (optional): Limit number of entries (default: 100)

```bash
curl http://localhost:8084/logs
curl http://localhost:8084/logs?level=error&limit=50
```

**Response**: HTML page with live log streaming interface

## 📊 Metrics Endpoints

### GET /metrics
**Description**: Prometheus-compatible metrics endpoint

```bash
curl http://localhost:8084/metrics
```

**Response**: Prometheus metrics format
```
# HELP bridge_transactions_total Total number of bridge transactions
# TYPE bridge_transactions_total counter
bridge_transactions_total{chain="ethereum"} 500
bridge_transactions_total{chain="solana"} 400
bridge_transactions_total{chain="blackhole"} 350

# HELP bridge_transaction_duration_seconds Transaction processing duration
# TYPE bridge_transaction_duration_seconds histogram
bridge_transaction_duration_seconds_bucket{le="1"} 100
bridge_transaction_duration_seconds_bucket{le="5"} 450
bridge_transaction_duration_seconds_bucket{le="10"} 800
bridge_transaction_duration_seconds_bucket{le="+Inf"} 1000
```

## 🌐 WebSocket Endpoints

### WS /ws/logs
**Description**: Real-time log streaming
**Protocol**: WebSocket

```javascript
const ws = new WebSocket('ws://localhost:8084/ws/logs');
ws.onmessage = function(event) {
    const logEntry = JSON.parse(event.data);
    console.log(logEntry);
};
```

### WS /ws/events
**Description**: Real-time event notifications
**Protocol**: WebSocket

```javascript
const ws = new WebSocket('ws://localhost:8084/ws/events');
ws.onmessage = function(event) {
    const bridgeEvent = JSON.parse(event.data);
    console.log('New bridge event:', bridgeEvent);
};
```

### WS /ws/metrics
**Description**: Real-time metrics updates
**Protocol**: WebSocket

```javascript
const ws = new WebSocket('ws://localhost:8084/ws/metrics');
ws.onmessage = function(event) {
    const metrics = JSON.parse(event.data);
    updateDashboard(metrics);
};
```

## 🚨 Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid parameters |
| 404 | Not Found - Resource not found |
| 500 | Internal Server Error |
| 503 | Service Unavailable - Circuit breaker open |

## 📝 Error Response Format

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid transaction ID format",
    "details": {
      "field": "transaction_id",
      "expected": "string with prefix 'tx_'"
    }
  },
  "timestamp": "2023-12-01T12:00:00Z"
}
```

## 🔄 Rate Limiting

The API implements rate limiting to prevent abuse:
- **Default**: 100 requests per minute per IP
- **Burst**: Up to 20 requests in a 10-second window
- **Headers**: Rate limit information in response headers

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1701432000
```

## 📚 SDK Integration

For programmatic access, use the Bridge SDK:

```go
// Get bridge statistics
stats := sdk.GetBridgeStats()

// Get transaction status
status, err := sdk.GetTransactionStatus("tx_123")

// Manual relay
err := sdk.RelayToChain(transaction, "solana")
```

---

This API documentation provides comprehensive coverage of all available endpoints. For additional examples and integration guides, see the [Developer Guide](DEVELOPER.md).
