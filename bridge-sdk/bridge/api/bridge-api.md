# BlackHole Bridge API Documentation (v0.3 Skeleton)

## Overview
The Bridge service provides cross-chain relay functionality between Ethereum, Solana, and BlackHole blockchain. This API supports both gRPC (port 9090) and REST (port 8080) interfaces. Messages are versioned as "v1alpha1". All requests/responses use JSON.

### Authentication
No authentication required for development. Production uses API keys.

### Error Codes
- 200: Success
- 400: Bad Request (invalid message, unsigned)
- 409: Conflict (duplicate eventHash)
- 429: Too Many Requests (rate limit)
- 500: Internal Error
- 503: Service Unavailable (circuit breaker)

Error response format:
```json
{
  "error": {
    "code": "DUPLICATE_EVENT",
    "message": "Event already processed",
    "details": {"eventHash": "0xabc..."}
  }
}
```

## Schemas
Generated from [api-schema.proto](../api-schema.proto). Key messages:

### BridgeMessage (v1alpha1)
```proto
message BridgeMessage {
  string id = 1;
  string source_chain = 2; // "ethereum", "solana"
  string dest_chain = 3; // "blackhole", "solana", "ethereum"
  enum SourceModule { TOKEN = 0; DEX = 1; STAKE = 2; }
  SourceModule source_module = 4;
  string topic = 5; // e.g., "transfer", "swap"
  map<string, string> meta = 6; // e.g., {"amountIn": "100", "slippage": "0.5"}
  string message_version = 7; // "v1alpha1"
  // Payload data
  string amount = 8;
  string token_symbol = 9;
  string from_address = 10;
  string to_address = 11;
}
```

### SignedBridgeMessage
```proto
message SignedBridgeMessage {
  BridgeMessage message = 1;
  bytes signature = 2;
  string public_key = 3;
  string sig_scheme = 4; // "ed25519"
}
```

### RelayResponse
```json
{
  "success": true,
  "relay_id": "relay_123",
  "status": "accepted",
  "estimated_completion": 1640995200
}
```

### StatusResponse
```json
{
  "status": "ok",
  "height": 18500000,
  "queue_depth": 5,
  "accepted": 1200,
  "duplicates": 23
}
```

## Endpoints

### POST /relay/eth
Accept SignedBridgeMessage from Ethereum. Validates signature, checks dedupe, relays to BlackHole.

Example:
```bash
curl -X POST http://localhost:8080/relay/eth \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "source_chain": "ethereum",
      "dest_chain": "blackhole",
      "source_module": "TOKEN",
      "topic": "transfer",
      "meta": {"amount": "1.5"},
      "amount": "1.5",
      "token_symbol": "ETH",
      "from_address": "0x742d...",
      "to_address": "bhx_addr",
      "message_version": "v1alpha1"
    },
    "signature": "base64_sig",
    "public_key": "pubkey",
    "sig_scheme": "ed25519"
  }'
```

Response: RelayResponse or error (409 if duplicate).

### POST /relay/sol
Similar to /relay/eth for Solana.

### GET /bridge/status
Health and metrics.

Example:
```bash
curl http://localhost:8080/bridge/status
```

Response: StatusResponse.

### GET /log/retry
Last N retry items (limit query param, default 10).

Example:
```bash
curl "http://localhost:8080/log/retry?limit=5"
```

Response: Array of retry items with attempt, error.

### GET /log/events
Recent accepted event summaries (limit=5 default).

Example:
```bash
curl "http://localhost:8080/log/events?limit=5"
```

Response: Array of events with parsed fields (TOKEN/DEX mixed).

## Idempotency & Replay Protection
- Key: eventHash = SHA256(source_chain + dest_chain + from + to + token + amount)
- Stored in BoltDB; TTL 24h.
- Duplicate requests return 409 {status: "duplicate"}.
- Cross-channel replay via pubKey + nonce cache.

## Retry Semantics
- Exponential backoff: delay = attempts^2 * base_delay (default 1s).
- Max attempts: 5 (configurable).
- Dead-letter queue: Failed after max written to retry-dlq.jsonl.
- Retry queue depth monitored in /bridge/status.

## SLO Targets
- p99 latency < 5s end-to-end.
- Success rate > 99%.
- DLQ size < 1% of total events.
- Monitored via /metrics (Prometheus) and deploy/bridge/metrics.json (snapshot every 30s).

## gRPC
Use grpcurl or generated clients. Service: bridge.BridgeService.

Example:
```bash
grpcurl -plaintext localhost:9090 blackhole.bridge.v1.BridgeService/ProcessTransaction
```

For full proto, see api-schema.proto. REST gateway proxies to gRPC.

## Configuration
See deploy/bridge/.env.example for RPC URLs, retry limits, failure injection (--inject-drop=0.03).

## Limitations
- Mocks only; real RPCs future.
- Attestations stubbed.

Updated: 2025-09-19