# 🔌 Blackhole Blockchain API Documentation

Complete API reference for the Blackhole Blockchain ecosystem. All APIs are RESTful and return JSON responses.

## 🌐 **Base URLs**

- **Blockchain API**: `http://localhost:8080/api`
- **Wallet API**: `http://localhost:9000/api`

## 📚 **API Categories**

### 🔗 **Core Blockchain APIs**
- [`BLOCKCHAIN_API.md`](BLOCKCHAIN_API.md) - Core blockchain operations
  - Block management
  - Transaction handling
  - Network status
  - Health checks

### 💼 **Wallet APIs**
- [`WALLET_API.md`](WALLET_API.md) - Wallet management operations
  - Wallet creation/import
  - Balance checking
  - Token transfers
  - Transaction history

### 🥩 **Staking APIs**
- [`STAKING_API.md`](STAKING_API.md) - Staking and validation
  - Stake deposits/withdrawals
  - Validator management
  - Reward calculations
  - Slashing operations

### 🔄 **DEX APIs**
- [`DEX_API.md`](DEX_API.md) - Decentralized exchange
  - Token swaps
  - Liquidity pools
  - Price quotes
  - Trading history

### 🌉 **Cross-Chain APIs**
- [`CROSS_CHAIN_API.md`](CROSS_CHAIN_API.md) - Cross-chain operations
  - Bridge transfers
  - Cross-chain swaps
  - Multi-chain quotes
  - Order tracking

### 🤝 **OTC Trading APIs**
- [`OTC_API.md`](OTC_API.md) - Over-the-counter trading
  - Order creation/matching
  - Multi-signature support
  - Escrow management
  - Trade execution

## 🛠️ **Postman Collections**

Pre-built Postman collections for easy API testing:

- [`postman/Blackhole_Blockchain_Core.postman_collection.json`](postman/Blackhole_Blockchain_Core.postman_collection.json)
- [`postman/Blackhole_Wallet.postman_collection.json`](postman/Blackhole_Wallet.postman_collection.json)
- [`postman/Blackhole_Staking.postman_collection.json`](postman/Blackhole_Staking.postman_collection.json)
- [`postman/Blackhole_DEX.postman_collection.json`](postman/Blackhole_DEX.postman_collection.json)
- [`postman/Blackhole_Cross_Chain.postman_collection.json`](postman/Blackhole_Cross_Chain.postman_collection.json)

## 🔐 **Authentication**

### Session-Based Authentication (Wallet APIs)
```http
POST /api/login
Content-Type: application/json

{
  "username": "your_username",
  "password": "your_password"
}
```

### API Key Authentication (Blockchain APIs)
```http
GET /api/blocks
Authorization: Bearer your_api_key
```

## 📝 **Common Response Format**

All APIs follow a consistent response format:

### Success Response
```json
{
  "success": true,
  "data": {
    // Response data here
  },
  "message": "Operation completed successfully"
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error description",
  "code": "ERROR_CODE"
}
```

## 🚀 **Quick Start Examples**

### Check Blockchain Health
```bash
curl http://localhost:8080/api/health
```

### Get Latest Block
```bash
curl http://localhost:8080/api/blocks/latest
```

### Check Wallet Balance
```bash
curl -X POST http://localhost:9000/api/wallets/balance \
  -H "Content-Type: application/json" \
  -d '{"address": "0x742d35Cc6634C0532925a3b8D4C0532925a3b8D4"}'
```

### Execute Token Transfer
```bash
curl -X POST http://localhost:8080/api/transactions/transfer \
  -H "Content-Type: application/json" \
  -d '{
    "from": "0x742d35Cc6634C0532925a3b8D4C0532925a3b8D4",
    "to": "0x8ba1f109551bD432803012645Hac136c",
    "amount": 1000000,
    "token": "BHX"
  }'
```

### Get Cross-Chain Quote
```bash
curl -X POST http://localhost:8080/api/cross-chain/quote \
  -H "Content-Type: application/json" \
  -d '{
    "source_chain": "ethereum",
    "dest_chain": "blackhole",
    "token_in": "USDT",
    "token_out": "BHX",
    "amount_in": 1000000
  }'
```

## 🔧 **Error Codes**

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Request format is invalid |
| `UNAUTHORIZED` | Authentication required |
| `FORBIDDEN` | Insufficient permissions |
| `NOT_FOUND` | Resource not found |
| `INSUFFICIENT_BALANCE` | Insufficient token balance |
| `INVALID_ADDRESS` | Invalid wallet address |
| `TRANSACTION_FAILED` | Transaction execution failed |
| `NETWORK_ERROR` | Network connectivity issue |

## 📊 **Rate Limits**

| Endpoint Category | Rate Limit |
|-------------------|------------|
| **Health/Status** | 100 req/min |
| **Read Operations** | 60 req/min |
| **Write Operations** | 30 req/min |
| **Trading Operations** | 10 req/min |

## 🌍 **CORS Support**

All APIs support CORS for web applications:
- **Allowed Origins**: `*` (configurable)
- **Allowed Methods**: `GET, POST, PUT, DELETE, OPTIONS`
- **Allowed Headers**: `Content-Type, Authorization`

## 📈 **API Versioning**

Current API version: `v1`

Version is included in the URL path:
- `http://localhost:8080/api/v1/blocks`
- `http://localhost:9000/api/v1/wallets`

## 🔍 **Testing APIs**

### Using cURL
```bash
# Test blockchain health
curl -i http://localhost:8080/api/health

# Test with JSON data
curl -X POST http://localhost:8080/api/transactions \
  -H "Content-Type: application/json" \
  -d '{"from": "addr1", "to": "addr2", "amount": 100}'
```

### Using Postman
1. Import the provided Postman collections
2. Set up environment variables
3. Run the pre-configured requests

### Using JavaScript
```javascript
// Fetch blockchain status
const response = await fetch('http://localhost:8080/api/health');
const data = await response.json();
console.log(data);

// Execute transaction
const txResponse = await fetch('http://localhost:8080/api/transactions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    from: 'addr1',
    to: 'addr2',
    amount: 100
  })
});
```

## 📞 **Support**

For API support and questions:
- Check the specific API documentation files
- Review the Postman collections
- Test with the provided examples
- Refer to the error codes table

---

**API Version**: 1.0.0  
**Last Updated**: December 2024  
**Status**: Production Ready
