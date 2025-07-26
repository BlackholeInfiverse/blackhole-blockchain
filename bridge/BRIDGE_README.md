# 🌉 BlackHole Bridge - Advanced Cross-Chain Token Transfer Infrastructure

A comprehensive, production-ready cross-chain bridge system that enables seamless token transfers between Ethereum, Solana, and BlackHole blockchain networks.

## 🎯 Overview

The BlackHole Bridge provides a robust, secure, and user-friendly infrastructure for cross-chain token transfers. Built with enterprise-grade features including structured logging, real-time monitoring, replay attack protection, and comprehensive error handling.

## ✨ Key Features

### 🔄 **Cross-Chain Token Transfers**
- **Multi-Chain Support**: Ethereum ↔ Solana ↔ BlackHole
- **Token Standards**: ERC-20, SPL, Native tokens, BHX tokens
- **Bidirectional Transfers**: Full support for all chain combinations
- **Transfer Validation**: Comprehensive validation before execution
- **State Management**: Complete transfer lifecycle tracking

### 🛡️ **Security & Reliability**
- **Replay Attack Protection**: Event hash validation with BoltDB storage
- **Address Validation**: Chain-specific address format validation
- **Transfer Limits**: Configurable minimum and maximum transfer amounts
- **Circuit Breakers**: Automatic failure detection and recovery
- **Error Recovery**: Robust error handling with retry mechanisms

### 📊 **Monitoring & Observability**
- **Structured Logging**: High-performance Zap logging with colored CLI output
- **Real-time Dashboard**: Beautiful dark-themed web interface
- **Live Log Streaming**: WebSocket-based real-time log viewing
- **Health Monitoring**: Comprehensive system health tracking
- **Performance Metrics**: Detailed statistics and monitoring

### 🎨 **User Experience**
- **Modular Dashboard**: Embeddable UI components
- **Interactive Transfer Widget**: Easy-to-use transfer interface
- **Real-time Updates**: Live status updates via WebSocket
- **Responsive Design**: Mobile-friendly interface
- **Dark Theme**: Modern, professional appearance

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    BlackHole Bridge System                     │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Bridge SDK    │  │ Token Transfer  │  │   Dashboard     │ │
│  │                 │  │    Manager      │  │   Components    │ │
│  │ • Listeners     │  │ • Validators    │  │ • Transfer UI   │ │
│  │ • Relay System  │  │ • Handlers      │  │ • Live Logs     │ │
│  │ • Error Handler │  │ • Fee Calc      │  │ • Status View   │ │
│  │ • Logger        │  │ • State Mgmt    │  │ • Pair Display  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Ethereum      │  │     Solana      │  │   BlackHole     │ │
│  │   Integration   │  │   Integration   │  │   Integration   │ │
│  │                 │  │                 │  │                 │ │
│  │ • Event Listen  │  │ • Event Listen  │  │ • Event Listen  │ │
│  │ • TX Validation │  │ • TX Validation │  │ • TX Validation │ │
│  │ • Fee Calc      │  │ • Fee Calc      │  │ • Fee Calc      │ │
│  │ • Transfer Exec │  │ • Transfer Exec │  │ • Transfer Exec │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Go 1.21 or higher
- Access to Ethereum RPC endpoint
- Access to Solana RPC endpoint
- BlackHole blockchain node

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/your-org/blackhole-blockchain.git
cd blackhole-blockchain
```

2. **Install dependencies**
```bash
go mod tidy
```

3. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your RPC endpoints and configuration
```

4. **Run the bridge system**
```bash
cd bridge-sdk/example
go run main.go
```

5. **Access the dashboard**
- Main Dashboard: http://localhost:8084
- Live Logs: http://localhost:8084/logs
- API Documentation: http://localhost:8084/api

## 📖 Usage Examples

### Basic Token Transfer

```go
package main

import (
    "math/big"
    "time"
    
    bridgesdk "github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk"
    "github.com/Shivam-Patel-G/blackhole-blockchain/bridge/core"
)

func main() {
    // Initialize bridge SDK
    sdk := bridgesdk.NewBridgeSDK(blockchain, nil)
    sdk.Initialize()
    defer sdk.Shutdown()
    
    // Create transfer request
    request := &core.TransferRequest{
        ID:          "transfer_" + time.Now().Format("20060102150405"),
        FromChain:   core.ChainTypeEthereum,
        ToChain:     core.ChainTypeBlackHole,
        FromAddress: "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87",
        ToAddress:   "bh1234567890123456789012345678901234567890",
        Token: core.TokenInfo{
            Symbol:   "ETH",
            Name:     "Ethereum",
            Decimals: 18,
            Standard: core.TokenStandardNative,
            ChainID:  "1",
            IsNative: true,
        },
        Amount:   big.NewInt(1000000000000000000), // 1 ETH
        Deadline: time.Now().Add(time.Hour),
    }
    
    // Validate transfer
    validation := sdk.ValidateTokenTransferRequest(request)
    if !validation.IsValid {
        log.Fatalf("Transfer validation failed: %v", validation.Errors)
    }
    
    // Initiate transfer
    response, err := sdk.InitiateTokenTransfer(request)
    if err != nil {
        log.Fatalf("Transfer initiation failed: %v", err)
    }
    
    log.Printf("Transfer initiated: %s (Status: %s)", response.RequestID, response.State)
}
```

### Dashboard Integration

```go
// Add bridge components to your existing web interface
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    components := bridgesdk.NewDashboardComponents(sdk)
    
    data := struct {
        TokenTransferWidget  string
        SupportedPairsWidget string
    }{
        TokenTransferWidget:  components.TokenTransferWidget(),
        SupportedPairsWidget: components.SupportedPairsWidget(),
    }
    
    renderTemplate(w, "dashboard.html", data)
}
```

## 🔧 Configuration

### Environment Variables

```bash
# Ethereum Configuration
BRIDGE_ETHEREUM_RPC=https://eth-mainnet.g.alchemy.com/v2/your-api-key
BRIDGE_ETHEREUM_WSS=wss://eth-mainnet.g.alchemy.com/v2/your-api-key

# Solana Configuration  
BRIDGE_SOLANA_RPC=https://api.mainnet-beta.solana.com

# Bridge Settings
BRIDGE_ENABLE_TESTNET=true
BRIDGE_LOG_LEVEL=info
BRIDGE_ENABLE_REPLAY_PROTECTION=true
BRIDGE_ENABLE_COLORS=true

# Dashboard Settings
BRIDGE_DASHBOARD_PORT=8084
BRIDGE_ENABLE_DASHBOARD=true
```

## 📊 API Reference

### REST Endpoints

#### Validate Transfer
```http
POST /api/validate-transfer
Content-Type: application/json

{
    "id": "transfer_123",
    "from_chain": "ethereum",
    "to_chain": "blackhole",
    "from_address": "0x...",
    "to_address": "bh...",
    "token": {
        "symbol": "ETH",
        "decimals": 18,
        "standard": "NATIVE"
    },
    "amount": "1000000000000000000"
}
```

#### Initiate Transfer
```http
POST /api/initiate-transfer
Content-Type: application/json
```

#### Get Transfer Status
```http
GET /api/transfer-status/{requestId}
```

#### Get Supported Pairs
```http
GET /api/supported-pairs
```

### WebSocket Endpoints

#### Real-time Logs
```javascript
const ws = new WebSocket('ws://localhost:8084/ws/logs');

ws.onmessage = function(event) {
    const logEntry = JSON.parse(event.data);
    console.log('New log:', logEntry);
};
```

## 🔒 Security Features

### Replay Attack Protection
- Event hash validation using SHA-256
- BoltDB storage for processed events
- Configurable cleanup of old events
- Duplicate transaction detection

### Address Validation
- Chain-specific address format validation
- Checksum validation for Ethereum addresses
- Base58 validation for Solana addresses
- Custom validation for BlackHole addresses

### Transfer Limits
- Configurable minimum and maximum amounts
- Per-token transfer limits
- Daily/hourly rate limiting (configurable)
- Emergency pause functionality

## 📈 Monitoring

### Health Checks
```bash
curl http://localhost:8084/health
```

### Metrics
```bash
curl http://localhost:8084/stats
```

### Live Logs
Visit http://localhost:8084/logs for real-time log viewing with filtering capabilities.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

- Documentation: [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)
- Issues: GitHub Issues
- Discussions: GitHub Discussions

## 🗺️ Roadmap

- [ ] Multi-signature wallet support
- [ ] Advanced fee optimization
- [ ] Cross-chain NFT transfers
- [ ] Governance token integration
- [ ] Mobile SDK
- [ ] Hardware wallet support
