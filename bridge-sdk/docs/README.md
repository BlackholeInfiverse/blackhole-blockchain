# BlackHole Bridge SDK

🌉 **Enterprise-Grade Cross-Chain Bridge Infrastructure** for seamless asset transfers between Ethereum, Solana, and BlackHole blockchain networks.

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()

## 🚀 Quick Start

```bash
# Clone and navigate
git clone https://github.com/blackhole-network/bridge-sdk.git
cd bridge-sdk

# One-command deployment

make quick-start

# Or run directly
cd example && go run main.go
```

**Access Points:**
- 📊 **Dashboard**: http://localhost:8084
<!-- - 📈 **Monitoring**: http://localhost:3000 (admin/admin123) -->
- 🔍 **Health**: http://localhost:8084/health

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Components](#-components)
- [Installation](#-installation)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [Deployment](#-deployment)
- [Development](#-development)
- [Contributing](#-contributing)
- [Documentation](#-documentation)

## ✨ Features

### 🌉 **Cross-Chain Bridge**
- **Bidirectional transfers** between Ethereum ↔ Solana ↔ BlackHole
- **Real-time event listening** with WebSocket connections
- **Automatic relay processing** with confirmation tracking
- **Multi-signature validation** for enhanced security

### 🔒 **Security & Reliability**
- **Replay attack protection** with event hash validation
- **Circuit breaker patterns** for fault tolerance
- **Exponential backoff** on RPC failures
- **Comprehensive error handling** with retry mechanisms

### 📊 **Monitoring & Observability**
- **Real-time dashboard** with cosmic space theme
- **Prometheus metrics** integration
- **Grafana dashboards** for visualization
- **Health checks** and alerting
- **Structured logging** with multiple levels

### 🚀 **Performance & Scalability**
- **Concurrent processing** with goroutine pools
- **Database optimization** with connection pooling
- **Caching strategies** with Redis integration
- **Horizontal scaling** support

### 🛠️ **Developer Experience**
- **Hot reload** development environment
- **Comprehensive testing** suite
- **Docker containerization** for easy deployment
- **Extensive documentation** and examples

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    BlackHole Bridge SDK                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Ethereum   │  │   Solana    │  │  BlackHole  │             │
│  │  Listener   │  │  Listener   │  │  Listener   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│         │                 │                 │                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Event Processing Engine                        │ │
│  │  • Event Validation  • Replay Protection  • Circuit Breaker│ │
│  └─────────────────────────────────────────────────────────────┘ │
│         │                 │                 │                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Ethereum   │  │   Solana    │  │  BlackHole  │             │
│  │   Relay     │  │   Relay     │  │   Relay     │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ PostgreSQL  │  │    Redis    │  │  Prometheus │             │
│  │ Database    │  │   Cache     │  │  Metrics    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

### Core Components

1. **Blockchain Listeners** - Monitor events on each blockchain
2. **Event Processing Engine** - Validates and processes cross-chain events
3. **Relay System** - Executes transactions on destination chains
4. **Security Layer** - Replay protection and validation
5. **Monitoring Stack** - Metrics, logging, and alerting
6. **Web Dashboard** - Real-time monitoring interface

## 🧩 Components

### 📡 **Blockchain Listeners**

**Ethereum Listener** (`listeners.go`)
- WebSocket connection to Ethereum RPC
- Event filtering and parsing
- Block confirmation tracking
- Gas price optimization

**Solana Listener** (`listeners.go`)
- WebSocket connection to Solana RPC
- Program log monitoring
- Slot confirmation tracking
- Compute unit optimization

**BlackHole Listener** (`listeners.go`)
- Native blockchain integration
- Custom event handling
- Validator network communication

### 🔄 **Relay System**

**Transaction Relay** (`relay.go`)
- Cross-chain transaction execution
- Multi-signature coordination
- Fee calculation and optimization
- Confirmation tracking

**Recovery System** (`event_recovery.go`)
- Failed transaction recovery
- Automatic retry mechanisms
- Manual intervention support
- State reconciliation

### 🔒 **Security Components**

**Replay Protection** (`replay_protection.go`)
- Event hash validation
- Duplicate transaction prevention
- Time-based expiration
- Database persistence

**Error Handler** (`error_handler.go`)
- Fault tolerance patterns
- Automatic failure detection
- Service degradation handling
- Recovery mechanisms

### 📊 **Monitoring & Metrics**

**Dashboard** (`dashboard_components.go`)
- Real-time transaction monitoring
- System health visualization
- Interactive controls
- Responsive design

**Log Streamer** (`log_streamer.go`)
- Real-time log streaming
- WebSocket connections
- Structured logging
- Performance tracking

## 🛠️ Installation

### Prerequisites

- **Go 1.21+** - [Download](https://golang.org/dl/)
- **Docker & Docker Compose** - [Install](https://docs.docker.com/get-docker/)
- **Git** - [Install](https://git-scm.com/downloads)

### Quick Installation

```bash
# Clone repository
git clone https://github.com/blackhole-network/bridge-sdk.git
cd bridge-sdk

# Install dependencies
go mod download

# Setup environment
cp .env.example .env
# Edit .env with your configuration

# Run development server
make dev
```

### Docker Installation

```bash
# One-command deployment
make quick-start

# Or manual Docker setup
docker-compose up -d
```

## 🎯 Usage

### Basic Usage

```go
package main

import (
    "context"
    "log"
    
    bridgesdk "github.com/blackhole-network/bridge-sdk"
    "github.com/blackhole-network/blackhole-blockchain/core/relay-chain/chain"
)

func main() {
    // Create blockchain instance
    blockchain := chain.NewBlockchain()
    
    // Initialize bridge SDK
    sdk := bridgesdk.NewBridgeSDK(blockchain, nil)
    
    // Start listeners
    ctx := context.Background()
    if err := sdk.StartEthereumListener(ctx); err != nil {
        log.Fatal(err)
    }
    
    if err := sdk.StartSolanaListener(ctx); err != nil {
        log.Fatal(err)
    }
    
    // Start web server
    sdk.StartWebServer(":8084")
}
```

### Advanced Configuration

```go
// Custom configuration
config := &bridgesdk.Config{
    EthereumRPC: "wss://eth-mainnet.alchemyapi.io/v2/YOUR_KEY",
    SolanaRPC:   "wss://api.mainnet-beta.solana.com",
    LogLevel:    "info",
    DatabasePath: "./data/bridge.db",
}

sdk := bridgesdk.NewBridgeSDK(blockchain, config)

// Custom event handlers
sdk.OnEthereumEvent(func(event *bridgesdk.EthereumEvent) {
    log.Printf("Ethereum event: %+v", event)
})

sdk.OnSolanaEvent(func(event *bridgesdk.SolanaEvent) {
    log.Printf("Solana event: %+v", event)
})
```

## 📚 API Reference

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard interface |
| `/health` | GET | System health status |
| `/stats` | GET | Bridge statistics |
| `/transactions` | GET | Transaction history |
| `/transaction/{id}` | GET | Transaction details |
| `/relay` | POST | Manual relay trigger |
| `/errors` | GET | Error metrics |
| `/circuit-breakers` | GET | Circuit breaker status |
| `/failed-events` | GET | Failed events list |
| `/replay-protection` | GET | Replay protection status |
| `/processed-events` | GET | Processed events list |
| `/logs` | GET | Live logs interface |

### WebSocket Endpoints

| Endpoint | Description |
|----------|-------------|
| `/ws/logs` | Real-time log streaming |
| `/ws/events` | Live event notifications |
| `/ws/metrics` | Real-time metrics |

### SDK Methods

```go
// Core methods
sdk.StartEthereumListener(ctx) error
sdk.StartSolanaListener(ctx) error
sdk.StopListeners() error
sdk.RelayToChain(tx *Transaction, targetChain string) error

// Transaction management
sdk.GetTransactionStatus(id string) (*Status, error)
sdk.GetAllTransactions() ([]*Transaction, error)
sdk.GetTransactionsByStatus(status string) ([]*Transaction, error)

// Monitoring
sdk.GetBridgeStats() *BridgeStats
sdk.GetHealth() *HealthStatus
sdk.GetErrorMetrics() *ErrorMetrics
```

## 🚀 Deployment

### Development Deployment

```bash
# Start development environment
make dev

# Run tests
make test

# View logs
make logs
```

### Production Deployment

```bash
# Deploy to production
make prod

# Scale services
docker-compose up -d --scale bridge-node=3

# Monitor deployment
make health
```

### Available Commands

```bash
make help           # Show all available commands
make quick-start    # Complete setup and start
make start          # Start production mode
make dev            # Start development mode
make stop           # Stop all services
make restart        # Restart all services
make status         # Show service status
make logs           # Show all logs
make health         # Check service health
make clean          # Clean up containers and volumes
make backup         # Create backup
make restore        # Restore from backup
make test           # Run tests
make update         # Update services
```

## 📖 Documentation

- 📋 **[Architecture Documentation](docs/ARCHITECTURE.md)** - Detailed system design
- 🚀 **[Deployment Guide](DEPLOYMENT.md)** - Complete deployment instructions
- 👨‍💻 **[Developer Guide](docs/DEVELOPER.md)** - Code usage and integration
- 🔧 **[API Documentation](docs/API.md)** - Complete API reference
- 🐛 **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions
- 🐳 **[Docker Deployment Summary](DOCKER_DEPLOYMENT_SUMMARY.md)** - Docker deployment guide

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📧 **Email**: support@blackhole.network
- 💬 **Discord**: [BlackHole Community](https://discord.gg/blackhole)
- 📖 **Documentation**: [docs.blackhole.network](https://docs.blackhole.network)
- 🐛 **Issues**: [GitHub Issues](https://github.com/blackhole-network/bridge-sdk/issues)

---

**Built with ❤️ by the BlackHole Team**
