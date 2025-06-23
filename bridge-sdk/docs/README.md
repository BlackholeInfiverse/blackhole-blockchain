# 🌉 BlackHole Bridge SDK

**Enterprise-Grade Cross-Chain Bridge Infrastructure** for seamless asset transfers between Ethereum, Solana, and BlackHole blockchain networks with advanced security, monitoring, and simulation capabilities.

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/Security-Replay%20Protected-red.svg)]()
[![Monitoring](https://img.shields.io/badge/Monitoring-Prometheus-orange.svg)]()

## 🚀 Quick Start

### Option 1: Direct Run (Fastest)
```bash
# Clone and navigate
git clone https://github.com/blackhole-network/bridge-sdk.git
cd bridge-sdk/example

# Install dependencies
go mod tidy

# Run the bridge
go run main.go
```

### Option 2: Docker Deployment (Production)
```bash
# Clone and navigate
git clone https://github.com/blackhole-network/bridge-sdk.git
cd bridge-sdk

# Setup environment
cp .env.example .env
# Edit .env with your configuration

# One-command deployment
docker-compose up -d
```

### Option 3: Development Mode
```bash
# Clone and navigate
git clone https://github.com/blackhole-network/bridge-sdk.git
cd bridge-sdk

# Development setup
make dev
```

**🌐 Access Points:**
- 📊 **Main Dashboard**: http://localhost:8084
- 🏥 **Health Check**: http://localhost:8084/health
- 📈 **Statistics**: http://localhost:8084/stats
- 💸 **Transactions**: http://localhost:8084/transactions
- 📜 **Live Logs**: http://localhost:8084/logs
- 📚 **API Docs**: http://localhost:8084/docs
- 🧪 **Simulation**: http://localhost:8084/simulation (if enabled)
- 📊 **Grafana**: http://localhost:3000 (admin/admin123)
- 🔍 **Prometheus**: http://localhost:9091

## 📋 Table of Contents

- [🚀 Quick Start](#-quick-start)
- [✨ Features](#-features)
- [🏗️ Architecture](#️-architecture)
- [🧩 Components](#-components)
- [🛠️ Installation](#️-installation)
- [📖 Configuration](#-configuration)
- [🎯 Usage Examples](#-usage-examples)
- [🧪 Simulation Mode](#-simulation-mode)
- [📚 API Reference](#-api-reference)
- [🚀 Deployment](#-deployment)
- [🔧 Development](#-development)
- [📊 Monitoring](#-monitoring)
- [🔒 Security](#-security)
- [🐛 Troubleshooting](#-troubleshooting)
- [🤝 Contributing](#-contributing)
- [📖 Documentation](#-documentation)

## ✨ Features

### 🌉 **Cross-Chain Bridge Core**
- **✅ Bidirectional transfers** between Ethereum ↔ Solana ↔ BlackHole
- **✅ Real-time event listening** with WebSocket connections
- **✅ Automatic relay processing** with confirmation tracking
- **✅ Instant token transfers** with minimal processing time
- **✅ Multi-token support** (ERC-20, SPL, Native tokens)
- **✅ Fee optimization** with dynamic gas price calculation

### 🔒 **Security & Reliability**
- **✅ Replay attack protection** with SHA-256 hash validation and BoltDB persistence
- **✅ Circuit breaker patterns** for fault tolerance and graceful degradation
- **✅ Exponential backoff** on RPC failures with configurable retry limits
- **✅ Comprehensive error handling** with retry queues and panic recovery
- **✅ Input validation** and sanitization for all API endpoints
- **✅ Rate limiting** and DDoS protection

### 📊 **Monitoring & Observability**
- **✅ Real-time dashboard** with cosmic space theme and golden color scheme
- **✅ Enhanced logging** with Zap/Logrus support and colored CLI output
- **✅ Prometheus metrics** integration with custom dashboards
- **✅ Grafana visualization** with pre-configured dashboards
- **✅ Health checks** and alerting with WebSocket streaming
- **✅ Performance tracking** with detailed transaction metrics

### 🧪 **Simulation & Testing**
- **✅ Full end-to-end simulation** with real testnet deployments
- **✅ Token deployment testing** on Ethereum/Solana testnets
- **✅ Screenshot capture** for verification and documentation
- **✅ Comprehensive logging** with detailed transaction flows
- **✅ Performance benchmarking** with success rate analysis
- **✅ Replay attack testing** with security validation

### 🚀 **Performance & Scalability**
- **✅ Concurrent processing** with worker pools and goroutine management
- **✅ Database optimization** with BoltDB and connection pooling
- **✅ Caching strategies** with Redis integration and memory optimization
- **✅ Horizontal scaling** support with Docker Swarm/Kubernetes
- **✅ Load balancing** with Nginx reverse proxy
- **✅ Auto-scaling** based on transaction volume

### 🛠️ **Developer Experience**
- **✅ Hot reload** development environment with file watching
- **✅ Comprehensive testing** suite with unit and integration tests
- **✅ Docker containerization** for easy deployment and development
- **✅ Extensive documentation** with examples and diagrams
- **✅ CLI tools** for debugging and administration
- **✅ IDE integration** with Go modules and debugging support

## 🏗️ Architecture

### High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           🌉 BlackHole Bridge SDK                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐             │
│  │   🔗 Ethereum   │    │   🔗 Solana     │    │  🔗 BlackHole   │             │
│  │    Listener     │    │    Listener     │    │    Listener     │             │
│  │  • WebSocket    │    │  • WebSocket    │    │  • Native RPC   │             │
│  │  • Event Filter │    │  • Log Monitor  │    │  • Validator    │             │
│  │  • Gas Tracker  │    │  • Slot Track   │    │  • Block Track  │             │
│  └─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘             │
│            │                      │                      │                     │
│            └──────────────────────┼──────────────────────┘                     │
│                                   │                                            │
│  ┌─────────────────────────────────▼─────────────────────────────────────────┐  │
│  │                    🔄 Event Processing Engine                             │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐        │  │
│  │  │🛡️ Replay    │ │⚡ Circuit   │ │🔄 Retry     │ │📊 Metrics   │        │  │
│  │  │ Protection  │ │ Breakers    │ │ Queue       │ │ Collector   │        │  │
│  │  │• Hash Valid │ │• Fault Tol  │ │• Exp Backoff│ │• Real-time  │        │  │
│  │  │• BoltDB     │ │• Auto Recov │ │• Error Hand │ │• Prometheus │        │  │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘        │  │
│  └─────────────────────────────────┬─────────────────────────────────────────┘  │
│                                    │                                            │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐             │
│  │   💸 Ethereum   │    │   💸 Solana     │    │  💸 BlackHole   │             │
│  │     Relay       │    │     Relay       │    │     Relay       │             │
│  │  • Smart Cont   │    │  • Program Call │    │  • Native Tx    │             │
│  │  • Multi-Sig    │    │  • Token Mint   │    │  • Validator    │             │
│  │  • Gas Optim    │    │  • Compute Unit │    │  • Consensus    │             │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘             │
│                                                                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                              💾 Data & Storage Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │ 🗄️ BoltDB   │  │ 🗄️ PostgreSQL│  │ ⚡ Redis     │  │ 📊 Prometheus│           │
│  │ • Replay    │  │ • Tx History │  │ • Cache     │  │ • Metrics   │           │
│  │ • Events    │  │ • User Data  │  │ • Sessions  │  │ • Alerts    │           │
│  │ • Config    │  │ • Analytics  │  │ • Rate Limit│  │ • Dashboards│           │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            🌐 User Interface Layer                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │ 📊 Dashboard│  │ 📈 Grafana  │  │ 🔧 API      │  │ 📱 CLI      │           │
│  │ • Real-time │  │ • Monitoring│  │ • REST      │  │ • Admin     │           │
│  │ • WebSocket │  │ • Alerting  │  │ • WebSocket │  │ • Debug     │           │
│  │ • Cosmic UI │  │ • Analytics │  │ • GraphQL   │  │ • Deploy    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Ethereum   │────▶│   Bridge    │────▶│  BlackHole  │
│   Network   │     │    Core     │     │   Network   │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │
       │            ┌─────────────┐            │
       │            │   Solana    │            │
       └───────────▶│   Network   │◀───────────┘
                    └─────────────┘

Flow Steps:
1. 🔍 Event Detection    → Blockchain listeners detect transfer events
2. 🛡️ Security Check     → Replay protection & validation
3. 🔄 Processing         → Circuit breakers & retry mechanisms
4. 💸 Relay Execution    → Cross-chain transaction execution
5. ✅ Confirmation       → Block confirmations & finality
6. 📊 Monitoring         → Real-time updates & metrics
```

### Core Components

1. **🔗 Blockchain Listeners** - Monitor events on each blockchain with WebSocket connections
2. **🔄 Event Processing Engine** - Validates and processes cross-chain events with security layers
3. **💸 Relay System** - Executes transactions on destination chains with optimization
4. **🛡️ Security Layer** - Replay protection, circuit breakers, and validation
5. **📊 Monitoring Stack** - Metrics collection, logging, and alerting
6. **🌐 Web Dashboard** - Real-time monitoring interface with cosmic theme
7. **💾 Storage Layer** - Persistent data storage with multiple database systems
8. **🧪 Simulation Engine** - End-to-end testing and validation framework

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
- **Node.js 18+** (optional, for frontend development)

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

### Manual Installation

```bash
# 1. Clone and setup
git clone https://github.com/blackhole-network/bridge-sdk.git
cd bridge-sdk

# 2. Install Go dependencies
go mod tidy

# 3. Setup environment
cp .env.example .env

# 4. Create required directories
mkdir -p data logs simulation_screenshots simulation_logs

# 5. Run the bridge
cd example && go run main.go
```

## 📖 Configuration

### Environment Variables

The bridge uses environment variables for configuration. Copy `.env.example` to `.env` and customize:

#### Core Configuration
```bash
# Server Settings
PORT=8084                    # Web server port
LOG_LEVEL=info              # Logging level (debug, info, warn, error)

# Blockchain RPC Endpoints
ETHEREUM_RPC=wss://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
SOLANA_RPC=wss://api.devnet.solana.com
BLACKHOLE_RPC=ws://localhost:8545

# Database
DATABASE_PATH=./data/bridge.db
```

#### Security Configuration
```bash
# Replay Attack Protection
REPLAY_PROTECTION_ENABLED=true
REPLAY_CACHE_SIZE=10000
REPLAY_CACHE_TTL=24h

# Circuit Breakers
CIRCUIT_BREAKER_ENABLED=true
CIRCUIT_BREAKER_THRESHOLD=5
CIRCUIT_BREAKER_TIMEOUT=60s

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=1m
```

#### Enhanced Features
```bash
# Logging
ENABLE_COLORED_LOGS=true     # Colored console output
ENABLE_ZAP_LOGGER=true       # High-performance structured logging

# Simulation Mode
SIMULATION_MODE=false        # Enable simulation features
ENABLE_FULL_SIMULATION=false # Full end-to-end simulation
TOKEN_DEPLOYMENT_ENABLED=false # Deploy test tokens
SCREENSHOT_MODE=false        # Capture screenshots

# Performance
MAX_RETRIES=3               # Maximum retry attempts
RETRY_DELAY_MS=5000         # Delay between retries
BATCH_SIZE=100              # Transaction batch size
WORKER_COUNT=5              # Number of worker goroutines
```

#### Monitoring Configuration
```bash
# Metrics
ENABLE_METRICS=true
METRICS_PORT=9090

# Prometheus
PROMETHEUS_PORT=9091

# Grafana
GRAFANA_PORT=3000
GRAFANA_PASSWORD=admin123

# Health Checks
HEALTH_CHECK_INTERVAL=30s
```

### Configuration Examples

#### Development Configuration
```bash
# .env for development
PORT=8084
LOG_LEVEL=debug
ENABLE_COLORED_LOGS=true
ENABLE_ZAP_LOGGER=true
SIMULATION_MODE=true
ENABLE_FULL_SIMULATION=true
TOKEN_DEPLOYMENT_ENABLED=true
SCREENSHOT_MODE=true
DEBUG_MODE=true

# Use testnets
ETHEREUM_RPC=wss://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
SOLANA_RPC=wss://api.devnet.solana.com
```

#### Production Configuration
```bash
# .env for production
PORT=8084
LOG_LEVEL=info
ENABLE_COLORED_LOGS=false
ENABLE_ZAP_LOGGER=true
SIMULATION_MODE=false
DEBUG_MODE=false

# Use mainnets
ETHEREUM_RPC=wss://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
SOLANA_RPC=wss://api.mainnet-beta.solana.com

# Security
ENABLE_TLS=true
ENABLE_SECURITY_HEADERS=true
ENABLE_REQUEST_LOGGING=true
```

### Advanced Configuration

#### Custom Go Configuration
```go
config := &bridgesdk.Config{
    EthereumRPC:             "wss://your-ethereum-rpc",
    SolanaRPC:               "wss://your-solana-rpc",
    BlackHoleRPC:            "ws://your-blackhole-rpc",
    DatabasePath:            "./custom/path/bridge.db",
    LogLevel:                "info",
    LogFile:                 "./custom/logs/bridge.log",
    ReplayProtectionEnabled: true,
    CircuitBreakerEnabled:   true,
    Port:                    "8084",
    MaxRetries:              3,
    RetryDelay:              5 * time.Second,
    BatchSize:               100,
    SimulationMode:          false,
    EnableColoredLogs:       true,
    EnableZapLogger:         true,
}

sdk := bridgesdk.NewBridgeSDK(blockchain, config)
```

## 🎯 Usage Examples

### Basic Usage

```go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    bridgesdk "github.com/blackhole-network/bridge-sdk"
)

func main() {
    // Initialize bridge SDK with default configuration
    sdk := bridgesdk.NewBridgeSDK(nil, nil)

    // Setup graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Start blockchain listeners
    go func() {
        if err := sdk.StartEthereumListener(ctx); err != nil {
            log.Printf("Ethereum listener error: %v", err)
        }
    }()

    go func() {
        if err := sdk.StartSolanaListener(ctx); err != nil {
            log.Printf("Solana listener error: %v", err)
        }
    }()

    // Start web server
    go func() {
        if err := sdk.StartWebServer(":8084"); err != nil {
            log.Printf("Web server error: %v", err)
        }
    }()

    // Wait for interrupt signal
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan

    log.Println("Shutting down...")
    cancel()
}
```

### Advanced Configuration

```go
package main

import (
    "context"
    "time"

    bridgesdk "github.com/blackhole-network/bridge-sdk"
)

func main() {
    // Custom configuration
    config := &bridgesdk.Config{
        EthereumRPC:             "wss://eth-mainnet.alchemyapi.io/v2/YOUR_KEY",
        SolanaRPC:               "wss://api.mainnet-beta.solana.com",
        BlackHoleRPC:            "ws://localhost:8545",
        DatabasePath:            "./data/bridge.db",
        LogLevel:                "info",
        LogFile:                 "./logs/bridge.log",
        ReplayProtectionEnabled: true,
        CircuitBreakerEnabled:   true,
        Port:                    "8084",
        MaxRetries:              3,
        RetryDelay:              5 * time.Second,
        BatchSize:               100,
        SimulationMode:          false,
        EnableColoredLogs:       true,
        EnableZapLogger:         true,
    }

    sdk := bridgesdk.NewBridgeSDK(nil, config)

    // Start with custom context
    ctx := context.Background()
    sdk.StartEthereumListener(ctx)
    sdk.StartSolanaListener(ctx)
    sdk.StartWebServer(":8084")
}
```

### Transaction Monitoring

```go
// Monitor specific transaction
func monitorTransaction(sdk *bridgesdk.BridgeSDK, txID string) {
    for {
        status, err := sdk.GetTransactionStatus(txID)
        if err != nil {
            log.Printf("Error getting transaction status: %v", err)
            continue
        }

        log.Printf("Transaction %s status: %s", txID, status.Status)

        if status.Status == "completed" || status.Status == "failed" {
            break
        }

        time.Sleep(5 * time.Second)
    }
}

// Get all transactions
func getAllTransactions(sdk *bridgesdk.BridgeSDK) {
    transactions, err := sdk.GetAllTransactions()
    if err != nil {
        log.Printf("Error getting transactions: %v", err)
        return
    }

    for _, tx := range transactions {
        log.Printf("Transaction: %s, Status: %s, Amount: %s %s",
            tx.ID, tx.Status, tx.Amount, tx.TokenSymbol)
    }
}
```

### Custom Event Handlers

```go
// Custom event processing
func setupCustomHandlers(sdk *bridgesdk.BridgeSDK) {
    // Ethereum event handler
    sdk.OnEthereumEvent(func(event *bridgesdk.EthereumEvent) {
        log.Printf("🔗 Ethereum event detected:")
        log.Printf("  Block: %d", event.BlockNumber)
        log.Printf("  TxHash: %s", event.TxHash)
        log.Printf("  Amount: %s", event.Amount)
        log.Printf("  Token: %s", event.TokenSymbol)

        // Custom processing logic
        if event.Amount > "1000" {
            log.Printf("⚠️  Large transaction detected!")
            // Send alert, additional validation, etc.
        }
    })

    // Solana event handler
    sdk.OnSolanaEvent(func(event *bridgesdk.SolanaEvent) {
        log.Printf("🔗 Solana event detected:")
        log.Printf("  Slot: %d", event.Slot)
        log.Printf("  Signature: %s", event.Signature)
        log.Printf("  Amount: %s", event.Amount)

        // Custom processing logic
        processCustomSolanaLogic(event)
    })
}

func processCustomSolanaLogic(event *bridgesdk.SolanaEvent) {
    // Your custom Solana event processing
    log.Printf("Processing Solana event with custom logic...")
}
```

### Error Handling and Recovery

```go
// Advanced error handling
func setupErrorHandling(sdk *bridgesdk.BridgeSDK) {
    // Monitor circuit breaker status
    go func() {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()

        for range ticker.C {
            breakers := sdk.GetCircuitBreakerStatus()
            for name, status := range breakers {
                if status.State != "closed" {
                    log.Printf("⚠️  Circuit breaker %s is %s", name, status.State)
                }
            }
        }
    }()

    // Monitor failed events
    go func() {
        ticker := time.NewTicker(60 * time.Second)
        defer ticker.Stop()

        for range ticker.C {
            failedEvents := sdk.GetFailedEvents()
            if len(failedEvents) > 0 {
                log.Printf("⚠️  %d failed events need attention", len(failedEvents))

                // Attempt recovery
                for _, event := range failedEvents {
                    if event.RetryCount < event.MaxRetries {
                        log.Printf("🔄 Retrying failed event: %s", event.ID)
                        sdk.RetryFailedEvent(event.ID)
                    }
                }
            }
        }
    }()
}
```

### Health Monitoring

```go
// Health check implementation
func monitorHealth(sdk *bridgesdk.BridgeSDK) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        health := sdk.GetHealth()

        log.Printf("🏥 System Health: %s", health.Status)
        log.Printf("   Uptime: %s", health.Uptime)

        // Check individual components
        for component, status := range health.Components {
            if status != "healthy" {
                log.Printf("⚠️  Component %s is %s", component, status)

                // Take corrective action
                switch component {
                case "ethereum_listener":
                    // Restart Ethereum listener
                    sdk.RestartEthereumListener()
                case "solana_listener":
                    // Restart Solana listener
                    sdk.RestartSolanaListener()
                case "database":
                    // Check database connection
                    sdk.CheckDatabaseConnection()
                }
            }
        }

        // Check if overall system is healthy
        if !health.Healthy {
            log.Printf("🚨 System is unhealthy! Taking emergency actions...")
            // Implement emergency procedures
            handleSystemEmergency(sdk)
        }
    }
}

func handleSystemEmergency(sdk *bridgesdk.BridgeSDK) {
    // Emergency procedures
    log.Printf("🚨 Implementing emergency procedures...")

    // 1. Stop accepting new transactions
    sdk.SetMaintenanceMode(true)

    // 2. Complete pending transactions
    sdk.FlushPendingTransactions()

    // 3. Create system backup
    sdk.CreateEmergencyBackup()

    // 4. Send alerts
    sdk.SendEmergencyAlert("System health critical - emergency procedures activated")
}
```

## 🧪 Simulation Mode

The BlackHole Bridge includes a comprehensive simulation engine for testing and validation of cross-chain operations.

### Quick Simulation Setup

```bash
# 1. Enable simulation in .env
SIMULATION_MODE=true
ENABLE_FULL_SIMULATION=true
TOKEN_DEPLOYMENT_ENABLED=true
SCREENSHOT_MODE=true

# 2. Run simulation
cd example && go run main.go
```

### Simulation Features

#### 🪙 Token Deployment Testing
```bash
# Deploy test tokens on testnets
TOKEN_DEPLOYMENT_ENABLED=true
ETHEREUM_TESTNET_RPC=wss://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
SOLANA_TESTNET_RPC=wss://api.devnet.solana.com

# Simulation will deploy:
# - ERC-20 test token on Ethereum Sepolia
# - SPL test token on Solana Devnet
# - Native test token on BlackHole testnet
```

#### 📸 Screenshot Documentation
```bash
# Enable screenshot capture
SCREENSHOT_MODE=true

# Screenshots saved to:
# ./simulation_screenshots/
# ├── dashboard_overview.png
# ├── transaction_list.png
# ├── health_status.png
# ├── replay_protection.png
# └── circuit_breakers.png
```

#### 📊 Performance Testing
```bash
# Configure simulation parameters
SIMULATION_TRANSACTION_COUNT=50
SIMULATION_DURATION=10m
SIMULATION_CONCURRENT_TRANSFERS=5

# Metrics collected:
# - Transaction success rate
# - Average processing time
# - Error rates by chain
# - Replay attack detection
# - Circuit breaker triggers
```

### Advanced Simulation Configuration

#### Custom Simulation Script
```go
package main

import (
    "context"
    "time"

    bridgesdk "github.com/blackhole-network/bridge-sdk"
)

func runCustomSimulation() {
    // Create simulation configuration
    config := &bridgesdk.SimulationConfig{
        EnableFullSimulation:    true,
        TokenDeploymentEnabled:  true,
        ScreenshotMode:          true,
        TestnetMode:            true,
        EthereumTestnetRPC:     "wss://eth-sepolia.g.alchemy.com/v2/YOUR_KEY",
        SolanaTestnetRPC:       "wss://api.devnet.solana.com",
        SimulationDuration:     15 * time.Minute,
        TransactionCount:       100,
    }

    // Initialize simulation engine
    sdk := bridgesdk.NewBridgeSDK(nil, nil)
    engine := bridgesdk.NewSimulationEngine(sdk, config)

    // Run simulation
    ctx := context.Background()
    result, err := engine.RunFullSimulation(ctx)
    if err != nil {
        log.Printf("Simulation failed: %v", err)
        return
    }

    // Print results
    log.Printf("🎉 Simulation completed!")
    log.Printf("   Duration: %s", result.Duration)
    log.Printf("   Total Transactions: %d", result.TotalTransactions)
    log.Printf("   Success Rate: %.2f%%", result.SuccessRate)
    log.Printf("   Screenshots: %d", len(result.Screenshots))
    log.Printf("   Log Files: %d", len(result.LogFiles))
}
```

### Simulation Results Analysis

#### Generated Reports
```bash
# Simulation generates comprehensive reports:
./simulation_logs/
├── simulation_summary.json      # Overall results
├── transaction_details.log      # Detailed transaction logs
├── performance_metrics.json     # Performance analysis
├── error_analysis.log          # Error breakdown
└── security_validation.log     # Security test results
```

#### Sample Results
```json
{
  "simulation_id": "sim_1703123456",
  "start_time": "2023-12-21T10:30:00Z",
  "end_time": "2023-12-21T10:45:00Z",
  "duration": "15m0s",
  "total_transactions": 100,
  "successful_transactions": 97,
  "failed_transactions": 3,
  "success_rate": 97.0,
  "token_deployments": [
    {
      "symbol": "TESTETH",
      "name": "Test Ethereum Token",
      "address": "0x1234567890123456789012345678901234567890",
      "chain": "ethereum",
      "deployment_tx_hash": "0xabcdef..."
    }
  ],
  "metrics": {
    "avg_processing_time": "2.3s",
    "replay_attacks_blocked": 5,
    "circuit_breaker_triggers": 1,
    "max_concurrent_transactions": 8
  }
}
```

## 📚 API Reference

### REST Endpoints

| Endpoint | Method | Description | Parameters |
|----------|--------|-------------|------------|
| `/` | GET | Dashboard interface | - |
| `/health` | GET | System health status | - |
| `/stats` | GET | Bridge statistics | `?period=24h` |
| `/transactions` | GET | Transaction history | `?limit=50&offset=0&status=all` |
| `/transaction/{id}` | GET | Transaction details | - |
| `/transfer` | POST | Initiate transfer | JSON body |
| `/relay` | POST | Manual relay trigger | JSON body |
| `/errors` | GET | Error metrics | `?severity=all` |
| `/circuit-breakers` | GET | Circuit breaker status | - |
| `/failed-events` | GET | Failed events list | `?limit=20` |
| `/replay-protection` | GET | Replay protection status | - |
| `/processed-events` | GET | Processed events list | `?limit=100` |
| `/logs` | GET | Live logs interface | `?level=info&lines=1000` |
| `/simulation` | GET | Simulation status | - |
| `/simulation/start` | POST | Start simulation | JSON body |
| `/simulation/results` | GET | Simulation results | `?simulation_id=sim_123` |

### WebSocket Endpoints

| Endpoint | Description | Events |
|----------|-------------|--------|
| `/ws` | Real-time updates | `transaction_update`, `health_update`, `stats_update` |
| `/ws/transactions` | Transaction updates | `transaction_created`, `transaction_completed`, `transaction_failed` |
| `/ws/health` | Health status updates | `component_status_change`, `system_alert` |
| `/ws/logs` | Live log streaming | `log_entry` |
| `/ws/simulation` | Simulation updates | `simulation_progress`, `simulation_completed` |

### API Usage Examples

#### 1. Initiate Transfer
```bash
curl -X POST http://localhost:8084/transfer \
  -H "Content-Type: application/json" \
  -d '{
    "from_chain": "ethereum",
    "to_chain": "solana",
    "token_symbol": "USDC",
    "amount": "100.50",
    "from_address": "0x1234567890123456789012345678901234567890",
    "to_address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
  }'
```

#### 2. Check Transaction Status
```bash
curl http://localhost:8084/transaction/tx_123456789
```

#### 3. Get System Health
```bash
curl http://localhost:8084/health | jq
```

#### 4. Get Bridge Statistics
```bash
curl "http://localhost:8084/stats?period=24h" | jq
```

#### 5. Start Simulation
```bash
curl -X POST http://localhost:8084/simulation/start \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_count": 50,
    "duration": "10m",
    "enable_screenshots": true,
    "test_replay_protection": true
  }'
```

### Response Examples

#### Health Check Response
```json
{
  "status": "healthy",
  "uptime": "2h30m15s",
  "version": "1.0.0",
  "timestamp": "2023-12-21T10:30:00Z",
  "components": {
    "ethereum_listener": {
      "status": "healthy",
      "last_block": 18123456,
      "connection": "active",
      "latency": "45ms"
    },
    "solana_listener": {
      "status": "healthy",
      "last_slot": 234567890,
      "connection": "active",
      "latency": "23ms"
    },
    "database": {
      "status": "healthy",
      "connections": 5,
      "size": "1.2GB"
    },
    "circuit_breakers": {
      "status": "healthy",
      "active_breakers": 0,
      "total_breakers": 3
    }
  },
  "metrics": {
    "total_transactions": 15420,
    "successful_transactions": 15398,
    "failed_transactions": 22,
    "success_rate": 99.86,
    "avg_processing_time": "2.3s",
    "replay_attacks_blocked": 45
  }
}
```

#### Transaction Response
```json
{
  "id": "tx_123456789",
  "source_chain": "ethereum",
  "dest_chain": "solana",
  "source_address": "0x1234567890123456789012345678901234567890",
  "dest_address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
  "token_symbol": "USDC",
  "amount": "100.50",
  "status": "completed",
  "source_tx_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
  "dest_tx_hash": "5J7XKVx8Zx9YQGHm8Zx9YQGHm8Zx9YQGHm8Zx9YQGHm8Zx9YQGHm8Zx9YQGHm",
  "confirmations": {
    "source": 12,
    "destination": 32
  },
  "fees": {
    "source_fee": "0.002",
    "dest_fee": "0.000005",
    "bridge_fee": "0.1"
  },
  "processing_time": "2m15s",
  "created_at": "2023-12-21T10:30:00Z",
  "completed_at": "2023-12-21T10:32:15Z",
  "events": [
    {
      "timestamp": "2023-12-21T10:30:00Z",
      "event": "transfer_initiated",
      "details": "Transfer request received and validated"
    },
    {
      "timestamp": "2023-12-21T10:30:30Z",
      "event": "source_transaction_confirmed",
      "details": "Source transaction confirmed with 12 blocks"
    },
    {
      "timestamp": "2023-12-21T10:32:15Z",
      "event": "destination_transaction_completed",
      "details": "Tokens successfully minted on destination chain"
    }
  ]
}
```

### SDK Methods

```go
// Core methods
sdk.StartEthereumListener(ctx) error
sdk.StartSolanaListener(ctx) error
sdk.StartBlackHoleListener(ctx) error
sdk.StopListeners() error
sdk.RelayToChain(tx *Transaction, targetChain string) error

// Transaction management
sdk.GetTransactionStatus(id string) (*Status, error)
sdk.GetAllTransactions() ([]*Transaction, error)
sdk.GetTransactionsByStatus(status string) ([]*Transaction, error)
sdk.InitiateTransfer(request *TransferRequest) (*TransferResult, error)

// Monitoring and Health
sdk.GetBridgeStats() *BridgeStats
sdk.GetHealth() *HealthStatus
sdk.GetErrorMetrics() *ErrorMetrics
sdk.GetCircuitBreakerStatus() map[string]*CircuitBreakerStatus

// Simulation
sdk.RunSimulation(config *SimulationConfig) (*SimulationResult, error)
sdk.GetSimulationResults(id string) (*SimulationResult, error)

// Security
sdk.IsReplayAttack(hash string) bool
sdk.MarkAsProcessed(hash string) error
sdk.GetBlockedReplays() int64
```

## 🚀 Deployment

### Development Deployment

#### Local Development Setup
```bash
# 1. Clone and setup
git clone https://github.com/blackhole-network/bridge-sdk.git
cd bridge-sdk

# 2. Install dependencies
go mod download

# 3. Setup environment
cp .env.example .env

# 4. Configure for development
cat > .env << EOF
# Development Configuration
PORT=8084
LOG_LEVEL=debug
ENABLE_COLORED_LOGS=true
ENABLE_ZAP_LOGGER=true
DEBUG_MODE=true

# Use testnets for development
ETHEREUM_RPC=wss://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
SOLANA_RPC=wss://api.devnet.solana.com
BLACKHOLE_RPC=ws://localhost:8545

# Enable simulation features
SIMULATION_MODE=true
ENABLE_FULL_SIMULATION=true
TOKEN_DEPLOYMENT_ENABLED=true
SCREENSHOT_MODE=true

# Database
DATABASE_PATH=./data/bridge.db

# Security (relaxed for development)
REPLAY_PROTECTION_ENABLED=true
CIRCUIT_BREAKER_ENABLED=true
MAX_RETRIES=5
RETRY_DELAY_MS=3000
EOF

# 5. Create required directories
mkdir -p data logs simulation_screenshots simulation_logs

# 6. Run development server
cd example && go run main.go
```

#### Quick Start (Alternative)
```bash
# Start development environment
make dev

# Run tests
make test

# View logs
make logs
```

#### Or Simply Run
```bash
cd bridge-sdk/example
go run main.go
```

### Production Deployment

#### Docker Deployment (Recommended)
```bash
# 1. Clone and setup
git clone https://github.com/blackhole-network/bridge-sdk.git
cd bridge-sdk

# 2. Setup production environment
cp .env.example .env

# 3. Configure for production
cat > .env << EOF
# Production Configuration
PORT=8084
LOG_LEVEL=info
ENABLE_COLORED_LOGS=false
ENABLE_ZAP_LOGGER=true
DEBUG_MODE=false

# Production RPC endpoints
ETHEREUM_RPC=wss://eth-mainnet.g.alchemy.com/v2/YOUR_PRODUCTION_KEY
SOLANA_RPC=wss://api.mainnet-beta.solana.com
BLACKHOLE_RPC=wss://your-production-blackhole-rpc

# Database
DATABASE_PATH=/app/data/bridge.db

# Security (strict for production)
REPLAY_PROTECTION_ENABLED=true
CIRCUIT_BREAKER_ENABLED=true
MAX_RETRIES=3
RETRY_DELAY_MS=5000

# Disable simulation in production
SIMULATION_MODE=false
ENABLE_FULL_SIMULATION=false
TOKEN_DEPLOYMENT_ENABLED=false
SCREENSHOT_MODE=false

# Production security
ENABLE_TLS=true
ENABLE_SECURITY_HEADERS=true
ENABLE_REQUEST_LOGGING=true
RATE_LIMIT_ENABLED=true

# Monitoring
ENABLE_METRICS=true
PROMETHEUS_PORT=9091
GRAFANA_PORT=3000
GRAFANA_PASSWORD=your_secure_password
EOF

# 4. Deploy with Docker Compose
docker-compose up -d

# 5. Verify deployment
docker-compose ps
docker-compose logs -f bridge-node

# 6. Check health
curl http://localhost:8084/health
```

#### Alternative Production Commands
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

## � Troubleshooting

### Common Issues and Solutions

#### 1. Connection Issues

**Problem**: Cannot connect to blockchain RPC endpoints
```
Error: dial tcp: lookup eth-mainnet.alchemyapi.io: no such host
```

**Solutions**:
```bash
# Check network connectivity
ping eth-mainnet.alchemyapi.io

# Verify RPC URL format
echo $ETHEREUM_RPC

# Test with curl
curl -X POST $ETHEREUM_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Check firewall settings
sudo ufw status

# Verify DNS resolution
nslookup eth-mainnet.alchemyapi.io
```

#### 2. Database Issues

**Problem**: Database connection failures
```
Error: database is locked
Error: no such file or directory
```

**Solutions**:
```bash
# Check database file permissions
ls -la data/bridge.db

# Fix permissions
chmod 644 data/bridge.db
chown $USER:$USER data/bridge.db

# Check disk space
df -h

# Verify database path
echo $DATABASE_PATH

# Test database connection
sqlite3 data/bridge.db ".tables"
```

#### 3. Memory Issues

**Problem**: Out of memory errors
```
Error: runtime: out of memory
Error: cannot allocate memory
```

**Solutions**:
```bash
# Check memory usage
free -h
top -p $(pgrep -f "go run main.go")

# Increase Docker memory limits
# In docker-compose.yml:
services:
  bridge-node:
    mem_limit: 2g
    memswap_limit: 2g

# Optimize Go garbage collector
export GOGC=100
export GOMEMLIMIT=1GiB

# Monitor memory usage
go tool pprof http://localhost:8084/debug/pprof/heap
```

#### 4. Port Conflicts

**Problem**: Port already in use
```
Error: bind: address already in use
```

**Solutions**:
```bash
# Check what's using the port
lsof -i :8084
netstat -tulpn | grep 8084

# Kill process using the port
sudo kill -9 $(lsof -t -i:8084)

# Use different port
export PORT=8085

# Check available ports
ss -tuln | grep LISTEN
```

#### 5. Permission Issues

**Problem**: Permission denied errors
```
Error: permission denied
Error: operation not permitted
```

**Solutions**:
```bash
# Fix file permissions
chmod +x example/main.go
chmod -R 755 data/
chmod -R 755 logs/

# Fix ownership
sudo chown -R $USER:$USER .

# Run with sudo (not recommended for production)
sudo go run example/main.go

# Check SELinux (if applicable)
sestatus
sudo setsebool -P httpd_can_network_connect 1
```

#### 6. Docker Issues

**Problem**: Docker container failures
```
Error: container exited with code 1
Error: no space left on device
```

**Solutions**:
```bash
# Check Docker logs
docker-compose logs bridge-node

# Check disk space
docker system df
docker system prune -a

# Restart Docker daemon
sudo systemctl restart docker

# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Check container resources
docker stats
```

#### 7. Simulation Issues

**Problem**: Simulation failures
```
Error: simulation failed to start
Error: token deployment failed
```

**Solutions**:
```bash
# Check simulation configuration
echo $SIMULATION_MODE
echo $ENABLE_FULL_SIMULATION

# Verify testnet RPC endpoints
curl -X POST $ETHEREUM_RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}'

# Check simulation logs
tail -f simulation_logs/simulation_summary.json

# Disable problematic features
export TOKEN_DEPLOYMENT_ENABLED=false
export SCREENSHOT_MODE=false

# Run minimal simulation
export SIMULATION_TRANSACTION_COUNT=5
```

### Performance Optimization

#### 1. Database Optimization
```bash
# Optimize BoltDB settings
export BOLT_TIMEOUT=5s
export BOLT_NO_SYNC=false

# Regular database maintenance
sqlite3 data/bridge.db "VACUUM;"
sqlite3 data/bridge.db "ANALYZE;"

# Monitor database size
du -h data/bridge.db
```

#### 2. Memory Optimization
```bash
# Tune garbage collector
export GOGC=50  # More aggressive GC
export GOMEMLIMIT=512MiB

# Reduce batch sizes
export BATCH_SIZE=50
export WORKER_COUNT=3

# Monitor memory usage
watch -n 1 'ps aux | grep "go run main.go"'
```

#### 3. Network Optimization
```bash
# Increase connection timeouts
export RPC_TIMEOUT=30s
export WEBSOCKET_TIMEOUT=60s

# Use connection pooling
export MAX_CONNECTIONS=10
export IDLE_TIMEOUT=300s

# Monitor network usage
iftop -i eth0
```

### Debugging Tools

#### 1. Enable Debug Mode
```bash
# Enable comprehensive debugging
export DEBUG_MODE=true
export LOG_LEVEL=debug
export ENABLE_PROFILING=true

# Run with race detector
go run -race example/main.go

# Enable memory profiling
go run example/main.go &
go tool pprof http://localhost:8084/debug/pprof/heap
```

#### 2. Log Analysis
```bash
# Real-time log monitoring
tail -f logs/bridge.log | grep ERROR

# Search for specific errors
grep -r "circuit breaker" logs/

# Analyze log patterns
awk '/ERROR/ {print $1, $2, $NF}' logs/bridge.log

# Monitor WebSocket connections
curl -s http://localhost:8084/ws/logs
```

#### 3. Health Monitoring
```bash
# Continuous health checks
watch -n 5 'curl -s http://localhost:8084/health | jq'

# Monitor specific components
curl -s http://localhost:8084/health | jq '.components'

# Check circuit breaker status
curl -s http://localhost:8084/circuit-breakers | jq

# Monitor replay protection
curl -s http://localhost:8084/replay-protection | jq
```

### Recovery Procedures

#### 1. Database Recovery
```bash
# Backup current database
cp data/bridge.db data/bridge.db.backup

# Restore from backup
cp data/bridge.db.backup data/bridge.db

# Reset database (CAUTION: Data loss)
rm data/bridge.db
mkdir -p data
```

#### 2. Service Recovery
```bash
# Graceful restart
curl -X POST http://localhost:8084/admin/restart

# Force restart
pkill -f "go run main.go"
cd example && go run main.go &

# Docker restart
docker-compose restart bridge-node
```

#### 3. Emergency Procedures
```bash
# Stop all processing
curl -X POST http://localhost:8084/admin/maintenance

# Emergency backup
tar -czf emergency_backup_$(date +%Y%m%d_%H%M%S).tar.gz data/ logs/

# Reset to safe state
export SIMULATION_MODE=false
export CIRCUIT_BREAKER_ENABLED=true
export MAX_RETRIES=1
```

### Getting Help

#### 1. Collect System Information
```bash
# System info script
cat > debug_info.sh << 'EOF'
#!/bin/bash
echo "=== System Information ==="
uname -a
echo "=== Go Version ==="
go version
echo "=== Docker Version ==="
docker --version
echo "=== Memory Usage ==="
free -h
echo "=== Disk Usage ==="
df -h
echo "=== Network Interfaces ==="
ip addr show
echo "=== Environment Variables ==="
env | grep -E "(ETHEREUM|SOLANA|BLACKHOLE|PORT|LOG)" | sort
echo "=== Process Information ==="
ps aux | grep -E "(go|bridge)" | head -10
echo "=== Recent Logs ==="
tail -20 logs/bridge.log 2>/dev/null || echo "No logs found"
EOF

chmod +x debug_info.sh
./debug_info.sh > debug_report.txt
```

#### 2. Support Channels
- **GitHub Issues**: https://github.com/blackhole-network/bridge-sdk/issues
- **Discord**: https://discord.gg/blackhole-network
- **Documentation**: https://docs.blackhole.network
- **Email**: support@blackhole.network

#### 3. Before Reporting Issues
1. Check this troubleshooting guide
2. Search existing GitHub issues
3. Collect debug information using the script above
4. Include reproduction steps
5. Specify your environment (OS, Go version, Docker version)

## �📖 Documentation

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
