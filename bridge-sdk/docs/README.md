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
- **✅ Real-time dashboard** with cosmic video background and golden color scheme
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
│  │ • Config    │  │ • Analytics  │  │ • Rate Limit│ │ • Dashboards│           │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            🌐 User Interface Layer                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │ 📊 Dashboard│  │ 📈 Grafana  │  │ 🔧 API      │  │ 📱 CLI      │           │
│  │ • Real-time │  │ • Monitoring│  │ • REST      │  │ • Admin     │           │
│  │ • WebSocket │  │ • Alerting  │  │ • WebSocket │  │ • Debug     │           │
│  │ • Video BG  │  │ • Analytics │  │ • GraphQL   │  │ • Deploy    │           │
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
6. **🌐 Web Dashboard** - Real-time monitoring interface with cosmic video background
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
- Real-time transaction monitoring with cosmic video background
- System health visualization with golden color scheme
- Interactive controls and responsive design
- WebSocket streaming for live updates
- Quick action sidebar with transfer widgets
- Collapsible menu sections for better UX

**Log Streamer** (`log_streamer.go`)
- Real-time log streaming with colored output
- WebSocket connections for live updates
- Structured logging with Zap/Logrus integration
- Performance tracking and metrics collection

### 🎬 **Video Background System**

The dashboard features a stunning cosmic video background system:

**Video Files** (`media/`)
```
bridge-sdk/media/
├── blackhole.mp4      # Primary cosmic video background
└── blackhole_2.mp4    # Secondary/fallback video
```

**Video Implementation**
```html
<!-- Cosmic video background with autoplay and loop -->
<div class="video-background">
    <video autoplay muted loop playsinline>
        <source src="media/blackhole.mp4" type="video/mp4">
        <source src="media/blackhole_2.mp4" type="video/mp4">
        Your browser does not support the video tag.
    </video>
</div>
```

**Video Styling**
```css
.video-background {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: -10;
    overflow: hidden;
}

.video-background video {
    width: 100%;
    height: 100%;
    object-fit: cover;
    opacity: 0.8;
    filter: brightness(0.7) contrast(1.2);
}
```

**Video Features**
- **Autoplay**: Starts automatically when dashboard loads
- **Loop**: Continuous playback for immersive experience
- **Muted**: No audio to avoid disruption
- **Responsive**: Scales to fit any screen size
- **Fallback**: Multiple video sources for compatibility
- **Performance**: Optimized for smooth playback

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
