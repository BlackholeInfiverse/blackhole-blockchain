# 🌉 BlackHole Bridge SDK

A comprehensive cross-chain bridge solution connecting Ethereum, Solana, and BlackHole blockchains with advanced features including replay attack protection, circuit breakers, and full end-to-end simulation capabilities.

## ✨ Features

### Core Bridge Functionality
- **Cross-chain token transfers** between Ethereum ↔ Solana ↔ BlackHole
- **Real-time transaction monitoring** with WebSocket streaming
- **Instant token transfers** with minimal processing time
- **Bidirectional swaps** supporting all chain combinations

### Security & Reliability
- **🛡️ Replay Attack Protection** with BoltDB persistence and hash validation
- **⚡ Circuit Breaker Pattern** for fault tolerance and graceful degradation
- **🔄 Retry Queue System** with exponential backoff for failed operations
- **🚨 Panic Recovery** with graceful shutdown handlers

### Monitoring & Observability
- **📊 Real-time Dashboard** with cosmic-themed UI and golden color scheme
- **📈 Comprehensive Metrics** with Prometheus integration
- **📝 Enhanced Logging** with Zap/Logrus support and colored CLI output
- **🏥 Health Monitoring** with detailed component status

### Simulation & Testing
- **🧪 Full End-to-End Simulation** with real testnet deployments
- **🪙 Token Deployment** on Ethereum/Solana testnets
- **📸 Screenshot Capture** for verification and documentation
- **📜 Comprehensive Logging** with detailed transaction flows

### Production Ready
- **🐳 Docker Deployment** with docker-compose setup
- **🔧 Environment Configuration** with comprehensive .env support
- **📚 Complete Documentation** with architecture diagrams
- **🚀 One-Command Startup** for production deployment

## 🚀 Quick Start

### Prerequisites
- Go 1.19+
- Docker & Docker Compose
- Git

### 1. Clone and Setup
```bash
git clone <repository-url>
cd blackhole-blockchain/bridge-sdk
cp .env.example .env
# Edit .env with your configuration
```

### 2. One-Command Startup
```bash
# Development mode
go run example/main.go

# Production mode with Docker
docker-compose up -d
```

### 3. Access Dashboard
- **Main Dashboard**: http://localhost:8084
- **Health Check**: http://localhost:8084/health
- **Statistics**: http://localhost:8084/stats
- **Transactions**: http://localhost:8084/transactions

## 📋 Configuration

### Environment Variables

#### Core Configuration
```bash
# Server
PORT=8084
LOG_LEVEL=info

# Blockchain RPCs
ETHEREUM_RPC=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
SOLANA_RPC=https://api.devnet.solana.com
BLACKHOLE_RPC=ws://localhost:8545

# Security
REPLAY_PROTECTION_ENABLED=true
CIRCUIT_BREAKER_ENABLED=true
```

#### Enhanced Features
```bash
# Logging
ENABLE_COLORED_LOGS=true
ENABLE_ZAP_LOGGER=true

# Simulation
SIMULATION_MODE=false
ENABLE_FULL_SIMULATION=false
TOKEN_DEPLOYMENT_ENABLED=false
SCREENSHOT_MODE=false
```

See [.env.example](.env.example) for complete configuration options.

## 🏗️ Architecture

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Ethereum      │    │     Solana      │    │   BlackHole     │
│   Listener      │    │    Listener     │    │   Listener      │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │      Bridge SDK Core      │
                    │  ┌─────────────────────┐  │
                    │  │ Replay Protection   │  │
                    │  │ Circuit Breakers    │  │
                    │  │ Retry Queue         │  │
                    │  │ Panic Recovery      │  │
                    │  └─────────────────────┘  │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │     Web Dashboard         │
                    │  ┌─────────────────────┐  │
                    │  │ Real-time Updates   │  │
                    │  │ Transaction Monitor │  │
                    │  │ Health Status       │  │
                    │  │ Simulation Results  │  │
                    │  └─────────────────────┘  │
                    └───────────────────────────┘
```

### Data Flow

1. **Transaction Detection**: Blockchain listeners monitor for bridge events
2. **Validation**: Replay protection validates transaction uniqueness
3. **Processing**: Circuit breakers ensure reliable processing
4. **Relay**: Transactions are relayed to destination chains
5. **Monitoring**: Real-time updates via WebSocket to dashboard

## 🧪 Simulation Mode

### Full End-to-End Simulation

Enable comprehensive testing with real testnet deployments:

```bash
# Enable simulation in .env
ENABLE_FULL_SIMULATION=true
TOKEN_DEPLOYMENT_ENABLED=true
SCREENSHOT_MODE=true

# Run simulation
go run example/main.go
```

### Simulation Features

- **Token Deployment**: Deploys test ERC-20/SPL tokens on testnets
- **Real Transactions**: Captures actual blockchain transactions
- **Screenshot Documentation**: Automated capture of dashboard states
- **Comprehensive Logging**: Detailed logs for verification
- **Performance Metrics**: Success rates, processing times, error analysis

### Simulation Results

Results are saved to:
- `./simulation_screenshots/` - Dashboard screenshots
- `./simulation_logs/` - Detailed transaction logs
- `./data/bridge.db` - Persistent transaction data

## 🔧 Development

### Project Structure
```
bridge-sdk/
├── example/
│   └── main.go              # Main application entry point
├── bridge_core.go           # Core bridge functionality
├── bridge_sdk.go            # SDK structure and initialization
├── circuit_breaker.go       # Circuit breaker implementation
├── replay_protection.go     # Replay attack protection
├── retry_queue.go           # Retry queue and error handling
├── transfer.go              # Transfer management
├── simulation.go            # End-to-end simulation engine
├── dashboard_components.go  # Dashboard UI components
├── docker-compose.yml       # Production deployment
├── .env.example            # Configuration template
└── README.md               # This file
```

### Adding New Features

1. **Create Component**: Add new .go file in bridge-sdk/
2. **Integrate**: Import and use in example/main.go
3. **Configure**: Add environment variables to .env.example
4. **Document**: Update README.md and add examples

### Testing

```bash
# Run basic tests
go test ./...

# Run with simulation
SIMULATION_MODE=true go run example/main.go

# Run full end-to-end test
ENABLE_FULL_SIMULATION=true go run example/main.go
```

## 🐳 Docker Deployment

### Production Deployment

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f bridge-node

# Stop services
docker-compose down
```

### Services Included

- **bridge-node**: Main bridge application
- **redis**: Caching and session management
- **postgres**: Persistent data storage
- **prometheus**: Metrics collection
- **grafana**: Monitoring dashboards
- **nginx**: Reverse proxy and SSL termination

### Health Checks

All services include health checks for monitoring:

```bash
# Check service health
docker-compose ps

# View health status
curl http://localhost:8084/health
```

## 📊 Monitoring

### Metrics Available

- **Transaction Metrics**: Count, success rate, processing time
- **Chain Metrics**: Per-chain statistics and health
- **System Metrics**: Memory, CPU, database performance
- **Security Metrics**: Replay attacks blocked, circuit breaker status

### Grafana Dashboards

Access Grafana at http://localhost:3000 (admin/admin123) for:

- **Bridge Overview**: High-level metrics and status
- **Transaction Analysis**: Detailed transaction flows
- **System Health**: Infrastructure monitoring
- **Security Dashboard**: Replay protection and circuit breakers

## 🔒 Security

### Replay Attack Protection

- **Hash-based Detection**: SHA-256 hashes of transaction details
- **Persistent Storage**: BoltDB for durability across restarts
- **Memory Cache**: Fast lookup with configurable TTL
- **Automatic Cleanup**: Expired entries removed automatically

### Circuit Breaker Pattern

- **Failure Detection**: Configurable failure thresholds
- **Automatic Recovery**: Self-healing with timeout mechanisms
- **Graceful Degradation**: Maintains service availability
- **Real-time Monitoring**: Dashboard integration for status

### Best Practices

1. **Private Key Security**: Use environment variables, never commit keys
2. **Network Security**: Firewall rules for production deployment
3. **SSL/TLS**: Enable HTTPS for production web interfaces
4. **Regular Updates**: Keep dependencies and base images updated
5. **Monitoring**: Set up alerts for critical failures

## 📚 API Reference

### REST Endpoints

- `GET /` - Main dashboard
- `GET /health` - System health status
- `GET /stats` - Bridge statistics
- `GET /transactions` - Transaction list
- `POST /transfer` - Initiate transfer
- `POST /relay` - Manual relay operation

### WebSocket Events

- `transaction_update` - Real-time transaction status
- `health_update` - System health changes
- `stats_update` - Statistics updates

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check this README and inline code comments
- **Issues**: Open GitHub issues for bugs and feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas

## 🎯 Roadmap

- [ ] Multi-signature wallet support
- [ ] Advanced fee optimization
- [ ] Cross-chain NFT transfers
- [ ] Mobile app integration
- [ ] Governance token integration
- [ ] Layer 2 network support

---

**Built with ❤️ for the BlackHole ecosystem**
