# BlackHole Blockchain & Bridge SDK Docker Setup

## Quick Start

### Single Command Execution

```bash
# From the project root directory
cd docker
docker-compose up
```

This will start both services simultaneously:
- **Main BlackHole Blockchain** on ports 8080, 8545, 30303
- **Bridge SDK Dashboard** on ports 8084, 9090

### Alternative Commands

```bash
# Build and run in detached mode
docker-compose up -d

# View logs from both services
docker-compose logs -f

# View logs from specific service
docker-compose logs -f blockchain
docker-compose logs -f bridge-sdk

# Stop all services
docker-compose down

# Rebuild and restart
docker-compose up --build

# Start only specific service
docker-compose up blockchain
docker-compose up bridge-sdk
```

## Access Points

### Main Blockchain Dashboard
- **Blockchain Dashboard**: http://localhost:8080
- **RPC Endpoint**: http://localhost:8545
- **Health Check**: http://localhost:8080/health
- **Peer Monitoring**: http://localhost:8080/peers

### Bridge SDK Dashboard
- **Bridge Dashboard**: http://localhost:8084
- **Infrastructure Dashboard**: http://localhost:8084/infra-dashboard
- **Health Check**: http://localhost:8084/health
- **API Documentation**: http://localhost:8084/docs
- **Relay Server**: http://localhost:9090

## Configuration

Edit the `.env` file to customize:

### Shared Configuration
- Log levels and colored output
- Node identification

### Blockchain Configuration
- Peer discovery settings
- Maximum peer connections
- Bootstrap peer addresses
- P2P networking

### Bridge SDK Configuration
- Security features (replay protection, circuit breakers)
- RPC endpoints for external chains
- Retry settings and performance tuning

## Data Persistence

### Blockchain Data
- Database: `blockchain_data` Docker volume
- Logs: `blockchain_logs` Docker volume
- Config: `blockchain_config` Docker volume

### Bridge SDK Data
- Database: `bridge_data` Docker volume
- Logs: `bridge_logs` Docker volume

## Networking

- Both services run on isolated `blackhole_network`
- Bridge SDK connects to blockchain via internal networking
- External access through mapped ports

## Requirements

- Docker & Docker Compose
- 4GB RAM minimum (2GB per service)
- Ports 8080, 8084, 8545, 9090, 30303 available
- Go 1.24.3+ (handled automatically in containers)

## API Endpoints

Once running, you can access:

- **Bridge Dashboard**: http://localhost:8084
- **Blockchain API**: http://localhost:8080 (blockchain node)
- **Bridge API**: http://localhost:8084/api/
- **WebSocket**: ws://localhost:8084/ws
- **gRPC Service**: localhost:9090

### Core API Endpoints

- `GET /api/log/status` - Comprehensive system status and health
- `GET /api/log/retry` - Retry queue information and statistics
- `GET /api/wallet/transactions` - Wallet transaction history
- `GET /api/main-dashboard/activities` - Admin dashboard activities
- `POST /api/test/retry-demo` - Test retry mechanism demonstration
- `POST /api/bridge/transfer` - Initiate cross-chain transfer
- `WebSocket /ws` - Real-time event streaming

### New Logging & Monitoring Endpoints

- `GET /api/log/status` - System health, uptime, performance metrics
- `GET /api/log/retry` - Active retry items, dead letter queue, success rates
- `POST /api/test/retry-demo` - Simulate failed events for retry testing

### API Testing Examples

```bash
# Check system status
curl http://localhost:8084/api/log/status

# Check retry queue
curl http://localhost:8084/api/log/retry

# Test retry demo
curl -X POST http://localhost:8084/api/test/retry-demo \
  -H "Content-Type: application/json" \
  -d '{"event_type":"ethereum_event","failure_count":3,"test_mode":"retry"}'

# Get wallet transactions
curl http://localhost:8084/api/wallet/transactions
```

## gRPC Schema

The bridge includes comprehensive gRPC API schema at `bridge-sdk/api-schema.proto` with:
- Transaction processing methods
- Wallet operations
- Retry mechanisms
- System monitoring
- Real-time event streaming

See `bridge-api.md` for complete API documentation.
