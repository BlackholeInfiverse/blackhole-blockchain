# BlackHole Blockchain - Docker Services Setup

This document describes the separate Docker setup for running the BlackHole Blockchain services.

## Overview

The services have been split into three separate Docker Compose files to ensure proper startup order and avoid dependency issues:

1. **Blockchain Nodes** (`docker-compose.blockchain.yml`) - 5 blockchain nodes
2. **Wallet Service** (`docker-compose.wallet.yml`) - Wallet web interface
3. **Bridge Service** (`docker-compose.bridge.yml`) - Bridge SDK for cross-chain transfers

## Quick Start

### Using the Startup Script (Recommended)

**PowerShell (Windows):**
```powershell
.\start-services.ps1
```

**Bash (Linux/Mac):**
```bash
chmod +x start-services.sh
./start-services.sh
```

The script will:
1. Stop any existing containers
2. Start blockchain nodes and wait for them to be healthy
3. Start the wallet service
4. Start the bridge service
5. Display the status and service URLs

### Manual Startup

If you prefer to start services manually:

#### 1. Start Blockchain Nodes
```bash
docker compose -f docker-compose.blockchain.yml up -d
```

Wait for the nodes to be healthy:
```bash
docker inspect blackhole-node-1 --format='{{.State.Health.Status}}'
```

#### 2. Start Wallet Service
```bash
docker compose -f docker-compose.wallet.yml up -d
```

#### 3. Start Bridge Service
```bash
docker compose -f docker-compose.bridge.yml up -d
```

## Service URLs

Once all services are running:

- **Blockchain Node 1:** http://localhost:8080
- **Blockchain Node 2:** http://localhost:8081
- **Blockchain Node 3:** http://localhost:8082
- **Blockchain Node 4:** http://localhost:8083
- **Blockchain Node 5:** http://localhost:8085
- **Wallet Dashboard:** http://localhost:9000
- **Bridge Dashboard:** http://localhost:8084
- **Bridge Relay Server:** http://localhost:9090

## Useful Commands

### Check Service Status
```bash
docker ps --filter "name=blackhole"
```

### View Logs

**Blockchain:**
```bash
docker compose -f docker-compose.blockchain.yml logs -f blockchain-node-1
```

**Wallet:**
```bash
docker compose -f docker-compose.wallet.yml logs -f wallet
```

**Bridge:**
```bash
docker compose -f docker-compose.bridge.yml logs -f bridge
```

### Stop Services

**Stop all:**
```bash
docker compose down
docker compose -f docker-compose.blockchain.yml down
docker compose -f docker-compose.wallet.yml down
docker compose -f docker-compose.bridge.yml down
```

**Stop individual service:**
```bash
docker compose -f docker-compose.<service>.yml down
```

### Restart Services

Use the startup script or manually restart:
```bash
docker compose -f docker-compose.<service>.yml restart
```

## Troubleshooting

### Bridge Keeps Restarting

**Previous Issue (Fixed):** The bridge was crashing due to a nil pointer dereference.
**Fix Applied:** Added nil checks in `bridge-sdk/main_bridge/main.go` at line 100-103.

If the issue persists:
```bash
docker compose -f docker-compose.bridge.yml logs bridge
```

### Wallet Not Starting

**Common Issue:** Wallet can't find `services/wallet/main.go`.
**Fix Applied:** Changed working directory from `/workspace/services/wallet` to `/workspace` and removed `:ro` (read-only) flag.

Check wallet logs:
```bash
docker logs blackhole-wallet --tail 50
```

### Blockchain Nodes Not Healthy

Wait up to 60 seconds for nodes to initialize. If they don't become healthy:
```bash
docker compose -f docker-compose.blockchain.yml logs blockchain-node-1
```

### Volume Issues

If you get volume errors, ensure volumes are created:
```bash
docker volume ls | grep blackhole
```

To recreate volumes (WARNING: deletes all data):
```bash
docker compose -f docker-compose.blockchain.yml down -v
docker compose -f docker-compose.wallet.yml down -v
docker compose -f docker-compose.bridge.yml down -v
```

## Network Configuration

All services share the `blackhole-network` bridge network, allowing them to communicate:

- Blockchain nodes can discover each other via P2P
- Wallet connects to blockchain via `http://blackhole-node-1:8080`
- Bridge connects to blockchain via the shared volume and network

## Volumes

### Blockchain
- `blockchain-data-1` to `blockchain-data-5`: Node data
- `blockchain-logs-1` to `blockchain-logs-5`: Node logs
- `blockchain_data`: Shared blockchain identity

### Bridge
- `bridge-data`: Bridge database and state
- `bridge-logs`: Bridge logs

### Wallet
- Uses bind mount to current directory for live code updates

## Environment Variables

You can customize services using environment variables in `.env` file:

```env
LOG_LEVEL=info
PEER_DISCOVERY=true
MAX_PEERS=50
```

## Architecture

```
┌─────────────────────────────────────────┐
│         blackhole-network               │
│                                         │
│  ┌──────────────┐  ┌──────────────┐   │
│  │ Blockchain   │  │ Blockchain   │   │
│  │   Node 1     │←→│   Node 2-5   │   │
│  │   :8080      │  │ :8081-8085   │   │
│  └──────┬───────┘  └──────────────┘   │
│         │                               │
│    ┌────┴────┐                         │
│    │         │                         │
│  ┌─▼────┐  ┌─▼──────┐                 │
│  │Wallet│  │ Bridge │                 │
│  │:9000 │  │ :8084  │                 │
│  └──────┘  └────────┘                 │
│                                         │
└─────────────────────────────────────────┘
```

## Changes from Original Setup

1. **Separated Services:** Split single `docker-compose.yml` into three files
2. **Sequential Startup:** Blockchain → Wallet → Bridge
3. **Fixed Dependencies:** Removed hard dependencies that caused restart loops
4. **Fixed Bridge Crash:** Added nil pointer checks
5. **Fixed Wallet Path:** Corrected working directory and volume mount
6. **Added Startup Scripts:** Automated sequential startup with health checks

## Reverting to Original Setup

If you need to use the original single-file setup:
```bash
docker compose down
docker compose -f docker-compose.blockchain.yml down
docker compose -f docker-compose.wallet.yml down
docker compose -f docker-compose.bridge.yml down

docker compose up -d
```

Note: The original setup may still have the restart issues that were fixed in this separated setup.
