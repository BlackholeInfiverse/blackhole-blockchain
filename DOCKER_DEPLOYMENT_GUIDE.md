# Docker Deployment Guide - BlackHole Cluster

**Date:** 2025-11-05  
**Status:** Ready for Deployment

---

## 📋 Architecture Overview

### Cluster Composition

```
┌─────────────────────────────────────────────────────────────┐
│                  BLACKHOLE BLOCKCHAIN CLUSTER                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ╔════════════════════════════════════════════════════════╗ │
│  ║        BLOCKCHAIN NODES (5-Node Cluster)               ║ │
│  ║  Ports 8081-8085 (Dashboard)                           ║ │
│  ║  Ports 8545-8549 (RPC)                                 ║ │
│  ║  Ports 30303-30307 (P2P)                               ║ │
│  ╚════════════════════════════════════════════════════════╝ │
│                                                              │
│  ╔════════════════════════════════════════════════════════╗ │
│  ║        DASHBOARD NODES (5-Node Independent)            ║ │
│  ║  Ports 9001-9005 (Dashboard)                           ║ │
│  ║  Ports 9545-9549 (RPC)                                 ║ │
│  ║  Ports 39303-39307 (P2P)                               ║ │
│  ╚════════════════════════════════════════════════════════╝ │
│                                                              │
│  ╔════════════════════════════════════════════════════════╗ │
│  ║           BRIDGE SERVICE                               ║ │
│  ║  Port 8090 (Bridge API)                                ║ │
│  ║  Port 9090 (gRPC Relay)                                ║ │
│  ╚════════════════════════════════════════════════════════╝ │
│                                                              │
│  ╔════════════════════════════════════════════════════════╗ │
│  ║        MONITORING & DATABASE                           ║ │
│  ║  Prometheus: Port 9091                                 ║ │
│  ║  PostgreSQL: Port 5432                                 ║ │
│  ╚════════════════════════════════════════════════════════╝ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Deployment Steps

### 1. Prerequisites

```bash
# Verify Docker is installed
docker --version
docker-compose --version

# Navigate to project directory
cd C:\Users\pc2\Desktop\Qoder\blackhole-blockchain
```

### 2. Build Docker Images

```bash
# Build all images (this will take 5-10 minutes)
docker-compose -f docker-compose.cluster.yml build

# Verify build completion
docker images | grep blackhole
```

### 3. Start Services

```bash
# Start all services in background
docker-compose -f docker-compose.cluster.yml up -d

# Monitor startup (wait 30-60 seconds for health checks)
docker-compose -f docker-compose.cluster.yml logs -f
```

### 4. Verify Deployment

```bash
# Check all services are running
docker-compose -f docker-compose.cluster.yml ps

# Expected output: All containers should be 'Up'
```

---

## 📊 Service Access

### Blockchain Nodes

| Node | Dashboard | RPC | P2P Port |
|------|-----------|-----|----------|
| Node 1 | http://localhost:8081 | http://localhost:8545 | 30303 |
| Node 2 | http://localhost:8082 | http://localhost:8546 | 30304 |
| Node 3 | http://localhost:8083 | http://localhost:8547 | 30305 |
| Node 4 | http://localhost:8084 | http://localhost:8548 | 30306 |
| Node 5 | http://localhost:8085 | http://localhost:8549 | 30307 |

### Dashboard Nodes

| Dashboard | Port | RPC | P2P Port |
|-----------|------|-----|----------|
| Dashboard 1 | http://localhost:9001 | http://localhost:9545 | 39303 |
| Dashboard 2 | http://localhost:9002 | http://localhost:9546 | 39304 |
| Dashboard 3 | http://localhost:9003 | http://localhost:9547 | 39305 |
| Dashboard 4 | http://localhost:9004 | http://localhost:9548 | 39306 |
| Dashboard 5 | http://localhost:9005 | http://localhost:9549 | 39307 |

### Bridge Service

| Service | Port | URL |
|---------|------|-----|
| Bridge API | 8090 | http://localhost:8090 |
| Bridge gRPC | 9090 | localhost:9090 |

### Monitoring

| Service | Port | URL |
|---------|------|-----|
| Prometheus | 9091 | http://localhost:9091 |
| PostgreSQL | 5432 | localhost:5432 |

---

## 🔍 Monitoring Commands

### View Logs

```bash
# All services
docker-compose -f docker-compose.cluster.yml logs -f

# Specific service
docker-compose -f docker-compose.cluster.yml logs -f blockchain-node-1
docker-compose -f docker-compose.cluster.yml logs -f dashboard-node-1
docker-compose -f docker-compose.cluster.yml logs -f bridge-service

# Last 100 lines
docker-compose -f docker-compose.cluster.yml logs --tail=100 blockchain-node-1
```

### Check Service Health

```bash
# Test blockchain nodes
curl http://localhost:8081/health
curl http://localhost:8082/health
curl http://localhost:8083/health
curl http://localhost:8084/health
curl http://localhost:8085/health

# Test dashboard nodes
curl http://localhost:9001/health
curl http://localhost:9002/health
curl http://localhost:9003/health
curl http://localhost:9004/health
curl http://localhost:9005/health

# Test bridge
curl http://localhost:8090/health

# Test RPC endpoints
curl http://localhost:8545
curl http://localhost:9545
```

### Get Container Information

```bash
# List all containers
docker-compose -f docker-compose.cluster.yml ps

# Get specific container stats
docker stats blockchain-node-1
docker stats dashboard-node-1
docker stats blackhole-bridge

# View container logs in real-time
docker logs -f blackhole-node-1
docker logs -f dashboard-node-1
docker logs -f blackhole-bridge
```

---

## 🛑 Stopping Services

### Stop All Services

```bash
# Stop all containers (keeps volumes)
docker-compose -f docker-compose.cluster.yml down

# Stop and remove volumes
docker-compose -f docker-compose.cluster.yml down -v
```

### Stop Specific Service

```bash
# Stop a specific container
docker-compose -f docker-compose.cluster.yml stop blockchain-node-1
docker-compose -f docker-compose.cluster.yml stop dashboard-node-1
docker-compose -f docker-compose.cluster.yml stop bridge-service

# Restart service
docker-compose -f docker-compose.cluster.yml restart blockchain-node-1
```

---

## 🔧 Troubleshooting

### Issue: Container Won't Start

```bash
# Check logs
docker-compose -f docker-compose.cluster.yml logs blockchain-node-1

# Force rebuild
docker-compose -f docker-compose.cluster.yml build --no-cache
docker-compose -f docker-compose.cluster.yml up -d
```

### Issue: Port Already in Use

```bash
# Find what's using the port (e.g., port 8081)
netstat -ano | findstr :8081  # Windows PowerShell

# Kill the process
taskkill /PID <PID> /F

# Or change the port in docker-compose.cluster.yml
```

### Issue: High Memory Usage

```bash
# Check memory usage
docker stats

# Reduce resource limits by editing docker-compose.cluster.yml
# and adding deploy section:
# deploy:
#   resources:
#     limits:
#       memory: 1G
#     reservations:
#       memory: 512M
```

### Issue: Health Check Failing

```bash
# Wait longer for startup
docker-compose -f docker-compose.cluster.yml up -d
sleep 60

# Check health status
docker ps --format "table {{.Names}}\t{{.Status}}"

# Manual health check
curl http://localhost:8081/health
```

---

## 📈 Performance Monitoring

### Prometheus Queries

```bash
# Access Prometheus at http://localhost:9091

# Useful queries:
# - up{job="blackhole"} - Check service status
# - container_memory_usage_bytes - Memory usage
# - container_cpu_usage_seconds_total - CPU usage
```

### Database Queries

```bash
# Connect to PostgreSQL
psql -h localhost -p 5432 -U admin -d blackhole

# Check tables
\dt

# Check data
SELECT * FROM transactions LIMIT 10;
```

---

## 🔄 Data Persistence

### Volume Management

```bash
# List volumes
docker volume ls | grep blackhole

# Inspect volume
docker volume inspect blackhole-blockchain_blockchain-data-1

# Backup volume data (Windows PowerShell)
docker run --rm -v blackhole-blockchain_blockchain-data-1:/data `
  -v C:\backups:/backup busybox tar czf /backup/blockchain-data-1.tar.gz /data

# Restore volume data
docker run --rm -v blackhole-blockchain_blockchain-data-1:/data `
  -v C:\backups:/backup busybox tar xzf /backup/blockchain-data-1.tar.gz -C /
```

---

## 📝 Environment Variables

### Available Options

```bash
# Logging
LOG_LEVEL=info|debug|warn|error

# Network
PEER_DISCOVERY=true|false
MAX_PEERS=50

# Bridge Configuration
ETHEREUM_RPC=<your-rpc-url>
SOLANA_RPC=<your-rpc-url>
REPLAY_PROTECTION_ENABLED=true|false
CIRCUIT_BREAKER_ENABLED=true|false

# Database
POSTGRES_DB=blackhole
POSTGRES_USER=admin
POSTGRES_PASSWORD=<strong-password>
```

### Set Environment Variables

```bash
# Create .env file
cat > .env << EOF
LOG_LEVEL=info
PEER_DISCOVERY=true
MAX_PEERS=50
POSTGRES_PASSWORD=your_secure_password
ETHEREUM_RPC=wss://your-eth-rpc.com
SOLANA_RPC=https://your-solana-rpc.com
EOF

# Use in docker-compose
docker-compose -f docker-compose.cluster.yml up -d
```

---

## ✅ Post-Deployment Verification

### Checklist

- [ ] All 5 blockchain nodes running and healthy
- [ ] All 5 dashboard nodes running and healthy
- [ ] Bridge service running and connected
- [ ] Prometheus collecting metrics
- [ ] PostgreSQL database accessible
- [ ] Health checks passing for all services
- [ ] RPC endpoints responsive
- [ ] Blockchain nodes synchronized
- [ ] Dashboard nodes independent and healthy
- [ ] Logs being collected properly

### Quick Test Script

```bash
#!/bin/bash

echo "=== Blockchain Nodes ==="
for i in {1..5}; do
  port=$((8080 + i))
  echo "Node $i (8081-8085): $(curl -s http://localhost:$port/health | grep -o 'healthy\|error' || echo 'ERROR')"
done

echo ""
echo "=== Dashboard Nodes ==="
for i in {1..5}; do
  port=$((9000 + i))
  echo "Dashboard $i (9001-9005): $(curl -s http://localhost:$port/health | grep -o 'healthy\|error' || echo 'ERROR')"
done

echo ""
echo "=== Bridge Service ==="
echo "Bridge (8090): $(curl -s http://localhost:8090/health | grep -o 'healthy\|error' || echo 'ERROR')"

echo ""
echo "=== Monitoring ==="
echo "Prometheus (9091): $(curl -s http://localhost:9091/-/healthy | grep -o 'OK\|ERROR' || echo 'ERROR')"
```

---

## 🚀 Ready to Deploy

All components are configured and ready for deployment:

- ✅ 5 Blockchain nodes (core consensus + storage)
- ✅ 5 Dashboard nodes (independent dashboards, separate data)
- ✅ 1 Bridge service (cross-chain operations)
- ✅ Prometheus (metrics collection)
- ✅ PostgreSQL (persistent data storage)
- ✅ Health checks (every 30 seconds)
- ✅ Auto-restart policies (unless-stopped)
- ✅ Data persistence (volumes)

**Run `docker-compose -f docker-compose.cluster.yml up -d` to start!**

---

**Last Updated:** 2025-11-05  
**Next Review:** Weekly health check
**Maintenance Window:** Sundays 02:00-04:00 UTC
