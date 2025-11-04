# BlackHole Bridge - Deployment Guide

🚀 **One-Command Deployment Ready** - Complete Docker-based deployment solution for the BlackHole Cross-Chain Bridge.

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Deployment Options](#deployment-options)
- [Monitoring](#monitoring)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)

## 🚀 Quick Start

### One-Command Deployment

**Linux/macOS:**
```bash
# Make script executable and start
chmod +x start-bridge.sh
./start-bridge.sh
```

**Windows:**
```cmd
# Run the Docker deployment script
start-bridge-docker.bat
```

**Using Make (Recommended):**
```bash
# Complete setup and start in one command
make quick-start
```

That's it! Your bridge will be running at:
- 📊 **Dashboard**: http://localhost:8084
- 📈 **Monitoring**: http://localhost:3000 (admin/admin123)

## 📦 Prerequisites

### Required Software

1. **Docker & Docker Compose**
   ```bash
   # Install Docker (Linux)
   curl -fsSL https://get.docker.com -o get-docker.sh
   sh get-docker.sh
   
   # Install Docker Compose
   sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   sudo chmod +x /usr/local/bin/docker-compose
   ```

2. **System Requirements**
   - **RAM**: Minimum 4GB, Recommended 8GB+
   - **Storage**: Minimum 20GB free space
   - **CPU**: 2+ cores recommended
   - **Network**: Stable internet connection for blockchain RPC access

### Optional Tools

- **Make**: For using Makefile commands
- **curl**: For health checks and API testing
- **jq**: For JSON parsing in scripts

## ⚙️ Configuration

### 1. Environment Setup

The deployment automatically creates a `.env` file with default values. Edit it with your configuration:

```bash
# Copy example configuration
cp .env.example .env

# Edit with your settings
nano .env
```

### 2. Essential Configuration

**Blockchain RPC URLs:**
```env
ETHEREUM_RPC_URL=https://eth-mainnet.alchemyapi.io/v2/YOUR_ALCHEMY_KEY
ETHEREUM_WS_URL=wss://eth-mainnet.alchemyapi.io/v2/YOUR_ALCHEMY_KEY
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
SOLANA_WS_URL=wss://api.mainnet-beta.solana.com
BLACKHOLE_RPC_URL=http://blackhole-node:8545
```

**Private Keys (Secure these properly!):**
```env
ETHEREUM_PRIVATE_KEY=your_ethereum_private_key_here
SOLANA_PRIVATE_KEY=your_solana_private_key_here
BLACKHOLE_PRIVATE_KEY=your_blackhole_private_key_here
```

**Contract Addresses:**
```env
ETHEREUM_BRIDGE_CONTRACT=0x742d35Cc6634C0532925a3b8D4C9db96590c6C87
SOLANA_BRIDGE_PROGRAM=9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM
BLACKHOLE_BRIDGE_CONTRACT=bh1234567890123456789012345678901234567890
```

### 3. Security Configuration

**For Production:**
```env
APP_ENV=production
DEBUG_MODE=false
LOG_LEVEL=info
JWT_SECRET=your_secure_jwt_secret_here
API_KEY=your_secure_api_key_here
```

**For Development:**
```env
APP_ENV=development
DEBUG_MODE=true
LOG_LEVEL=debug
USE_TESTNET=true
```

## 🐳 Deployment Options

### Production Deployment

```bash
# Using Make (Recommended)
make start

# Using Docker Compose directly
docker-compose up -d

# Using startup script
./start-bridge.sh start
```

### Development Deployment

```bash
# Development mode with hot reload
make dev

# Or using Docker Compose
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Or using startup script
./start-bridge.sh dev
```

### Custom Deployment

```bash
# Build only
make build

# Start specific services
docker-compose up -d bridge-node postgres redis

# Scale services
docker-compose up -d --scale bridge-node=3
```

## 📊 Monitoring

### Built-in Monitoring Stack

The deployment includes a complete monitoring solution:

1. **Prometheus** - Metrics collection (Port 9091)
2. **Grafana** - Visualization dashboard (Port 3000)
3. **Redis** - Caching and session management
4. **PostgreSQL** - Persistent data storage

### Access Monitoring

```bash
# Open monitoring dashboard
make monitor

# Or visit directly
open http://localhost:3000
# Login: admin / admin123
```

### Health Checks

```bash
# Check all services
make health

# Check specific service
curl http://localhost:8084/health
```

## 🔧 Maintenance

### Logs Management

```bash
# View all logs
make logs

# View specific service logs
make logs-bridge
make logs-db
make logs-redis

# Follow logs in real-time
docker-compose logs -f bridge-node
```

### Database Operations

```bash
# Database backup
make db-backup

# Database restore
make db-restore BACKUP_FILE=backups/backup.sql

# Database shell access
make db-shell
```

### Updates

```bash
# Update all services
make update

# Rebuild and restart
make restart
```

### Backup & Restore

```bash
# Create full backup
make backup

# Restore from backup
make restore BACKUP_DIR=backups/20231201_120000
```

## 🛠️ Available Commands

### Make Commands

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
make test           # Run tests
make backup         # Create backup
make update         # Update services
```

### Script Commands

```bash
# Linux/macOS
./start-bridge.sh [start|stop|restart|status|logs|health|setup|clean]

# Windows
start-bridge-docker.bat [start|stop|restart|status|logs|health|setup|clean]
```

## 🔍 Troubleshooting

### Common Issues

**1. Port Already in Use**
```bash
# Check what's using the port
lsof -i :8084
netstat -tulpn | grep 8084

# Stop conflicting services or change port in .env
```

**2. Docker Permission Issues**
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker
```

**3. Services Not Starting**
```bash
# Check Docker daemon
sudo systemctl status docker

# Check logs for errors
docker-compose logs bridge-node
```

**4. Database Connection Issues**
```bash
# Reset database
docker-compose down -v
docker-compose up -d postgres
# Wait for initialization, then start other services
```

### Performance Optimization

**1. Resource Allocation**
```yaml
# In docker-compose.yml, add resource limits
services:
  bridge-node:
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
```

**2. Database Tuning**
```env
# In .env file
DB_MAX_CONNECTIONS=20
DB_CONNECTION_TIMEOUT=60s
```

### Security Hardening

**1. Network Security**
```bash
# Use custom network
docker network create --driver bridge bridge-secure
```

**2. Secret Management**
```bash
# Use Docker secrets for production
echo "your_private_key" | docker secret create eth_private_key -
```

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/)
- [Prometheus Configuration](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)

## 🆘 Support

If you encounter issues:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review logs: `make logs`
3. Check service health: `make health`
4. Create an issue with logs and configuration details

---

**🎉 Congratulations!** Your BlackHole Bridge is now deployed and ready for cross-chain operations!
