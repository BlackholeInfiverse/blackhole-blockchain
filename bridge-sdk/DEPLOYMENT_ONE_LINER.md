# 🚀 BlackHole Bridge - Ultimate One-Liner Deployment

**Deploy the entire BlackHole Bridge infrastructure with a single command!**

## 🎯 Quick Start (30 seconds to running bridge)

### Option 1: Make Command (Recommended)
```bash
# Clone and deploy in one go
git clone https://github.com/blackhole-network/bridge-sdk.git && cd bridge-sdk && make quick-start
```

### Option 2: Direct Script Execution
```bash
# Linux/macOS
git clone https://github.com/blackhole-network/bridge-sdk.git && cd bridge-sdk && chmod +x deploy-one-liner.sh && ./deploy-one-liner.sh

# Windows
git clone https://github.com/blackhole-network/bridge-sdk.git && cd bridge-sdk && deploy-one-liner.bat
```

### Option 3: Docker Compose Only
```bash
git clone https://github.com/blackhole-network/bridge-sdk.git && cd bridge-sdk && cp .env.example .env && docker-compose up -d
```

## 🌟 What Gets Deployed

The one-liner deployment automatically sets up:

### 🏗️ **Core Infrastructure**
- **BlackHole Bridge Node** - Main bridge application
- **PostgreSQL Database** - Persistent data storage
- **Redis Cache** - Session management and caching
- **Nginx Reverse Proxy** - Load balancing and SSL termination

### 📊 **Monitoring Stack**
- **Prometheus** - Metrics collection
- **Grafana** - Visualization dashboards
- **Health Checks** - Automated service monitoring
- **Log Aggregation** - Centralized logging

### 🔒 **Security Features**
- **Replay Attack Protection** - SHA-256 hash validation
- **Circuit Breakers** - Fault tolerance
- **Rate Limiting** - DDoS protection
- **SSL/TLS Support** - Encrypted communications

### 🌐 **Access Points**
After deployment, access these services:
- **📊 Main Dashboard**: http://localhost:8084
- **🏥 Health Check**: http://localhost:8084/health
- **📈 Grafana**: http://localhost:3000 (admin/admin123)
- **📊 Prometheus**: http://localhost:9091
- **🗄️ Redis**: localhost:6379
- **🐘 PostgreSQL**: localhost:5432

## 🎛️ Environment-Specific Deployments

### 🏠 Local Development
```bash
make deploy-local
# or
./deploy-one-liner.sh local
```
- Uses local configuration
- Debug mode enabled
- Hot reload for development

### 🧪 Development (Testnets)
```bash
make deploy-dev
# or
./deploy-one-liner.sh dev
```
- Connects to Ethereum Goerli and Solana Devnet
- Debug logging enabled
- Test token contracts

### 🎭 Staging Environment
```bash
make deploy-staging
# or
./deploy-one-liner.sh staging
```
- Production-like configuration
- Performance monitoring
- Load testing ready

### 🏭 Production Deployment
```bash
make deploy-prod
# or
./deploy-one-liner.sh prod
```
- Mainnet configuration
- Enhanced security
- Full monitoring stack

## ⚙️ Configuration

### Automatic Configuration
The deployment script automatically:
1. **Creates .env file** from template if missing
2. **Sets up directories** for data, logs, and monitoring
3. **Configures Docker networks** and volumes
4. **Initializes databases** with required schemas
5. **Starts health checks** for all services

### Manual Configuration (Optional)
Edit the `.env` file for custom settings:

```bash
# Essential Configuration
ETHEREUM_RPC_URL=https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
ETHEREUM_PRIVATE_KEY=your_private_key_here
SOLANA_PRIVATE_KEY=your_private_key_here

# Contract Addresses
ETHEREUM_BRIDGE_CONTRACT=0x742d35Cc6634C0532925a3b8D4C9db96590c6C87
SOLANA_BRIDGE_PROGRAM=9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM

# Security
JWT_SECRET=your_secure_jwt_secret_32_chars_min
API_KEY=your_secure_api_key
```

## 🔧 Management Commands

### Service Management
```bash
# View all services status
docker-compose ps

# View logs
docker-compose logs -f bridge-node

# Restart specific service
docker-compose restart bridge-node

# Stop all services
docker-compose down

# Update and restart
make deploy-local
```

### Health Monitoring
```bash
# Check bridge health
curl http://localhost:8084/health

# Check all service health
make health

# View metrics
curl http://localhost:9091/metrics
```

### Backup and Recovery
```bash
# Create backup
make backup

# View backups
ls -la backups/

# Restore from backup
tar -xzf backups/bridge-backup-YYYYMMDD-HHMMSS.tar.gz
```

## 🚨 Troubleshooting

### Common Issues

**Port Already in Use**
```bash
# Check what's using port 8084
lsof -i :8084
# Kill the process or change port in .env
```

**Docker Permission Issues**
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
# Restart terminal
```

**Service Not Starting**
```bash
# Check logs
docker-compose logs bridge-node
# Check health
curl http://localhost:8084/health
```

**Database Connection Issues**
```bash
# Reset database
docker-compose down
docker volume rm bridge-sdk_postgres-data
docker-compose up -d
```

### Getting Help
```bash
# View available commands
make help

# Check service status
make status

# View detailed logs
make logs
```

## 🎉 Success Verification

After deployment, verify everything is working:

1. **✅ Dashboard Access**: Visit http://localhost:8084
2. **✅ Health Check**: `curl http://localhost:8084/health`
3. **✅ Monitoring**: Visit http://localhost:3000
4. **✅ Test Transfer**: Use the Quick Transfer widget
5. **✅ View Logs**: Check real-time transaction processing

## 🔄 Updates and Maintenance

### Update to Latest Version
```bash
# Pull latest changes and redeploy
git pull origin main && make deploy-local
```

### Scheduled Maintenance
```bash
# Graceful shutdown
docker-compose down

# Update system
git pull && docker-compose pull

# Restart with latest
docker-compose up -d
```

---

**🎯 That's it! Your BlackHole Bridge is now running with full monitoring, security, and cross-chain capabilities!**

For detailed documentation, see:
- [Architecture Guide](docs/ARCHITECTURE.md)
- [API Documentation](docs/API.md)
- [Developer Guide](docs/DEVELOPER.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
