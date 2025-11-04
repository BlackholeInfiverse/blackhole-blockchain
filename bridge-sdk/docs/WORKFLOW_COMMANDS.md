# BlackHole Bridge SDK - Workflow & Commands Reference

## 🚀 **Quick Start Commands**

### **One-Command Deployment**
```bash
# Complete setup and start (Recommended)
make quick-start

# Alternative startup methods
./start-bridge.sh              # Linux/macOS
start-bridge-docker.bat        # Windows
cd example && go run main.go   # Direct Go execution
```

### **Access Points After Deployment**
```bash
# Main dashboard
open http://localhost:8084

# Monitoring dashboard
# open http://localhost:3000  # admin/admin123

# Health check
curl http://localhost:8084/health

# API stats
curl http://localhost:8084/stats
```

## 🛠️ **Development Workflow**

### **Initial Setup**
```bash
# 1. Clone repository
git clone https://github.com/blackhole-network/bridge-sdk.git
cd bridge-sdk

# 2. Setup environment
cp .env.example .env
nano .env  # Configure your settings

# 3. Install dependencies
go mod download

# 4. Start development server
make dev
```

### **Development Commands**
```bash
# Hot reload development
make dev

# Run tests
make test

# Check code quality
make lint

# Build binary
make build

# View logs
make logs

# Check health
make health
```

## 🐳 **Docker Workflow**

### **Docker Development**
```bash
# Start development environment
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# View logs
docker-compose logs -f bridge-node

# Stop services
docker-compose down

# Clean up
docker-compose down -v --remove-orphans
```

### **Docker Production**
```bash
# Production deployment
docker-compose up -d

# Scale services
docker-compose up -d --scale bridge-node=3

# Update services
docker-compose pull && docker-compose up -d

# Backup data
make backup
```

## 📊 **Monitoring Commands**

### **Health Monitoring**
```bash
# Overall system health
curl http://localhost:8084/health

# Component status
curl http://localhost:8084/circuit-breakers

# Error metrics
curl http://localhost:8084/errors

# Bridge statistics
curl http://localhost:8084/stats
```

### **Log Management**
```bash
# View all logs
make logs

# View specific service logs
make logs-bridge
make logs-db
make logs-redis

# Follow logs in real-time
docker-compose logs -f bridge-node

# Search logs for errors
grep ERROR ./logs/bridge.log
```

## 🔧 **Maintenance Commands**

### **Database Operations**
```bash
# Database backup
make db-backup

# Database restore
make db-restore BACKUP_FILE=backups/backup.sql

# Database shell
make db-shell

# Database migration
make db-migrate
```

### **System Maintenance**
```bash
# Create full backup
make backup

# Restore from backup
make restore BACKUP_DIR=backups/20231201_120000

# Clean up old data
make clean

# Update all services
make update

# Security scan
make security-scan
```

## 🔄 **Operational Commands**

### **Service Management**
```bash
# Start services
make start

# Stop services
make stop

# Restart services
make restart

# Check service status
make status

# Force recovery
curl -X POST http://localhost:8084/force-recovery
```

### **Manual Operations**
```bash
# Manual relay trigger
curl -X POST http://localhost:8084/relay \
  -H "Content-Type: application/json" \
  -d '{"transaction_id": "tx_123", "target_chain": "solana"}'

# Cleanup old events
curl -X POST http://localhost:8084/cleanup-events \
  -H "Content-Type: application/json" \
  -d '{"older_than": "7d"}'

# Reset circuit breaker
curl -X POST http://localhost:8084/circuit-breakers/reset \
  -H "Content-Type: application/json" \
  -d '{"component": "ethereum_listener"}'
```

## 🧪 **Testing Commands**

### **Test Execution**
```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests
make test-integration

# Run with coverage
make test-coverage

# Benchmark tests
go test -bench=. ./...
```

### **Test Development**
```bash
# Run tests in watch mode
go test -v ./... -count=1

# Run specific test
go test -run TestBridgeSDK ./...

# Run tests with race detection
go test -race ./...

# Generate test coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 🔍 **Debugging Commands**

### **Debug Information**
```bash
# Enable debug mode
export LOG_LEVEL=debug
export DEBUG_MODE=true

# CPU profiling
go tool pprof http://localhost:8084/debug/pprof/profile

# Memory profiling
go tool pprof http://localhost:8084/debug/pprof/heap

# Goroutine profiling
go tool pprof http://localhost:8084/debug/pprof/goroutine
```

### **Troubleshooting**
```bash
# Check Docker status
docker ps
docker-compose ps

# Check port usage
netstat -tulpn | grep 8084
lsof -i :8084

# Check disk space
df -h
docker system df

# Check memory usage
free -h
ps aux | grep bridge
```

## 📚 **Documentation Commands**

### **Generate Documentation**
```bash
# Generate Go documentation
go doc -all ./...

# Serve documentation locally
godoc -http=:6060

# Generate API documentation
swag init

# Build documentation site
make docs
```

### **Documentation Access**
```bash
# Open main documentation
open README.md

# Open specific guides
open docs/ARCHITECTURE.md
open docs/DEVELOPER.md
open docs/API.md
open docs/TROUBLESHOOTING.md
```

## 🔐 **Security Commands**

### **Security Checks**
```bash
# Security scan
make security-scan

# Check for vulnerabilities
go list -json -m all | nancy sleuth

# Audit dependencies
go mod verify

# Check private key format
echo $ETHEREUM_PRIVATE_KEY | wc -c
```

### **Key Management**
```bash
# Generate new private key (Ethereum)
openssl rand -hex 32

# Validate private key format
echo "your_private_key" | grep -E '^[0-9a-fA-F]{64}$'

# Secure environment setup
chmod 600 .env
```

## 🌐 **Network Commands**

### **Connectivity Tests**
```bash
# Test Ethereum RPC
curl -X POST $ETHEREUM_RPC_URL \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Test Solana RPC
curl -X POST $SOLANA_RPC_URL \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'

# Test WebSocket connections
wscat -c $ETHEREUM_WS_URL
wscat -c $SOLANA_WS_URL
```

### **Network Monitoring**
```bash
# Monitor network connections
netstat -an | grep 8084

# Check DNS resolution
nslookup eth-mainnet.alchemyapi.io
nslookup api.mainnet-beta.solana.com

# Test network latency
ping eth-mainnet.alchemyapi.io
ping api.mainnet-beta.solana.com
```

## 📈 **Performance Commands**

### **Performance Monitoring**
```bash
# Monitor CPU usage
top -p $(pgrep bridge)

# Monitor memory usage
ps aux | grep bridge

# Monitor disk I/O
iotop -p $(pgrep bridge)

# Monitor network I/O
nethogs
```

### **Performance Optimization**
```bash
# Optimize Go runtime
export GOGC=100
export GOMAXPROCS=4

# Database optimization
PRAGMA optimize;

# Clear caches
sync && echo 3 > /proc/sys/vm/drop_caches
```

## 🔄 **CI/CD Commands**

### **Build Pipeline**
```bash
# Build for multiple platforms
make build-all

# Run quality checks
make lint
make test
make security-scan

# Build Docker images
docker build -t blackhole-bridge:latest .

# Push to registry
docker push blackhole-bridge:latest
```

### **Deployment Pipeline**
```bash
# Deploy to staging
make deploy-staging

# Deploy to production
make deploy-production

# Rollback deployment
make rollback

# Health check after deployment
make health-check
```

## 🆘 **Emergency Commands**

### **Emergency Procedures**
```bash
# Emergency stop
make emergency-stop

# Force restart
make force-restart

# Emergency backup
make emergency-backup

# Disaster recovery
make disaster-recovery
```

### **Quick Fixes**
```bash
# Reset to clean state
make clean && make quick-start

# Fix permission issues
sudo chown -R $USER:$USER ./data ./logs

# Fix Docker issues
docker system prune -f
docker-compose down -v
docker-compose up -d
```

## 📋 **Command Cheat Sheet**

### **Most Used Commands**
```bash
make quick-start    # Start everything
make health         # Check status
make logs          # View logs
make stop          # Stop services
make clean         # Clean up
```

### **Development Commands**
```bash
make dev           # Development mode
make test          # Run tests
make lint          # Code quality
make docs          # Documentation
```

### **Production Commands**
```bash
make start         # Production start
make backup        # Create backup
make update        # Update services
make monitor       # Open monitoring
```

---

**💡 Tip**: Use `make help` to see all available commands with descriptions.

**🔗 Quick Links**:
- Dashboard: http://localhost:8084
- Monitoring: http://localhost:3000
- Health: http://localhost:8084/health
- API Docs: [docs/API.md](docs/API.md)
