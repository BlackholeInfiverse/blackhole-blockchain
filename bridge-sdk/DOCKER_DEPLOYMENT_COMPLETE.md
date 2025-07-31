# BlackHole Bridge - Complete Docker Infrastructure

## 🚀 One-Command Deployment

The BlackHole Bridge system includes a comprehensive Docker infrastructure that enables complete system deployment with a single command.

### Quick Start

**Linux/macOS:**
```bash
./deploy-one-liner.sh
```

**Windows:**
```cmd
deploy-one-liner.bat
```

## 📋 Infrastructure Components

### Core Services
- **BlackHole Blockchain Node** - Core blockchain with API on port 3000
- **Bridge Node** - Main bridge service with dashboard on port 8084
- **PostgreSQL** - Persistent data storage on port 5432
- **Redis** - Caching and session management on port 6379

### Monitoring Stack
- **Prometheus** - Metrics collection on port 9091
- **Grafana** - Monitoring dashboard on port 3001 (admin/admin123)
- **Node Exporter** - System metrics on port 9100
- **Redis Exporter** - Redis metrics on port 9121
- **PostgreSQL Exporter** - Database metrics on port 9187

### Production Features
- **Nginx** - Reverse proxy with SSL support (ports 80/443)
- **Fluentd** - Log aggregation on port 24224
- **Health Checks** - Automated health monitoring for all services
- **Resource Limits** - CPU and memory constraints for production
- **Security** - No-new-privileges, read-only containers, secrets management

## 🔧 Configuration Files

### Docker Compose Files
- `docker-compose.yml` - Main configuration for local/staging
- `docker-compose.dev.yml` - Development overrides with hot reload
- `docker-compose.prod.yml` - Production configuration with security

### Environment Configuration
- `.env` - Main environment variables (155 configuration options)
- `.env.dev` - Development-specific settings
- `.env.staging` - Staging environment settings
- `.env.prod` - Production environment settings

### Dockerfiles
- `Dockerfile` - Multi-stage build for bridge service
- `Dockerfile.blockchain` - BlackHole blockchain node
- `Dockerfile.dev` - Development container with debugging

## 🌍 Environment Support

### Local Development
```bash
./deploy-one-liner.sh local
```
- Uses simulation mode
- Debug logging enabled
- All ports exposed
- Hot reload support

### Development with Testnets
```bash
./deploy-one-liner.sh dev
```
- Connects to Ethereum/Solana testnets
- Debug mode enabled
- Profiling and tracing enabled
- Development database

### Staging Environment
```bash
./deploy-one-liner.sh staging
```
- Production-like configuration
- Reduced logging
- Performance monitoring
- Staging database

### Production Deployment
```bash
./deploy-one-liner.sh prod
```
- Full security hardening
- Resource limits enforced
- SSL/TLS enabled
- Secrets management
- Log aggregation
- Comprehensive monitoring

## 📊 Service URLs

After deployment, access these services:

| Service | URL | Credentials |
|---------|-----|-------------|
| Bridge Dashboard | http://localhost:8084 | - |
| Health Check | http://localhost:8084/health | - |
| Infrastructure Dashboard | http://localhost:8084/infra-dashboard | - |
| Grafana | http://localhost:3001 | admin/admin123 |
| Prometheus | http://localhost:9091 | - |
| PostgreSQL | localhost:5432 | bridge/bridge123 |
| Redis | localhost:6379 | - |

## 🔐 Security Features

### Production Security
- **Container Security**: No-new-privileges, read-only containers
- **Network Isolation**: Custom bridge network with subnet control
- **Secrets Management**: External secrets for passwords and keys
- **SSL/TLS**: Nginx with SSL certificate support
- **Resource Limits**: CPU and memory constraints
- **Security Headers**: HSTS, secure cookies, CSRF protection

### Environment Variables Security
- Private keys and secrets in environment files
- Separate configuration for each environment
- Template-based configuration with secure defaults
- Comprehensive validation and error handling

## 📈 Monitoring & Observability

### Metrics Collection
- **Application Metrics**: Bridge performance, transaction rates, error rates
- **System Metrics**: CPU, memory, disk, network usage
- **Database Metrics**: PostgreSQL performance and health
- **Cache Metrics**: Redis performance and hit rates
- **Custom Metrics**: Circuit breaker states, retry queue sizes

### Logging
- **Structured Logging**: JSON format with correlation IDs
- **Log Aggregation**: Fluentd for centralized log collection
- **Log Rotation**: Automatic rotation with size and time limits
- **Debug Logging**: Configurable log levels per environment

### Health Checks
- **Service Health**: Automated health checks for all services
- **Dependency Checks**: Database and cache connectivity
- **Circuit Breaker Status**: Real-time circuit breaker monitoring
- **Performance Alerts**: Automated alerting for performance issues

## 🔄 Management Commands

### Service Management
```bash
# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Restart services
docker-compose restart

# Update deployment
./deploy-one-liner.sh [environment]

# Scale services
docker-compose up -d --scale bridge-node=3
```

### Development Commands
```bash
# Run tests
docker-compose --profile test up test-runner

# Access container shell
docker-compose exec bridge-node sh

# View service status
docker-compose ps

# Monitor resource usage
docker stats
```

## 🚀 Deployment Verification

The deployment script automatically verifies:
1. ✅ Docker and Docker Compose installation
2. ✅ Environment configuration
3. ✅ Service health checks
4. ✅ Network connectivity
5. ✅ Database initialization
6. ✅ Bridge service functionality

## 📦 Volume Management

### Persistent Volumes
- `blockchain-data` - BlackHole blockchain data
- `bridge-data` - Bridge service data and BoltDB
- `postgres-data` - PostgreSQL database
- `redis-data` - Redis cache data
- `prometheus-data` - Metrics storage
- `grafana-data` - Grafana dashboards and settings

### Log Volumes
- `blockchain-logs` - Blockchain service logs
- `bridge-logs` - Bridge service logs
- `nginx-logs` - Nginx access and error logs
- `fluentd-logs` - Log aggregation data

## 🔧 Customization

### Adding Custom Services
1. Add service definition to `docker-compose.yml`
2. Configure environment variables in `.env`
3. Add health checks and monitoring
4. Update deployment scripts

### SSL Certificate Setup
1. Place certificates in `nginx/ssl/`
2. Update `nginx/nginx.conf` with certificate paths
3. Configure domain names in environment variables
4. Restart nginx service

## 🎯 Production Checklist

Before production deployment:
- [ ] Configure real blockchain RPC endpoints
- [ ] Set secure private keys and secrets
- [ ] Configure SSL certificates
- [ ] Set up external secret management
- [ ] Configure monitoring alerts
- [ ] Set up backup procedures
- [ ] Configure firewall rules
- [ ] Test disaster recovery procedures

## 📚 Additional Resources

- [API Documentation](docs/API.md)
- [Architecture Overview](docs/ARCHITECTURE.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Integration Guide](docs/INTEGRATION_SUMMARY.md)

---

**🌟 The BlackHole Bridge Docker infrastructure provides enterprise-grade deployment capabilities with comprehensive monitoring, security, and scalability features.**
