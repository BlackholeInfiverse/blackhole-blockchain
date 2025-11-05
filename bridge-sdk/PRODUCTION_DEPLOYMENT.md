# Bridge SDK Production Deployment Guide

**Version:** 1.0.0  
**Target:** Mainnet Deployment  
**Last Updated:** 2025-11-05

---

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Security Hardening](#security-hardening)
3. [Configuration Setup](#configuration-setup)
4. [Docker Deployment](#docker-deployment)
5. [Monitoring & Observability](#monitoring--observability)
6. [High Availability Setup](#high-availability-setup)
7. [Backup & Recovery](#backup--recovery)
8. [Troubleshooting](#troubleshooting)
9. [Maintenance](#maintenance)

---

## Pre-Deployment Checklist

### ✅ Code Security

- [x] Ed25519 signature verification implemented
- [x] Configuration validation added
- [x] Input sanitization in place
- [x] Security audit passed
- [x] No mock data in production code

### ✅ Infrastructure

- [x] Production Docker images created
- [x] Resource limits configured
- [x] Health checks implemented
- [x] Logging aggregation setup
- [x] Metrics collection enabled

### ✅ Certificates & Keys

- [ ] SSL/TLS certificates obtained
- [ ] Private keys securely generated and stored
- [ ] Secrets manager integrated
- [ ] Key rotation policy documented

### ✅ Monitoring

- [ ] Prometheus configured
- [ ] Alerting rules defined
- [ ] Dashboards created
- [ ] Log aggregation setup

### ✅ Testing

- [ ] Unit tests passing
- [ ] Integration tests completed
- [ ] Load testing performed
- [ ] Security testing completed

---

## Security Hardening

### 1. Environment Variables

Create `.env.prod` file with all required variables:

```bash
# Core Configuration
NODE_ENV=production
LOG_LEVEL=info
DOCKER_MODE=true

# Blockchain RPC Endpoints (MAINNET - CHANGE FROM TESTNET)
ETHEREUM_RPC_URL=https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY
ETHEREUM_PRIVATE_KEY=your_ethereum_private_key
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
SOLANA_PRIVATE_KEY=your_solana_private_key
BLACKHOLE_RPC_URL=wss://mainnet.blackhole.com/ws
BLACKHOLE_PRIVATE_KEY=your_blackhole_private_key

# Database
DATABASE_PATH=/app/data/bridge.db
POSTGRES_DB=bridge_prod
POSTGRES_USER=bridge_user
POSTGRES_PASSWORD=generate_strong_password_here

# Security
JWT_SECRET=generate_using_openssl_rand_-hex_32
API_KEY=generate_using_openssl_rand_-hex_32
CORS_ORIGINS=https://yourdomain.com,https://api.yourdomain.com

# Data Paths
BRIDGE_DATA_PATH=/data/bridge
BRIDGE_LOGS_PATH=/logs/bridge

# Feature Flags (Production Settings)
REPLAY_PROTECTION_ENABLED=true
CIRCUIT_BREAKER_ENABLED=true
ENABLE_COLORED_LOGS=false
MAX_RETRIES=5
RETRY_DELAY_MS=5000

# Monitoring
METRICS_ENABLED=true
METRICS_PORT=9091
LOG_FILE=/app/logs/bridge.log
```

### 2. Secrets Management

**Generate Secure Values:**

```bash
# Generate JWT Secret
openssl rand -hex 32

# Generate API Key
openssl rand -hex 32

# Generate Database Password
openssl rand -base64 32
```

### 3. File Permissions

```bash
# Secure data directories
chmod 700 /data/bridge
chmod 700 /logs/bridge

# Restrict private key files
chmod 600 .env.prod

# Secure docker-compose file
chmod 600 docker-compose.prod.yml
```

### 4. Firewall Rules

```bash
# Allow only specific IPs to access bridge
# Port 8084: Bridge API (restrict to admin/apps)
# Port 9090: Prometheus (restrict to monitoring servers)
# Port 443: HTTPS (public)
# Port 80: HTTP redirect (public)

# Example ufw rules
ufw allow from 203.0.113.0/24 to any port 8084
ufw allow from 198.51.100.0/24 to any port 9090
ufw allow from any to any port 443
ufw allow from any to any port 80
```

---

## Configuration Setup

### 1. Pre-Flight Validation

```bash
cd /path/to/bridge-sdk

# Validate configuration
go run cmd/validator/main.go --config .env.prod --production

# Check RPC connectivity
curl https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY
curl https://api.mainnet-beta.solana.com
```

### 2. Database Initialization

```bash
# Initialize PostgreSQL
docker-compose -f docker-compose.prod.yml run postgres \
  psql -U bridge_user -d bridge_prod < scripts/init-db.sql

# Verify database is ready
docker-compose -f docker-compose.prod.yml exec postgres \
  pg_isready -U bridge_user
```

### 3. Directory Setup

```bash
# Create required directories
mkdir -p /data/bridge/{data,logs}
mkdir -p /app/data
mkdir -p /app/logs

# Set permissions
chown bridge:bridge /data/bridge -R
chmod 700 /data/bridge
```

---

## Docker Deployment

### 1. Build Production Images

```bash
# Build optimized image
docker-compose -f docker-compose.prod.yml build

# Verify images
docker images | grep bridge-sdk
```

### 2. Deploy Containers

```bash
# Start all services
docker-compose -f docker-compose.prod.yml up -d

# Verify services are running
docker-compose -f docker-compose.prod.yml ps

# Check logs
docker-compose -f docker-compose.prod.yml logs -f bridge-sdk-1
```

### 3. Health Checks

```bash
# Check bridge health
curl -H "Authorization: Bearer ${API_KEY}" http://localhost:8084/health

# Check Prometheus
curl http://localhost:9090/-/healthy

# Check PostgreSQL
docker-compose -f docker-compose.prod.yml exec postgres pg_isready
```

---

## Monitoring & Observability

### 1. Prometheus Configuration

**File:** `monitoring/prometheus.yml`

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'bridge-sdk'
    static_configs:
      - targets: ['localhost:9091', 'localhost:9092', 'localhost:9093']
    scheme: http
    
  - job_name: 'postgres'
    static_configs:
      - targets: ['localhost:5432']
```

### 2. Key Metrics to Monitor

```
# Transaction throughput
bridge_transactions_total
bridge_transactions_completed
bridge_transactions_failed

# Response times
bridge_request_duration_seconds
bridge_relay_latency_seconds

# Errors
bridge_errors_total
bridge_signature_verification_failures

# Security
bridge_replay_attacks_detected
bridge_invalid_signatures_total

# System
bridge_uptime_seconds
bridge_memory_usage_bytes
bridge_database_connections
```

### 3. Alerting Rules

**File:** `monitoring/alert_rules.yml`

```yaml
groups:
  - name: bridge_alerts
    rules:
      - alert: HighErrorRate
        expr: rate(bridge_errors_total[5m]) > 0.05
        for: 5m
        annotations:
          summary: "High error rate in bridge"
          
      - alert: ReplayAttackDetected
        expr: increase(bridge_replay_attacks_detected[5m]) > 10
        for: 1m
        annotations:
          summary: "Multiple replay attacks detected"
          
      - alert: ServiceDown
        expr: up{job="bridge-sdk"} == 0
        for: 2m
        annotations:
          summary: "Bridge service is down"
```

### 4. Logging Setup

**Structured Logging Configuration:**

```json
{
  "log_level": "info",
  "format": "json",
  "outputs": [
    {
      "type": "file",
      "path": "/app/logs/bridge.log",
      "max_size": "50MB",
      "max_backups": 5,
      "max_age": 30
    },
    {
      "type": "syslog",
      "network": "tcp",
      "address": "localhost:514"
    }
  ]
}
```

---

## High Availability Setup

### 1. Load Balancing

**Nginx Configuration:** `nginx/nginx.prod.conf`

```nginx
upstream bridge_backend {
    least_conn;
    server bridge-sdk-1:8084 weight=3;
    server bridge-sdk-2:8084 weight=2;
    server bridge-sdk-3:8084 weight=1;
}

server {
    listen 443 ssl;
    server_name api.yourdomain.com;
    
    ssl_certificate /etc/nginx/certs/certificate.crt;
    ssl_certificate_key /etc/nginx/certs/private.key;
    
    location / {
        proxy_pass http://bridge_backend;
        proxy_set_header Authorization $http_authorization;
        proxy_read_timeout 30s;
        proxy_connect_timeout 10s;
    }
}
```

### 2. Database Replication

```bash
# Setup PostgreSQL replication
docker-compose -f docker-compose.prod.yml exec postgres \
  psql -U bridge_user -c "CREATE USER replication_user WITH REPLICATION ENCRYPTED PASSWORD 'secure_password';"

# Configure standby servers
# Edit postgresql.conf on standby:
# primary_conninfo = 'host=primary_db port=5432 user=replication_user password=secure_password'
```

### 3. Failover Strategy

```bash
# Keep replica nodes ready
# Test failover monthly
# Document recovery procedures
# Set up automatic promotion scripts
```

---

## Backup & Recovery

### 1. Daily Backups

```bash
#!/bin/bash
# backup-bridge.sh

BACKUP_DIR="/backups/bridge"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_BACKUP="$BACKUP_DIR/db_backup_$TIMESTAMP.sql"
DATA_BACKUP="$BACKUP_DIR/data_backup_$TIMESTAMP.tar.gz"

# Backup database
docker-compose -f docker-compose.prod.yml exec -T postgres \
  pg_dump -U bridge_user bridge_prod > "$DB_BACKUP"

# Backup application data
tar -czf "$DATA_BACKUP" /data/bridge /app/data

# Upload to S3
aws s3 cp "$DB_BACKUP" s3://your-bucket/backups/
aws s3 cp "$DATA_BACKUP" s3://your-bucket/backups/

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -mtime +30 -delete
```

### 2. Recovery Procedures

```bash
# Restore database
docker-compose -f docker-compose.prod.yml exec -T postgres \
  psql -U bridge_user bridge_prod < /backups/bridge/db_backup.sql

# Restore application data
tar -xzf /backups/bridge/data_backup.tar.gz -C /

# Verify integrity
docker-compose -f docker-compose.prod.yml exec postgres \
  psql -U bridge_user -d bridge_prod -c "SELECT COUNT(*) FROM transactions;"
```

---

## Troubleshooting

### Issue: Signature Verification Failures

```bash
# Check logs
docker-compose -f docker-compose.prod.yml logs bridge-sdk-1 | grep "signature"

# Verify public keys are registered
curl -H "Authorization: Bearer ${API_KEY}" \
  http://localhost:8084/keys/status

# Check key format (should be hex Ed25519)
echo "Key should be 64 hex characters: $(echo -n 'key' | wc -c)"
```

### Issue: High Latency

```bash
# Check RPC endpoint performance
curl -w "Time: %{time_total}s\n" \
  https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY

# Monitor database connections
docker-compose -f docker-compose.prod.yml exec postgres \
  psql -U bridge_user -c "SELECT count(*) FROM pg_stat_activity;"

# Check replay protection cache size
curl -H "Authorization: Bearer ${API_KEY}" \
  http://localhost:8084/replay/status
```

### Issue: Memory Leaks

```bash
# Monitor memory usage
docker stats bridge-sdk-1 bridge-sdk-2 bridge-sdk-3

# Collect memory profile
curl http://localhost:9091/debug/pprof/heap > heap.prof
go tool pprof heap.prof

# Restart service if needed
docker-compose -f docker-compose.prod.yml restart bridge-sdk-1
```

---

## Maintenance

### Daily Tasks

- [ ] Check service health: `curl /health`
- [ ] Review error logs for anomalies
- [ ] Verify backup completion
- [ ] Monitor disk usage

### Weekly Tasks

- [ ] Review metrics and performance trends
- [ ] Check database replication lag
- [ ] Verify failover readiness
- [ ] Update security patches

### Monthly Tasks

- [ ] Full backup verification (test restore)
- [ ] Security audit of logs
- [ ] Performance baseline comparison
- [ ] Capacity planning review
- [ ] Disaster recovery drill

### Quarterly Tasks

- [ ] Security penetration testing
- [ ] Load testing (stress test infrastructure)
- [ ] Documentation update
- [ ] Team training

---

## Post-Deployment Checklist

- [ ] All services running and healthy
- [ ] Signature verification working
- [ ] Transactions being processed
- [ ] Monitoring dashboard operational
- [ ] Backups configured and tested
- [ ] Alerting rules active
- [ ] Load balancer distributing traffic
- [ ] CORS headers properly configured
- [ ] Rate limiting active
- [ ] Replay protection blocking duplicates
- [ ] Circuit breakers functioning
- [ ] All logs being collected
- [ ] Performance within SLA
- [ ] Team trained on procedures
- [ ] Documentation complete

---

## Support & Escalation

**Critical Issues (Severity P1):**
- Service down
- Data loss
- Security breach
- Contact: ops-team@yourdomain.com

**High Priority (Severity P2):**
- Degraded performance
- High error rates
- Multiple transaction failures
- Response time: 2 hours

**Medium Priority (Severity P3):**
- Non-critical feature issues
- Performance optimization needed
- Response time: 1 business day

**Low Priority (Severity P4):**
- Documentation updates
- Enhancement requests
- Response time: Best effort

---

## Version History

| Version | Date       | Changes |
|---------|------------|---------|
| 1.0.0   | 2025-11-05 | Initial production deployment guide |

---

**Last Updated:** 2025-11-05  
**Maintained By:** DevOps Team  
**Review Date:** 2025-12-05
