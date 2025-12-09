# Blackhole Blockchain Mainnet Deployment Guide

This directory contains the complete deployment configuration for the Blackhole Blockchain mainnet using Docker Compose. It includes a multi-node setup with reverse proxy, SSL certificates, and monitoring capabilities.

## Overview

The deployment consists of:
- **3 Blockchain Nodes**: For redundancy and load distribution
- **Bridge Service**: Cross-chain interoperability
- **Wallet Service**: User wallet management
- **Nginx Reverse Proxy**: SSL termination and routing
- **Certbot**: Automatic SSL certificate management

## Prerequisites

- Docker and Docker Compose installed
- Domain name (`blackhole-mainnet.com`) pointing to your server
- Minimum system requirements: 8GB RAM, 4 CPU cores
- Available ports: 80, 443, 8080-8082, 8545-8547, 30303-30305
- `jq` installed for verification scripts

## DNS Requirements

Configure your DNS to point `blackhole-mainnet.com` to your server's public IP address:

```
blackhole-mainnet.com A <your-server-ip>
```

**Important**: The domain must be publicly resolvable for Let's Encrypt certificate issuance. DNS propagation may take up to 24 hours.

## Step-by-Step Deployment

### 1. Prepare the Environment

```bash
# Navigate to deployment directory
cd deploy/mainnet

# Copy and configure environment file
cp .env.mainnet .env
# Edit .env with your specific configuration values
```

### 2. Initial Deployment

```bash
# Start all services
docker-compose up -d

# Monitor startup logs
docker-compose logs -f
```

### 3. Verify Services

```bash
# Check service health
docker-compose ps

# Verify web endpoints
curl -k https://blackhole-mainnet.com/admin/health
curl -k https://blackhole-mainnet.com/bridge/health
```

### 4. SSL Certificate Setup

Certificates are automatically requested on first startup. If needed manually:

```bash
# Request initial certificates
docker-compose run --rm certbot

# Test certificate renewal
docker-compose run --rm certbot renew --dry-run
```

## Zero-Downtime Updates

The multi-node architecture enables rolling updates without service interruption:

### Node Updates

```bash
# Update nodes one by one to maintain quorum
docker-compose up -d blackhole-node-2
# Wait for node to sync and join network
sleep 300

docker-compose up -d blackhole-node-3
sleep 300

docker-compose up -d blackhole-node-1
```

### Service Updates

```bash
# Update bridge and wallet services
docker-compose up -d bridge wallet

# Update proxy configuration if needed
docker-compose up -d nginx
```

## SSL Certificate Management (Certbot)

### Automatic Renewal

Certbot runs as a container and handles certificate renewal automatically. The nginx configuration includes ACME challenge support.

### Manual Certificate Operations

```bash
# Renew certificates
docker-compose run --rm certbot renew

# Force certificate renewal
docker-compose run --rm certbot certonly --force-renewal -d blackhole-mainnet.com
```

### Certificate Storage

Certificates are stored in Docker volumes:
- `/etc/letsencrypt/live/blackhole-mainnet.com/`
- Automatically mounted to nginx container

## Proxy Configuration Explanation

Nginx acts as the reverse proxy with the following routing:

### URL Routing

- `https://blackhole-mainnet.com/admin/*` → `blackhole-node-1:8080`
- `https://blackhole-mainnet.com/bridge/*` → `bridge:8084`
- `https://blackhole-mainnet.com/wallet/*` → `wallet:9000`
- `http://*` → `https://*` (automatic redirect)

### Features

- **SSL Termination**: All traffic is encrypted end-to-end
- **Load Balancing**: Ready for multiple backend instances
- **Security Headers**: XSS protection, content type sniffing prevention
- **Gzip Compression**: Optimized content delivery
- **Health Checks**: Automatic backend health monitoring

### Configuration File

The nginx configuration is in `nginx.conf` and supports:
- WebSocket upgrades for real-time communication
- Proper header forwarding (X-Real-IP, X-Forwarded-Proto)
- Buffering disabled for streaming responses

## Verification Steps

### Automated Testing

```bash
# P2P network connectivity test
../../scripts/p2p_smoke.sh --duration 120

# DEX swap functionality test
../../scripts/swap_test.sh --duration 60

# Additional DEX tests
../../scripts/dex_slippage_test.sh
../../scripts/stress.sh
```

### Manual Verification

1. **Blockchain Sync**:
   ```bash
   curl https://blackhole-mainnet.com/admin/health
   # Should return {"status":"healthy","block_height":<number>}
   ```

2. **Bridge Connectivity**:
   ```bash
   curl https://blackhole-mainnet.com/bridge/health
   # Should return bridge service status
   ```

3. **SSL Certificate**:
   ```bash
   openssl s_client -connect blackhole-mainnet.com:443 -servername blackhole-mainnet.com < /dev/null
   # Should show valid certificate chain
   ```

4. **DNS Resolution**:
   ```bash
   nslookup blackhole-mainnet.com
   # Should return your server IP
   ```

## Local Testing with Override

For development and testing without public DNS:

### Using Override Configuration

```bash
# Start with local override (self-signed certificates)
docker-compose -f docker-compose.yml -f docker-compose.override.yml up -d

# Access services locally
# Admin Dashboard: https://localhost/admin/
# Bridge API: https://localhost/bridge/
# Wallet Service: https://localhost/wallet/
```

### Override Features

- **Self-signed certificates** for local development
- **Local-only networking** (no external exposure)
- **Debug logging** enabled
- **Reduced resource requirements**

### Browser Warnings

Since self-signed certificates are used, browsers will show security warnings. This is expected for local testing.

## Rollback Procedures

### Data Rollback

If blockchain data corruption occurs:

```bash
# List available snapshots
../../scripts/rollback.sh list

# Create new snapshot before rollback
../../scripts/rollback.sh snapshot

# Restore from specific snapshot
../../scripts/rollback.sh restore 20231201_120000_data_snapshot.tar.gz
```

### Service Rollback

For application-level issues:

```bash
# Stop all services
docker-compose down

# Pull previous image versions (if using tags)
docker pull blackhole/blockchain:v1.0.0

# Restart with previous configuration
docker-compose up -d
```

### Emergency Procedures

1. **Immediate shutdown**:
   ```bash
   docker-compose down --remove-orphans
   ```

2. **Data backup**:
   ```bash
   ../../scripts/rollback.sh snapshot
   ```

3. **Clean restart**:
   ```bash
   docker system prune -f
   docker-compose up -d
   ```

## Troubleshooting

### Common Issues

1. **Certificate Issues**:
   ```bash
   # Check certificate status
   docker-compose logs certbot

   # Reissue certificates
   docker-compose run --rm certbot certonly --force-renewal
   ```

2. **Node Sync Problems**:
   ```bash
   # Check node logs
   docker-compose logs blackhole-node-1

   # Verify peer connections
   ../../scripts/p2p_smoke.sh
   ```

3. **Proxy Errors**:
   ```bash
   # Check nginx configuration
   docker-compose exec nginx nginx -t

   # View nginx logs
   docker-compose logs nginx
   ```

### Performance Monitoring

```bash
# Service resource usage
docker stats

# Application metrics
curl https://blackhole-mainnet.com/admin/metrics

# System monitoring
htop
```

### Log Analysis

```bash
# All service logs
docker-compose logs

# Specific service logs
docker-compose logs blackhole-node-1

# Follow logs in real-time
docker-compose logs -f nginx
```

## Security Considerations

- **Firewall**: Restrict ports to necessary services only
- **Updates**: Regularly update Docker images and host system
- **Monitoring**: Implement alerting for critical metrics
- **Backups**: Regular automated backups of blockchain data
- **Access Control**: Use strong passwords and API keys

## Support

For deployment issues:
1. Check this documentation
2. Review service logs
3. Run verification scripts
4. Check GitHub issues for known problems

## Configuration Files Reference

- `docker-compose.yml`: Main service definitions
- `docker-compose.override.yml`: Local development overrides
- `nginx.conf`: Reverse proxy configuration
- `.env.mainnet`: Environment variables template
- `Dockerfile.blockchain`: Node container build instructions