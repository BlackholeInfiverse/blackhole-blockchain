# BlackHole Blockchain Production Deployment Guide

This guide covers the complete deployment process for BlackHole Blockchain in production environments.

## 📋 Prerequisites

### System Requirements
- **CPU**: 4+ cores (8+ cores recommended for mainnet)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**: 500GB SSD minimum (1TB+ for mainnet)
- **Network**: 100+ Mbps connection with static IP
- **OS**: Ubuntu 22.04 LTS (recommended) or similar Linux distribution

### Software Requirements
- Docker 24.0+ and Docker Compose v2
- Git
- curl and other basic utilities
- Root/sudo access

## 🚀 Quick Deployment (Testnet)

### Automated Deployment
```bash
# Clone repository
git clone https://github.com/Shivam-Patel-G/blackhole-blockchain.git
cd blackhole-blockchain

# Run automated deployment script
sudo chmod +x deploy/testnet-deploy.sh
sudo ./deploy/testnet-deploy.sh
```

### Manual Deployment

#### 1. Prepare Environment
```bash
# Create deployment user
sudo useradd -r -s /bin/bash -d /opt/blackhole-blockchain -m blackhole
sudo usermod -aG docker blackhole

# Create directories
sudo mkdir -p /opt/blackhole-blockchain/{data,logs,config,backups}
sudo chown -R blackhole:blackhole /opt/blackhole-blockchain
```

#### 2. Configure Environment
```bash
# Copy and customize environment file
cp docker/.env.template /opt/blackhole-blockchain/.env

# Edit configuration
sudo nano /opt/blackhole-blockchain/.env
```

#### 3. Deploy with Docker Compose
```bash
# Build and start services
docker-compose --env-file /opt/blackhole-blockchain/.env up -d

# Check status
docker-compose ps
```

## ⚙️ Configuration

### Environment Variables

#### Network Configuration
```env
NETWORK=testnet                    # testnet | mainnet
NODE_ENV=production               # development | production
EXTERNAL_IP=your.server.ip        # Your server's public IP
```

#### Port Configuration
```env
BLOCKCHAIN_PORT=8080              # Main blockchain API
BRIDGE_PORT=8084                  # Bridge API
RPC_PORT=8545                     # JSON-RPC endpoint
P2P_PORT=30303                    # P2P networking
```

#### Security Settings
```env
API_RATE_LIMIT=100               # Requests per minute
CORS_ORIGINS=*                   # Allow all origins (restrict in production)
TLS_ENABLED=true                 # Enable HTTPS
TLS_CERT_PATH=/path/to/cert.pem  # SSL certificate
TLS_KEY_PATH=/path/to/key.pem    # SSL private key
```

### Firewall Configuration

#### UFW (Ubuntu Firewall)
```bash
# Reset and set defaults
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow necessary ports
sudo ufw allow ssh
sudo ufw allow 8080/tcp  comment "BlackHole API"
sudo ufw allow 8084/tcp  comment "Bridge API"
sudo ufw allow 8545/tcp  comment "RPC"
sudo ufw allow 30303     comment "P2P"

# Enable firewall
sudo ufw --force enable
```

## 🔍 Monitoring & Health Checks

### Built-in Health Endpoints
```bash
# Blockchain health
curl http://localhost:8080/health

# Bridge health  
curl http://localhost:8084/health

# System status
curl http://localhost:8080/api/status
```

### Docker Container Monitoring
```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs -f blockchain
docker-compose logs -f bridge

# Resource usage
docker stats
```

### Log Files
- **Blockchain logs**: `/opt/blackhole-blockchain/logs/blockchain.log`
- **Bridge logs**: `/opt/blackhole-blockchain/logs/bridge.log` 
- **Monitor logs**: `/opt/blackhole-blockchain/logs/monitor.log`

## 🔧 Maintenance Operations

### Backup Procedures
```bash
# Create backup
BACKUP_NAME="backup-$(date +%Y%m%d-%H%M%S)"
sudo -u blackhole cp -r /opt/blackhole-blockchain/data /opt/blackhole-backups/$BACKUP_NAME

# Restore from backup
sudo -u blackhole rm -rf /opt/blackhole-blockchain/data
sudo -u blackhole cp -r /opt/blackhole-backups/$BACKUP_NAME /opt/blackhole-blockchain/data
docker-compose restart
```

### Updates and Upgrades
```bash
# Pull latest changes
cd /opt/blackhole-blockchain/src
sudo -u blackhole git pull origin testnet

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Log Rotation
```bash
# Manual log rotation
sudo logrotate -f /etc/logrotate.d/blackhole-blockchain

# Setup automatic rotation
sudo tee /etc/logrotate.d/blackhole-blockchain << EOF
/opt/blackhole-blockchain/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        docker-compose -f /opt/blackhole-blockchain/src/docker-compose.yml restart
    endscript
}
EOF
```

## 🌐 Network Configuration

### Testnet Configuration
```env
NETWORK=testnet
BOOTSTRAP_PEERS="testnet-peer1.blackhole.network:30303,testnet-peer2.blackhole.network:30303"
MIN_VALIDATOR_STAKE=10000000000000000000000    # 10,000 BHX
```

### Mainnet Configuration
```env
NETWORK=mainnet  
BOOTSTRAP_PEERS="mainnet-peer1.blackhole.network:30303,mainnet-peer2.blackhole.network:30303"
MIN_VALIDATOR_STAKE=100000000000000000000000   # 100,000 BHX
```

### Validator Setup
```bash
# Generate validator keys
blackhole-node keygen --output validator-key.json

# Set validator key in environment
echo "VALIDATOR_KEY=$(cat validator-key.json)" >> .env

# Stake tokens to become validator
blackhole-cli validator stake --amount 100000 --key validator-key.json
```

## 🔐 Security Best Practices

### System Security
- Keep OS and packages updated
- Use fail2ban for SSH protection
- Configure proper firewall rules
- Regular security audits

### Application Security
- Enable TLS/SSL certificates
- Use strong validator keys
- Restrict API access with rate limiting
- Monitor for unusual activity

### Network Security
- Use VPN for admin access
- Configure DDoS protection
- Monitor network traffic
- Implement intrusion detection

## 📊 Performance Optimization

### Hardware Recommendations
```
Testnet:
- CPU: 4 cores
- RAM: 8GB
- Storage: 500GB SSD
- Network: 100 Mbps

Mainnet:
- CPU: 8+ cores
- RAM: 32GB+
- Storage: 2TB+ NVMe SSD
- Network: 1 Gbps
```

### Docker Optimization
```yaml
# docker-compose.override.yml
services:
  blockchain:
    deploy:
      resources:
        limits:
          memory: 8G
          cpus: '4'
        reservations:
          memory: 4G
          cpus: '2'
```

## 🚨 Troubleshooting

### Common Issues

#### Container Won't Start
```bash
# Check logs
docker-compose logs blockchain

# Check disk space
df -h

# Check permissions
ls -la /opt/blackhole-blockchain/
```

#### P2P Connection Issues
```bash
# Check firewall
sudo ufw status

# Check peer connectivity
telnet peer-address 30303

# Verify external IP
curl ifconfig.me
```

#### High Resource Usage
```bash
# Monitor resources
htop
docker stats

# Check database size
du -sh /opt/blackhole-blockchain/data/

# Restart services
docker-compose restart
```

### Recovery Procedures

#### Database Corruption
```bash
# Stop services
docker-compose down

# Restore from backup
sudo -u blackhole rm -rf /opt/blackhole-blockchain/data
sudo -u blackhole cp -r /opt/blackhole-backups/latest /opt/blackhole-blockchain/data

# Restart services
docker-compose up -d
```

#### Network Partition Recovery
```bash
# Reset peer connections
docker-compose restart blockchain

# Clear peer cache
sudo -u blackhole rm -rf /opt/blackhole-blockchain/data/peers.db

# Restart with fresh bootstrap
docker-compose up -d
```

## 📞 Support

### Getting Help
- **Documentation**: [docs.blackhole.network](https://docs.blackhole.network)
- **GitHub Issues**: [github.com/Shivam-Patel-G/blackhole-blockchain/issues](https://github.com/Shivam-Patel-G/blackhole-blockchain/issues)
- **Discord**: [discord.gg/BlackHoleChain](https://discord.gg/BlackHoleChain)
- **Telegram**: [t.me/BlackHoleChain](https://t.me/BlackHoleChain)

### Reporting Issues
When reporting issues, please include:
- OS and version
- Docker/Docker Compose versions
- Full error logs
- Configuration files (remove sensitive data)
- Steps to reproduce

---

## 📝 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.