# 🚀 BlackHole Blockchain - Production Deployment Guide

## 📋 Overview

This guide provides comprehensive instructions for deploying the BlackHole Blockchain platform to production environments.

---

## 🔧 Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+ recommended) or Windows Server 2019+
- **CPU**: 4+ cores (8+ recommended for high-traffic)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**: 100GB+ SSD (NVMe recommended)
- **Network**: Stable internet connection with public IP
- **Go Version**: 1.19+ required

### Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y git build-essential curl

# Install Go (if not already installed)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

---

## 📦 Installation

### 1. Clone Repository
```bash
git clone https://github.com/Shivam-Patel-G/blackhole-blockchain.git
cd blackhole-blockchain
```

### 2. Build Application
```bash
# Build all components
go mod tidy
go build -o blackhole-node ./cmd/node
go build -o blackhole-cli ./cmd/cli

# Make executable
chmod +x blackhole-node blackhole-cli
```

### 3. Create Directory Structure
```bash
# Create production directories
sudo mkdir -p /opt/blackhole-blockchain/{data,logs,config,backups}
sudo chown -R $USER:$USER /opt/blackhole-blockchain

# Copy binaries
sudo cp blackhole-node blackhole-cli /usr/local/bin/
```

---

## ⚙️ Configuration

### 1. Environment Configuration
Create `/opt/blackhole-blockchain/config/production.env`:
```bash
# Network Configuration
NODE_PORT=4001
P2P_PORT=4002
DASHBOARD_PORT=8080
API_PORT=8081

# Database Configuration
DB_PATH=/opt/blackhole-blockchain/data/blockchain.db
LOG_PATH=/opt/blackhole-blockchain/logs

# Security Configuration
ENABLE_TLS=true
TLS_CERT_PATH=/opt/blackhole-blockchain/config/server.crt
TLS_KEY_PATH=/opt/blackhole-blockchain/config/server.key

# Performance Configuration
MAX_PEERS=50
BLOCK_TIME=6
MAX_TXS_PER_BLOCK=1000

# Monitoring Configuration
ENABLE_METRICS=true
METRICS_PORT=9090
LOG_LEVEL=INFO

# Economic Configuration
INITIAL_SUPPLY=10000000
INFLATION_RATE=7.0
TARGET_STAKING_RATIO=67.0
```

### 2. Network Configuration
```bash
# Configure firewall
sudo ufw allow 4001/tcp  # Node communication
sudo ufw allow 4002/tcp  # P2P network
sudo ufw allow 8080/tcp  # Dashboard (restrict to admin IPs)
sudo ufw allow 8081/tcp  # API (restrict as needed)
sudo ufw enable
```

### 3. TLS Certificate Setup
```bash
# Generate self-signed certificate (for testing)
openssl req -x509 -newkey rsa:4096 -keyout /opt/blackhole-blockchain/config/server.key \
  -out /opt/blackhole-blockchain/config/server.crt -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=your-domain.com"

# Set proper permissions
chmod 600 /opt/blackhole-blockchain/config/server.key
chmod 644 /opt/blackhole-blockchain/config/server.crt
```

---

## 🚀 Deployment

### 1. Systemd Service Setup
Create `/etc/systemd/system/blackhole-blockchain.service`:
```ini
[Unit]
Description=BlackHole Blockchain Node
After=network.target
Wants=network.target

[Service]
Type=simple
User=blackhole
Group=blackhole
WorkingDirectory=/opt/blackhole-blockchain
EnvironmentFile=/opt/blackhole-blockchain/config/production.env
ExecStart=/usr/local/bin/blackhole-node --config /opt/blackhole-blockchain/config/production.env
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=blackhole-blockchain

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/blackhole-blockchain

[Install]
WantedBy=multi-user.target
```

### 2. Create Service User
```bash
# Create dedicated user
sudo useradd -r -s /bin/false -d /opt/blackhole-blockchain blackhole
sudo chown -R blackhole:blackhole /opt/blackhole-blockchain
```

### 3. Start Services
```bash
# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable blackhole-blockchain
sudo systemctl start blackhole-blockchain

# Check status
sudo systemctl status blackhole-blockchain
```

---

## 📊 Monitoring Setup

### 1. Production Dashboard
The production dashboard will be available at:
- **URL**: `https://your-domain:8080`
- **Features**: Real-time metrics, alerts, system health
- **Authentication**: Configure reverse proxy with authentication

### 2. Log Monitoring
```bash
# View real-time logs
sudo journalctl -u blackhole-blockchain -f

# View structured token logs
tail -f /opt/blackhole-blockchain/logs/token_transactions_*.jsonl

# Monitor system resources
htop
iostat -x 1
```

### 3. Alerting Setup
Configure alerts for:
- High CPU/Memory usage (>80%)
- Low peer count (<3)
- High error rate (>5%)
- Disk space usage (>90%)
- Network connectivity issues

---

## 🔒 Security Hardening

### 1. Network Security
```bash
# Restrict dashboard access to admin IPs only
sudo ufw delete allow 8080/tcp
sudo ufw allow from YOUR_ADMIN_IP to any port 8080

# Use fail2ban for SSH protection
sudo apt install fail2ban
sudo systemctl enable fail2ban
```

### 2. Application Security
- Enable TLS for all communications
- Use strong passwords for admin accounts
- Regularly update dependencies
- Monitor for security vulnerabilities
- Implement rate limiting for API endpoints

### 3. Data Protection
```bash
# Setup automated backups
sudo crontab -e
# Add: 0 2 * * * /opt/blackhole-blockchain/scripts/backup.sh

# Create backup script
cat > /opt/blackhole-blockchain/scripts/backup.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/blackhole-blockchain/backups"
tar -czf "$BACKUP_DIR/blockchain_backup_$DATE.tar.gz" \
  /opt/blackhole-blockchain/data \
  /opt/blackhole-blockchain/config
# Keep only last 7 days of backups
find "$BACKUP_DIR" -name "blockchain_backup_*.tar.gz" -mtime +7 -delete
EOF

chmod +x /opt/blackhole-blockchain/scripts/backup.sh
```

---

## 🔧 Maintenance

### 1. Regular Updates
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update blockchain software
cd blackhole-blockchain
git pull origin main
go build -o blackhole-node ./cmd/node
sudo systemctl stop blackhole-blockchain
sudo cp blackhole-node /usr/local/bin/
sudo systemctl start blackhole-blockchain
```

### 2. Database Maintenance
```bash
# Check database size
du -sh /opt/blackhole-blockchain/data/

# Compact database (if needed)
sudo systemctl stop blackhole-blockchain
# Run compaction tool (implement as needed)
sudo systemctl start blackhole-blockchain
```

### 3. Performance Tuning
```bash
# Monitor performance
iostat -x 1
iotop
netstat -i

# Adjust system limits if needed
echo "blackhole soft nofile 65536" >> /etc/security/limits.conf
echo "blackhole hard nofile 65536" >> /etc/security/limits.conf
```

---

## 🚨 Troubleshooting

### Common Issues

#### 1. Node Won't Start
```bash
# Check logs
sudo journalctl -u blackhole-blockchain -n 50

# Check configuration
sudo -u blackhole /usr/local/bin/blackhole-node --validate-config

# Check permissions
ls -la /opt/blackhole-blockchain/
```

#### 2. High Memory Usage
```bash
# Monitor memory usage
free -h
ps aux | grep blackhole

# Restart service if needed
sudo systemctl restart blackhole-blockchain
```

#### 3. Network Connectivity Issues
```bash
# Check network status
netstat -tlnp | grep blackhole
ss -tlnp | grep 4001

# Test connectivity
telnet your-domain 4001
```

#### 4. Database Corruption
```bash
# Stop service
sudo systemctl stop blackhole-blockchain

# Restore from backup
cd /opt/blackhole-blockchain/backups
tar -xzf blockchain_backup_YYYYMMDD_HHMMSS.tar.gz -C /

# Start service
sudo systemctl start blackhole-blockchain
```

---

## 📈 Performance Optimization

### 1. System Optimization
```bash
# Optimize kernel parameters
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
echo 'vm.swappiness = 10' >> /etc/sysctl.conf
sysctl -p
```

### 2. Application Optimization
- Adjust `MAX_TXS_PER_BLOCK` based on hardware
- Tune `BLOCK_TIME` for network conditions
- Configure appropriate `MAX_PEERS` count
- Enable connection pooling for database

### 3. Hardware Recommendations
- **CPU**: Intel Xeon or AMD EPYC for production
- **RAM**: 32GB+ for high-traffic networks
- **Storage**: NVMe SSD with high IOPS
- **Network**: Gigabit connection minimum

---

## 📞 Support

### Getting Help
- **Documentation**: Check `/docs` directory
- **Logs**: Always include relevant logs when reporting issues
- **System Info**: Provide OS, hardware, and configuration details
- **Monitoring**: Use dashboard metrics to identify issues

### Emergency Procedures
1. **Service Down**: Restart service, check logs, restore from backup if needed
2. **Data Corruption**: Stop service, restore from latest backup
3. **Security Breach**: Isolate node, analyze logs, update security measures
4. **Performance Issues**: Monitor resources, adjust configuration, scale hardware

---

*This deployment guide ensures a secure, reliable, and performant BlackHole Blockchain production environment.*
