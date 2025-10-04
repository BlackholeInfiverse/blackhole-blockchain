#!/bin/bash

# BlackHole Blockchain Testnet Deployment Script
# This script deploys BlackHole Blockchain to a testnet environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEPLOY_USER="blackhole"
DEPLOY_PATH="/opt/blackhole-blockchain"
SERVICE_NAME="blackhole-blockchain"
BACKUP_PATH="/opt/blackhole-backups"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Pre-deployment checks
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if running as root or with sudo
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Create deployment user and directories
setup_deployment_environment() {
    log_info "Setting up deployment environment..."
    
    # Create deployment user if it doesn't exist
    if ! id "$DEPLOY_USER" &>/dev/null; then
        useradd -r -s /bin/bash -d $DEPLOY_PATH -m $DEPLOY_USER
        usermod -aG docker $DEPLOY_USER
        log_success "Created deployment user: $DEPLOY_USER"
    fi
    
    # Create necessary directories
    mkdir -p $DEPLOY_PATH/{data,logs,config,backups}
    mkdir -p $BACKUP_PATH
    
    # Set ownership
    chown -R $DEPLOY_USER:$DEPLOY_USER $DEPLOY_PATH
    chown -R $DEPLOY_USER:$DEPLOY_USER $BACKUP_PATH
    
    log_success "Deployment environment setup complete"
}

# Clone or update repository
update_codebase() {
    log_info "Updating codebase..."
    
    if [ ! -d "$DEPLOY_PATH/src" ]; then
        # Clone repository
        sudo -u $DEPLOY_USER git clone https://github.com/Shivam-Patel-G/blackhole-blockchain.git $DEPLOY_PATH/src
        log_success "Repository cloned"
    else
        # Update existing repository
        cd $DEPLOY_PATH/src
        sudo -u $DEPLOY_USER git fetch origin
        sudo -u $DEPLOY_USER git checkout testnet
        sudo -u $DEPLOY_USER git pull origin testnet
        log_success "Repository updated"
    fi
}

# Setup environment configuration
setup_environment_config() {
    log_info "Setting up environment configuration..."
    
    # Copy environment template
    cp $DEPLOY_PATH/src/docker/.env.template $DEPLOY_PATH/.env
    
    # Update environment variables for testnet
    sed -i 's/NETWORK=testnet/NETWORK=testnet/' $DEPLOY_PATH/.env
    sed -i 's/NODE_ENV=development/NODE_ENV=production/' $DEPLOY_PATH/.env
    sed -i 's/LOG_LEVEL=info/LOG_LEVEL=info/' $DEPLOY_PATH/.env
    sed -i 's/DEBUG_MODE=false/DEBUG_MODE=false/' $DEPLOY_PATH/.env
    
    # Set external IP if available
    EXTERNAL_IP=$(curl -s ifconfig.me || echo "")
    if [ ! -z "$EXTERNAL_IP" ]; then
        sed -i "s/EXTERNAL_IP=\"\"/EXTERNAL_IP=\"$EXTERNAL_IP\"/" $DEPLOY_PATH/.env
        log_info "Set external IP to: $EXTERNAL_IP"
    fi
    
    chown $DEPLOY_USER:$DEPLOY_USER $DEPLOY_PATH/.env
    log_success "Environment configuration setup complete"
}

# Build Docker images
build_docker_images() {
    log_info "Building Docker images..."
    
    cd $DEPLOY_PATH/src
    sudo -u $DEPLOY_USER docker-compose build --no-cache
    
    log_success "Docker images built successfully"
}

# Create systemd service
create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=BlackHole Blockchain Node
Requires=docker.service
After=docker.service

[Service]
Type=forking
User=$DEPLOY_USER
Group=$DEPLOY_USER
WorkingDirectory=$DEPLOY_PATH/src
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
ExecReload=/usr/local/bin/docker-compose restart
TimeoutStartSec=300
TimeoutStopSec=120
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    
    log_success "Systemd service created and enabled"
}

# Deploy the blockchain
deploy_blockchain() {
    log_info "Deploying BlackHole Blockchain..."
    
    cd $DEPLOY_PATH/src
    
    # Create backup of existing data if it exists
    if [ -d "$DEPLOY_PATH/data" ] && [ "$(ls -A $DEPLOY_PATH/data)" ]; then
        BACKUP_NAME="backup-$(date +%Y%m%d-%H%M%S)"
        sudo -u $DEPLOY_USER cp -r $DEPLOY_PATH/data $BACKUP_PATH/$BACKUP_NAME
        log_info "Created backup: $BACKUP_NAME"
    fi
    
    # Start the services
    sudo -u $DEPLOY_USER docker-compose --env-file $DEPLOY_PATH/.env up -d
    
    log_success "BlackHole Blockchain deployed successfully"
}

# Setup firewall rules
setup_firewall() {
    log_info "Setting up firewall rules..."
    
    # Install ufw if not present
    if ! command -v ufw &> /dev/null; then
        apt-get update && apt-get install -y ufw
    fi
    
    # Configure firewall
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow ssh
    
    # Allow blockchain ports
    ufw allow 8080/tcp comment "BlackHole Blockchain API"
    ufw allow 8084/tcp comment "BlackHole Bridge API"
    ufw allow 8545/tcp comment "RPC Endpoint"
    ufw allow 30303/tcp comment "P2P Networking"
    ufw allow 30303/udp comment "P2P Discovery"
    
    # Enable firewall
    ufw --force enable
    
    log_success "Firewall configured"
}

# Health check
health_check() {
    log_info "Running health checks..."
    
    sleep 30 # Wait for services to start
    
    # Check blockchain API
    if curl -f http://localhost:8080/health &>/dev/null; then
        log_success "Blockchain API is healthy"
    else
        log_warning "Blockchain API health check failed"
    fi
    
    # Check bridge API
    if curl -f http://localhost:8084 &>/dev/null; then
        log_success "Bridge API is healthy"
    else
        log_warning "Bridge API health check failed"
    fi
    
    # Check Docker containers
    if sudo -u $DEPLOY_USER docker-compose ps | grep -q "Up"; then
        log_success "Docker containers are running"
    else
        log_error "Some Docker containers are not running"
    fi
}

# Setup monitoring
setup_monitoring() {
    log_info "Setting up monitoring..."
    
    # Create monitoring script
    cat > $DEPLOY_PATH/monitor.sh << EOF
#!/bin/bash
# Basic monitoring script for BlackHole Blockchain

LOG_FILE=$DEPLOY_PATH/logs/monitor.log
DATE=\$(date '+%Y-%m-%d %H:%M:%S')

# Check if containers are running
if ! docker-compose ps | grep -q "Up"; then
    echo "[\$DATE] ERROR: Some containers are not running" >> \$LOG_FILE
    # Restart services
    docker-compose restart
fi

# Check API endpoints
if ! curl -f http://localhost:8080/health &>/dev/null; then
    echo "[\$DATE] WARNING: Blockchain API health check failed" >> \$LOG_FILE
fi

if ! curl -f http://localhost:8084 &>/dev/null; then
    echo "[\$DATE] WARNING: Bridge API health check failed" >> \$LOG_FILE
fi

# Check disk space
DISK_USAGE=\$(df $DEPLOY_PATH | tail -1 | awk '{print \$5}' | sed 's/%//')
if [ \$DISK_USAGE -gt 80 ]; then
    echo "[\$DATE] WARNING: Disk usage is at \${DISK_USAGE}%" >> \$LOG_FILE
fi
EOF
    
    chmod +x $DEPLOY_PATH/monitor.sh
    chown $DEPLOY_USER:$DEPLOY_USER $DEPLOY_PATH/monitor.sh
    
    # Add cron job for monitoring
    (crontab -u $DEPLOY_USER -l 2>/dev/null || true; echo "*/5 * * * * $DEPLOY_PATH/monitor.sh") | crontab -u $DEPLOY_USER -
    
    log_success "Monitoring setup complete"
}

# Main deployment function
main() {
    log_info "Starting BlackHole Blockchain testnet deployment..."
    
    check_prerequisites
    setup_deployment_environment
    update_codebase
    setup_environment_config
    build_docker_images
    create_systemd_service
    setup_firewall
    deploy_blockchain
    health_check
    setup_monitoring
    
    log_success "Deployment completed successfully!"
    log_info "Blockchain API: http://$(curl -s ifconfig.me):8080"
    log_info "Bridge API: http://$(curl -s ifconfig.me):8084"
    log_info "To check status: systemctl status $SERVICE_NAME"
    log_info "To view logs: docker-compose logs -f"
}

# Run deployment
main "$@"