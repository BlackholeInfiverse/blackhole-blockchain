#!/bin/bash

# BlackHole Blockchain Deployment Script
# This script deploys the complete BlackHole blockchain ecosystem using Docker

set -e

echo "🚀 BlackHole Blockchain Deployment Script"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    print_header "Checking Docker installation..."
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_status "Docker and Docker Compose are installed"
}

# Check system requirements
check_requirements() {
    print_header "Checking system requirements..."
    
    # Check available memory (at least 4GB recommended)
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        MEMORY_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        MEMORY_GB=$((MEMORY_KB / 1024 / 1024))
        if [ $MEMORY_GB -lt 4 ]; then
            print_warning "System has less than 4GB RAM. Performance may be affected."
        else
            print_status "System memory: ${MEMORY_GB}GB (sufficient)"
        fi
    fi
    
    # Check available disk space (at least 10GB recommended)
    DISK_SPACE=$(df -BG . | tail -1 | awk '{print $4}' | sed 's/G//')
    if [ $DISK_SPACE -lt 10 ]; then
        print_warning "Less than 10GB disk space available. Consider freeing up space."
    else
        print_status "Available disk space: ${DISK_SPACE}GB (sufficient)"
    fi
}

# Create necessary directories
create_directories() {
    print_header "Creating necessary directories..."
    
    mkdir -p logs
    mkdir -p data/blockchain
    mkdir -p data/wallet
    mkdir -p data/mongodb
    mkdir -p config
    
    print_status "Directories created successfully"
}

# Generate configuration files
generate_config() {
    print_header "Generating configuration files..."
    
    # Create environment file
    cat > .env << EOF
# BlackHole Blockchain Configuration
COMPOSE_PROJECT_NAME=blackhole-blockchain

# Database Configuration
MONGODB_ROOT_USERNAME=admin
MONGODB_ROOT_PASSWORD=blackhole123
MONGODB_DATABASE=blackhole_wallet

# Blockchain Configuration
BLOCKCHAIN_LOG_LEVEL=info
BLOCKCHAIN_BLOCK_TIME=6s
BLOCKCHAIN_MAX_BLOCK_SIZE=1048576

# Wallet Configuration
WALLET_LOG_LEVEL=info
WALLET_SESSION_TIMEOUT=3600

# Monitoring Configuration
PROMETHEUS_RETENTION=200h
GRAFANA_ADMIN_PASSWORD=blackhole123

# Network Configuration
NETWORK_SUBNET=172.20.0.0/16
EOF

    print_status "Configuration files generated"
}

# Build Docker images
build_images() {
    print_header "Building Docker images..."
    
    print_status "Building blockchain node image..."
    docker build -f Dockerfile.blockchain -t blackhole/blockchain:latest .
    
    print_status "Building wallet service image..."
    docker build -f Dockerfile.wallet -t blackhole/wallet:latest .
    
    print_status "Docker images built successfully"
}

# Deploy services
deploy_services() {
    print_header "Deploying BlackHole blockchain services..."
    
    # Stop any existing services
    print_status "Stopping existing services..."
    docker-compose down --remove-orphans || true
    
    # Start services
    print_status "Starting services..."
    docker-compose up -d
    
    print_status "Services deployment initiated"
}

# Wait for services to be healthy
wait_for_services() {
    print_header "Waiting for services to be healthy..."
    
    # Wait for MongoDB
    print_status "Waiting for MongoDB..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if docker-compose exec -T mongodb mongosh --eval "db.adminCommand('ping')" &>/dev/null; then
            print_status "MongoDB is ready"
            break
        fi
        sleep 2
        timeout=$((timeout-2))
    done
    
    if [ $timeout -le 0 ]; then
        print_error "MongoDB failed to start within timeout"
        return 1
    fi
    
    # Wait for blockchain nodes
    print_status "Waiting for blockchain nodes..."
    for port in 8080 8081 8082; do
        timeout=60
        while [ $timeout -gt 0 ]; do
            if curl -s http://localhost:$port/api/status &>/dev/null; then
                print_status "Blockchain node on port $port is ready"
                break
            fi
            sleep 2
            timeout=$((timeout-2))
        done
        
        if [ $timeout -le 0 ]; then
            print_warning "Blockchain node on port $port may not be ready"
        fi
    done
    
    # Wait for wallet service
    print_status "Waiting for wallet service..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if curl -s http://localhost:9000/api/status &>/dev/null; then
            print_status "Wallet service is ready"
            break
        fi
        sleep 2
        timeout=$((timeout-2))
    done
    
    if [ $timeout -le 0 ]; then
        print_warning "Wallet service may not be ready"
    fi
}

# Display service information
display_info() {
    print_header "Deployment completed successfully!"
    echo ""
    echo "🌐 Service URLs:"
    echo "   Blockchain Node 1:  http://localhost:8080"
    echo "   Blockchain Node 2:  http://localhost:8081"
    echo "   Blockchain Node 3:  http://localhost:8082"
    echo "   Wallet Service:     http://localhost:9000"
    echo "   Load Balancer:      http://localhost:80"
    echo "   Prometheus:         http://localhost:9090"
    echo "   Grafana:           http://localhost:3000 (admin/blackhole123)"
    echo ""
    echo "📊 Monitoring:"
    echo "   Blockchain API:     http://localhost/api/status"
    echo "   Wallet API:         http://wallet.blackhole.local/api/status"
    echo "   Metrics:           http://monitor.blackhole.local/metrics"
    echo ""
    echo "🔧 Management Commands:"
    echo "   View logs:         docker-compose logs -f [service_name]"
    echo "   Stop services:     docker-compose down"
    echo "   Restart service:   docker-compose restart [service_name]"
    echo "   Scale nodes:       docker-compose up -d --scale blockchain-node-2=2"
    echo ""
    echo "📁 Data Locations:"
    echo "   Blockchain data:   ./data/blockchain/"
    echo "   Wallet data:       ./data/wallet/"
    echo "   MongoDB data:      Docker volume 'mongodb_data'"
    echo "   Logs:             ./logs/"
    echo ""
    print_status "BlackHole Blockchain is now running!"
}

# Cleanup function
cleanup() {
    print_header "Cleaning up deployment artifacts..."
    
    # Stop services
    docker-compose down --remove-orphans
    
    # Remove images (optional)
    read -p "Remove Docker images? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker rmi blackhole/blockchain:latest blackhole/wallet:latest || true
        print_status "Docker images removed"
    fi
    
    # Remove volumes (optional)
    read -p "Remove data volumes? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker-compose down -v
        print_status "Data volumes removed"
    fi
    
    print_status "Cleanup completed"
}

# Main deployment function
main() {
    case "${1:-deploy}" in
        "deploy")
            check_docker
            check_requirements
            create_directories
            generate_config
            build_images
            deploy_services
            wait_for_services
            display_info
            ;;
        "cleanup")
            cleanup
            ;;
        "status")
            docker-compose ps
            ;;
        "logs")
            docker-compose logs -f "${2:-}"
            ;;
        "restart")
            docker-compose restart "${2:-}"
            ;;
        "update")
            build_images
            docker-compose up -d --force-recreate
            wait_for_services
            display_info
            ;;
        *)
            echo "Usage: $0 {deploy|cleanup|status|logs|restart|update}"
            echo ""
            echo "Commands:"
            echo "  deploy   - Deploy the complete BlackHole blockchain (default)"
            echo "  cleanup  - Stop services and optionally remove data"
            echo "  status   - Show service status"
            echo "  logs     - Show service logs (optionally specify service name)"
            echo "  restart  - Restart services (optionally specify service name)"
            echo "  update   - Rebuild and update services"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
