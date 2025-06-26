#!/bin/bash

# BlackHole Bridge-SDK Integrated Deployment Script
# ==================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
ENV_FILE="$SCRIPT_DIR/.env"

# Functions
print_header() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    🌉 BlackHole Bridge-SDK Integration                       ║"
    echo "║                          Production Deployment                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Setup environment
setup_environment() {
    print_step "Setting up environment..."
    
    # Create .env file if it doesn't exist
    if [ ! -f "$ENV_FILE" ]; then
        print_info "Creating .env file from template..."
        cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
        print_warning "Please edit .env file with your configuration before running again"
        print_info "Configuration file created at: $ENV_FILE"
        exit 0
    fi
    
    # Source environment variables
    source "$ENV_FILE"
    
    print_success "Environment setup complete"
}

# Build and deploy
deploy_system() {
    print_step "Building and deploying integrated system..."
    
    # Stop any existing containers
    print_info "Stopping existing containers..."
    docker-compose -f "$COMPOSE_FILE" down --remove-orphans || true
    
    # Build images
    print_info "Building Docker images..."
    docker-compose -f "$COMPOSE_FILE" build --no-cache
    
    # Start services in correct order
    print_info "Starting BlackHole blockchain..."
    docker-compose -f "$COMPOSE_FILE" up -d blackhole-blockchain
    
    # Wait for blockchain to be ready
    print_info "Waiting for blockchain to initialize..."
    sleep 30
    
    # Check blockchain health
    for i in {1..12}; do
        if docker-compose -f "$COMPOSE_FILE" exec -T blackhole-blockchain wget --no-verbose --tries=1 --spider http://localhost:8080/health &> /dev/null; then
            print_success "BlackHole blockchain is ready"
            break
        fi
        if [ $i -eq 12 ]; then
            print_error "BlackHole blockchain failed to start"
            exit 1
        fi
        print_info "Waiting for blockchain... ($i/12)"
        sleep 10
    done
    
    # Start remaining services
    print_info "Starting bridge and supporting services..."
    docker-compose -f "$COMPOSE_FILE" up -d
    
    print_success "System deployment complete"
}

# Verify deployment
verify_deployment() {
    print_step "Verifying deployment..."
    
    # Check service health
    services=("blackhole-blockchain" "bridge-node" "redis" "postgres")
    
    for service in "${services[@]}"; do
        if docker-compose -f "$COMPOSE_FILE" ps "$service" | grep -q "Up"; then
            print_success "$service is running"
        else
            print_error "$service is not running"
            return 1
        fi
    done
    
    # Check bridge health endpoint
    sleep 10
    if curl -f http://localhost:8084/health &> /dev/null; then
        print_success "Bridge health check passed"
    else
        print_warning "Bridge health check failed - service may still be starting"
    fi
    
    print_success "Deployment verification complete"
}

# Display access information
show_access_info() {
    print_step "Deployment complete! Access information:"
    echo ""
    echo -e "${GREEN}🌉 BlackHole Bridge Dashboard:${NC}"
    echo -e "   ${CYAN}http://localhost:8084${NC}"
    echo ""
    echo -e "${GREEN}🧠 BlackHole Blockchain API:${NC}"
    echo -e "   ${CYAN}http://localhost:8080${NC}"
    echo ""
    echo -e "${GREEN}📊 Monitoring:${NC}"
    echo -e "   Grafana: ${CYAN}http://localhost:3000${NC} (admin/admin123)"
    echo -e "   Prometheus: ${CYAN}http://localhost:9091${NC}"
    echo ""
    echo -e "${GREEN}💾 Database:${NC}"
    echo -e "   PostgreSQL: ${CYAN}localhost:5432${NC} (bridge/bridge123)"
    echo -e "   Redis: ${CYAN}localhost:6379${NC}"
    echo ""
    echo -e "${GREEN}🔧 Management Commands:${NC}"
    echo -e "   View logs: ${CYAN}docker-compose -f $COMPOSE_FILE logs -f${NC}"
    echo -e "   Stop system: ${CYAN}docker-compose -f $COMPOSE_FILE down${NC}"
    echo -e "   Restart: ${CYAN}docker-compose -f $COMPOSE_FILE restart${NC}"
    echo ""
    echo -e "${YELLOW}📝 Configuration:${NC}"
    echo -e "   Environment: ${CYAN}$ENV_FILE${NC}"
    echo -e "   Blockchain Mode: ${CYAN}$([ "${USE_REAL_BLOCKCHAIN:-true}" = "true" ] && echo "Real Blockchain" || echo "Simulation")${NC}"
    echo ""
}

# Cleanup function
cleanup() {
    if [ $? -ne 0 ]; then
        print_error "Deployment failed. Cleaning up..."
        docker-compose -f "$COMPOSE_FILE" down --remove-orphans || true
    fi
}

# Main execution
main() {
    trap cleanup EXIT
    
    print_header
    check_prerequisites
    setup_environment
    deploy_system
    verify_deployment
    show_access_info
    
    print_success "🚀 BlackHole Bridge-SDK Integration deployed successfully!"
}

# Run main function
main "$@"
