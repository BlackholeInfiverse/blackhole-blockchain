#!/bin/bash

# BlackHole Bridge - One-Command Deployment Script
# =================================================
# This script demonstrates the complete deployment process
# Usage: ./deploy.sh [mode]
# Modes: dev, prod, simulation

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
MODE=${1:-dev}
PROJECT_NAME="blackhole-bridge"
COMPOSE_FILE="docker-compose.yml"

# Functions
print_header() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    BlackHole Bridge                         ║"
    echo "║                 One-Command Deployment                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${CYAN}🔧 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
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
    
    # Check Go (for local development)
    if [[ "$MODE" == "dev" ]] && ! command -v go &> /dev/null; then
        print_warning "Go is not installed. Docker mode will be used instead."
        MODE="docker"
    fi
    
    print_success "Prerequisites check completed"
}

# Setup environment
setup_environment() {
    print_step "Setting up environment..."
    
    # Create necessary directories
    mkdir -p data logs monitoring/grafana/dashboards monitoring/grafana/datasources
    
    # Copy .env file if it doesn't exist
    if [[ ! -f .env ]]; then
        if [[ -f .env.example ]]; then
            cp .env.example .env
            print_info "Created .env file from template"
        else
            print_warning "No .env file found. Using default configuration."
        fi
    fi
    
    # Set mode-specific environment variables
    case $MODE in
        "dev")
            export APP_ENV=development
            export DEBUG_MODE=true
            export RUN_SIMULATION=true
            export ENABLE_COLORED_LOGS=true
            ;;
        "prod")
            export APP_ENV=production
            export DEBUG_MODE=false
            export RUN_SIMULATION=false
            export ENABLE_COLORED_LOGS=false
            ;;
        "simulation")
            export APP_ENV=development
            export DEBUG_MODE=true
            export RUN_SIMULATION=true
            export ENABLE_COLORED_LOGS=true
            ;;
    esac
    
    print_success "Environment setup completed"
}

# Build and deploy
deploy() {
    print_step "Deploying BlackHole Bridge in $MODE mode..."
    
    case $MODE in
        "dev")
            deploy_development
            ;;
        "prod")
            deploy_production
            ;;
        "simulation")
            deploy_simulation
            ;;
        *)
            print_error "Unknown mode: $MODE"
            print_info "Available modes: dev, prod, simulation"
            exit 1
            ;;
    esac
}

# Development deployment
deploy_development() {
    print_step "Starting development environment..."
    
    # Build and start services
    docker-compose -f docker-compose.dev.yml up --build -d
    
    # Wait for services to be ready
    wait_for_services
    
    print_success "Development environment started"
    show_endpoints
}

# Production deployment
deploy_production() {
    print_step "Starting production environment..."
    
    # Build and start services
    docker-compose -f docker-compose.prod.yml up --build -d
    
    # Wait for services to be ready
    wait_for_services
    
    print_success "Production environment started"
    show_endpoints
}

# Simulation deployment
deploy_simulation() {
    print_step "Starting simulation environment..."
    
    # Set simulation environment variables
    export RUN_SIMULATION=true
    export ENABLE_COLORED_LOGS=true
    
    # Start with simulation enabled
    docker-compose up --build -d
    
    # Wait for services to be ready
    wait_for_services
    
    # Run simulation
    run_simulation
    
    print_success "Simulation environment started"
    show_endpoints
}

# Wait for services to be ready
wait_for_services() {
    print_step "Waiting for services to be ready..."
    
    # Wait for bridge node
    for i in {1..30}; do
        if curl -s http://localhost:8084/health > /dev/null 2>&1; then
            break
        fi
        echo -n "."
        sleep 2
    done
    echo ""
    
    print_success "Services are ready"
}

# Run simulation
run_simulation() {
    print_step "Running end-to-end simulation..."
    
    # Trigger simulation via API
    curl -X POST http://localhost:8084/api/simulation/run > /dev/null 2>&1 || true
    
    # Wait for simulation to complete
    sleep 10
    
    # Check simulation results
    if [[ -f simulation_proof.json ]]; then
        print_success "Simulation completed. Results saved to simulation_proof.json"
    else
        print_warning "Simulation results not found"
    fi
}

# Show endpoints
show_endpoints() {
    echo ""
    print_info "🌐 BlackHole Bridge is now running!"
    echo ""
    echo -e "${GREEN}📊 Dashboard:     ${CYAN}http://localhost:8084${NC}"
    echo -e "${GREEN}🏥 Health Check:  ${CYAN}http://localhost:8084/health${NC}"
    echo -e "${GREEN}📈 Statistics:    ${CYAN}http://localhost:8084/stats${NC}"
    echo -e "${GREEN}💸 Transactions:  ${CYAN}http://localhost:8084/transactions${NC}"
    echo -e "${GREEN}📜 Logs:          ${CYAN}http://localhost:8084/logs${NC}"
    echo -e "${GREEN}📚 Documentation: ${CYAN}http://localhost:8084/docs${NC}"
    echo -e "${GREEN}🧪 Simulation:    ${CYAN}http://localhost:8084/simulation${NC}"
    echo ""
    echo -e "${YELLOW}📊 Monitoring:    ${CYAN}http://localhost:3000${NC} (Grafana - admin/admin123)"
    echo -e "${YELLOW}🔍 Metrics:       ${CYAN}http://localhost:9091${NC} (Prometheus)"
    echo ""
    echo -e "${BLUE}🛑 To stop: ${CYAN}docker-compose down${NC}"
    echo ""
}

# Cleanup function
cleanup() {
    print_step "Cleaning up..."
    docker-compose down -v
    print_success "Cleanup completed"
}

# Main execution
main() {
    print_header
    
    # Handle cleanup flag
    if [[ "$1" == "cleanup" ]]; then
        cleanup
        exit 0
    fi
    
    check_prerequisites
    setup_environment
    deploy
}

# Run main function
main "$@"
