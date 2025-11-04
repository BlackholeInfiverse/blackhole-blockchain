#!/bin/bash

# BlackHole Bridge SDK Deployment Script
# This script deploys the bridge SDK with block explorer functionality

set -e

echo "🚀 Starting BlackHole Bridge SDK Deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN_BRIDGE_DIR="$PROJECT_DIR/main_bridge"
DOCKER_COMPOSE_FILE="$PROJECT_DIR/docker-compose.yml"
ENV_FILE="$MAIN_BRIDGE_DIR/.env"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
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

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."

    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi

    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed. Please install Go first."
        exit 1
    fi

    print_success "Prerequisites check passed"
}

# Setup environment
setup_environment() {
    print_status "Setting up environment..."

    # Create .env file if it doesn't exist
    if [ ! -f "$ENV_FILE" ]; then
        cp "$MAIN_BRIDGE_DIR/.env.example" "$ENV_FILE"
        print_warning "Created .env file from example. Please edit it with your configuration."
    fi

    # Create necessary directories
    mkdir -p "$MAIN_BRIDGE_DIR/data"
    mkdir -p "$MAIN_BRIDGE_DIR/logs"

    print_success "Environment setup completed"
}

# Build the application
build_application() {
    print_status "Building bridge application..."

    cd "$MAIN_BRIDGE_DIR"

    # Download dependencies
    go mod download

    # Build the application
    go build -o main main.go

    if [ $? -eq 0 ]; then
        print_success "Application built successfully"
    else
        print_error "Failed to build application"
        exit 1
    fi
}

# Start services with Docker Compose
start_services() {
    print_status "Starting services with Docker Compose..."

    cd "$PROJECT_DIR"

    # Start services
    if command -v docker-compose &> /dev/null; then
        docker-compose up -d
    else
        docker compose up -d
    fi

    if [ $? -eq 0 ]; then
        print_success "Services started successfully"
    else
        print_error "Failed to start services"
        exit 1
    fi
}

# Wait for services to be ready
wait_for_services() {
    print_status "Waiting for services to be ready..."

    # Wait for bridge service
    max_attempts=30
    attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -s http://localhost:8084/health > /dev/null; then
            print_success "Bridge service is ready"
            break
        fi

        print_status "Waiting for bridge service... (attempt $attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done

    if [ $attempt -gt $max_attempts ]; then
        print_warning "Bridge service may not be ready yet. Continuing..."
    fi
}

# Test block explorer endpoints
test_explorer_endpoints() {
    print_status "Testing block explorer endpoints..."

    # Test health endpoint
    if curl -s http://localhost:8084/health | grep -q "healthy"; then
        print_success "Health endpoint is working"
    else
        print_warning "Health endpoint may not be responding correctly"
    fi

    # Test stats endpoint
    if curl -s http://localhost:8084/stats | grep -q "success"; then
        print_success "Stats endpoint is working"
    else
        print_warning "Stats endpoint may not be responding correctly"
    fi

    # Test transactions endpoint
    if curl -s http://localhost:8084/transactions | grep -q "transactions"; then
        print_success "Transactions endpoint is working"
    else
        print_warning "Transactions endpoint may not be responding correctly"
    fi
}

# Display deployment information
display_info() {
    echo ""
    print_success "🎉 BlackHole Bridge SDK deployed successfully!"
    echo ""
    echo "📊 Dashboard URLs:"
    echo "   • Main Dashboard: http://localhost:8084"
    echo "   • Health Check: http://localhost:8084/health"
    echo "   • Statistics: http://localhost:8084/stats"
    echo "   • Transactions: http://localhost:8084/transactions"
    echo ""
    echo "🔍 Block Explorer Endpoints:"
    echo "   • Block by Height: http://localhost:8084/block/{height}"
    echo "   • Transaction by Hash: http://localhost:8084/tx/{hash}"
    echo ""
    echo "📝 Logs:"
    echo "   • View logs: docker-compose logs -f bridge"
    echo "   • Log files: ./main_bridge/logs/"
    echo ""
    echo "🛠️  Management:"
    echo "   • Stop: docker-compose down"
    echo "   • Restart: docker-compose restart"
    echo "   • Rebuild: docker-compose up -d --build"
    echo ""
}

# Main deployment function
main() {
    echo "=========================================="
    echo "🚀 BlackHole Bridge SDK Deployment Script"
    echo "=========================================="
    echo ""

    check_prerequisites
    setup_environment
    build_application
    start_services
    wait_for_services
    test_explorer_endpoints
    display_info

    print_success "Deployment completed successfully!"
}

# Handle command line arguments
case "${1:-}" in
    "stop")
        print_status "Stopping services..."
        cd "$PROJECT_DIR"
        if command -v docker-compose &> /dev/null; then
            docker-compose down
        else
            docker compose down
        fi
        print_success "Services stopped"
        ;;
    "restart")
        print_status "Restarting services..."
        cd "$PROJECT_DIR"
        if command -v docker-compose &> /dev/null; then
            docker-compose restart
        else
            docker compose restart
        fi
        print_success "Services restarted"
        ;;
    "logs")
        print_status "Showing logs..."
        cd "$PROJECT_DIR"
        if command -v docker-compose &> /dev/null; then
            docker-compose logs -f
        else
            docker compose logs -f
        fi
        ;;
    "status")
        print_status "Checking service status..."
        cd "$PROJECT_DIR"
        if command -v docker-compose &> /dev/null; then
            docker-compose ps
        else
            docker compose ps
        fi
        ;;
    *)
        main
        ;;
esac