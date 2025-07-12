#!/bin/bash

# BlackHole Bridge - Ultimate One-Liner Deployment Script
# ========================================================
# 
# This script provides a complete one-command deployment solution
# Usage: ./deploy-one-liner.sh [environment]
# 
# Environments:
#   dev        - Development with testnets
#   staging    - Staging environment  
#   prod       - Production deployment
#   local      - Local development (default)

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Environment setup
ENVIRONMENT=${1:-local}
PROJECT_NAME="blackhole-bridge"
COMPOSE_FILE="docker-compose.yml"

echo -e "${PURPLE}🚀 BlackHole Bridge - One-Liner Deployment${NC}"
echo -e "${CYAN}================================================${NC}"
echo -e "${BLUE}Environment: ${ENVIRONMENT}${NC}"
echo -e "${BLUE}Project: ${PROJECT_NAME}${NC}"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check prerequisites
echo -e "${CYAN}🔍 Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

print_status "Docker and Docker Compose are installed"

# Environment-specific configuration
case $ENVIRONMENT in
    "dev")
        ENV_FILE=".env.dev"
        COMPOSE_FILE="docker-compose.dev.yml"
        print_status "Using development configuration with testnets"
        ;;
    "staging")
        ENV_FILE=".env.staging"
        COMPOSE_FILE="docker-compose.yml"
        print_status "Using staging configuration"
        ;;
    "prod")
        ENV_FILE=".env.prod"
        COMPOSE_FILE="docker-compose.prod.yml"
        print_status "Using production configuration"
        ;;
    "local"|*)
        ENV_FILE=".env"
        COMPOSE_FILE="docker-compose.yml"
        print_status "Using local development configuration"
        ;;
esac

# Create .env file if it doesn't exist
if [ ! -f "$ENV_FILE" ]; then
    print_warning "Environment file $ENV_FILE not found. Creating from template..."
    cp .env.example "$ENV_FILE"
    
    if [ "$ENVIRONMENT" = "dev" ]; then
        # Configure for development/testnet
        sed -i 's/USE_TESTNET=false/USE_TESTNET=true/g' "$ENV_FILE"
        sed -i 's/APP_ENV=production/APP_ENV=development/g' "$ENV_FILE"
        sed -i 's/DEBUG_MODE=false/DEBUG_MODE=true/g' "$ENV_FILE"
        sed -i 's/LOG_LEVEL=info/LOG_LEVEL=debug/g' "$ENV_FILE"
    fi
    
    print_warning "Please edit $ENV_FILE with your actual configuration values:"
    print_warning "  - Blockchain RPC endpoints"
    print_warning "  - Private keys"
    print_warning "  - Contract addresses"
    print_warning "  - API keys and secrets"
    echo ""
    read -p "Press Enter to continue after configuring $ENV_FILE..."
fi

# Load environment variables
if [ -f "$ENV_FILE" ]; then
    export $(cat "$ENV_FILE" | grep -v '^#' | xargs)
    print_status "Environment variables loaded from $ENV_FILE"
fi

# Create required directories
echo -e "${CYAN}📁 Creating required directories...${NC}"
mkdir -p data logs media monitoring/grafana/dashboards monitoring/grafana/datasources nginx/ssl scripts
print_status "Directories created"

# Stop any existing containers
echo -e "${CYAN}🛑 Stopping existing containers...${NC}"
docker-compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
print_status "Existing containers stopped"

# Pull latest images
echo -e "${CYAN}📥 Pulling latest Docker images...${NC}"
docker-compose -f "$COMPOSE_FILE" pull
print_status "Docker images updated"

# Build the bridge application
echo -e "${CYAN}🔨 Building BlackHole Bridge...${NC}"
docker-compose -f "$COMPOSE_FILE" build --no-cache bridge-node
print_status "Bridge application built"

# Start all services
echo -e "${CYAN}🚀 Starting all services...${NC}"
docker-compose -f "$COMPOSE_FILE" up -d
print_status "All services started"

# Wait for services to be healthy
echo -e "${CYAN}⏳ Waiting for services to be ready...${NC}"
sleep 10

# Check service health
echo -e "${CYAN}🏥 Checking service health...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:${SERVER_PORT:-8084}/health > /dev/null; then
        print_status "Bridge service is healthy"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "Bridge service failed to start properly"
        docker-compose -f "$COMPOSE_FILE" logs bridge-node
        exit 1
    fi
    sleep 2
done

# Display service URLs
echo ""
echo -e "${PURPLE}🌟 BlackHole Bridge Deployment Complete!${NC}"
echo -e "${CYAN}================================================${NC}"
echo -e "${GREEN}📊 Dashboard:     http://localhost:${SERVER_PORT:-8084}${NC}"
echo -e "${GREEN}🏥 Health Check:  http://localhost:${SERVER_PORT:-8084}/health${NC}"
echo -e "${GREEN}📈 Grafana:       http://localhost:3000 (admin/admin123)${NC}"
echo -e "${GREEN}📊 Prometheus:    http://localhost:9091${NC}"
echo -e "${GREEN}🗄️  Redis:         localhost:6379${NC}"
echo -e "${GREEN}🐘 PostgreSQL:    localhost:5432${NC}"
echo ""
echo -e "${BLUE}🔧 Management Commands:${NC}"
echo -e "${CYAN}  View logs:      docker-compose -f $COMPOSE_FILE logs -f${NC}"
echo -e "${CYAN}  Stop services:  docker-compose -f $COMPOSE_FILE down${NC}"
echo -e "${CYAN}  Restart:        docker-compose -f $COMPOSE_FILE restart${NC}"
echo -e "${CYAN}  Update:         ./deploy-one-liner.sh $ENVIRONMENT${NC}"
echo ""
echo -e "${GREEN}✨ Bridge is ready for cross-chain transactions!${NC}"

# Optional: Open browser
if command -v xdg-open &> /dev/null; then
    read -p "Open dashboard in browser? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        xdg-open "http://localhost:${SERVER_PORT:-8084}"
    fi
elif command -v open &> /dev/null; then
    read -p "Open dashboard in browser? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        open "http://localhost:${SERVER_PORT:-8084}"
    fi
fi
