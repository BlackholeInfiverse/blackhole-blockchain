#!/bin/bash

# BlackHole Bridge Startup Script
# ===============================

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
ENV_FILE="$SCRIPT_DIR/.env"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
DEV_COMPOSE_FILE="$SCRIPT_DIR/docker-compose.dev.yml"

# Functions
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    BlackHole Bridge                         ║"
    echo "║                 Deployment & Management                     ║"
    echo "║                                                              ║"
    echo "║  🌉 Cross-Chain Bridge Infrastructure                       ║"
    echo "║  🚀 One-Command Deployment Ready                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_help() {
    echo -e "${CYAN}Usage: $0 [COMMAND] [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Commands:${NC}"
    echo "  start         Start the bridge in production mode"
    echo "  dev           Start in development mode with hot reload"
    echo "  stop          Stop all services"
    echo "  restart       Restart all services"
    echo "  status        Show status of all services"
    echo "  logs          Show logs from all services"
    echo "  health        Check health of all services"
    echo "  setup         Initial setup and configuration"
    echo "  clean         Clean up containers and volumes"
    echo "  backup        Create backup of data and configuration"
    echo "  update        Update all services to latest versions"
    echo "  shell         Open shell in bridge container"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -h, --help    Show this help message"
    echo "  -v, --verbose Enable verbose output"
    echo "  -q, --quiet   Suppress non-error output"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 start                    # Start production bridge"
    echo "  $0 dev                      # Start development mode"
    echo "  $0 logs bridge-node         # Show bridge logs only"
    echo "  $0 backup                   # Create full backup"
}

log() {
    if [[ "$QUIET" != "true" ]]; then
        echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
    fi
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}" >&2
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[DEBUG] $1${NC}"
    fi
}

check_dependencies() {
    log "Checking dependencies..."
    
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    verbose "Docker version: $(docker --version)"
    verbose "Docker Compose version: $(docker-compose --version)"
}

check_env() {
    if [[ ! -f "$ENV_FILE" ]]; then
        warn ".env file not found. Creating from template..."
        if [[ -f "$SCRIPT_DIR/.env.example" ]]; then
            cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
        else
            create_default_env
        fi
        warn "Please edit .env file with your configuration before starting the bridge."
    fi
}

create_default_env() {
    log "Creating default .env file..."
    cat > "$ENV_FILE" << 'EOF'
# BlackHole Bridge Configuration
APP_ENV=production
SERVER_PORT=8084
ETHEREUM_RPC_URL=https://eth-mainnet.alchemyapi.io/v2/YOUR_ALCHEMY_KEY
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
BLACKHOLE_RPC_URL=http://blackhole-node:8545
LOG_LEVEL=info
DEBUG_MODE=false
EOF
}

setup_directories() {
    log "Setting up directories..."
    mkdir -p "$SCRIPT_DIR/data"
    mkdir -p "$SCRIPT_DIR/logs"
    mkdir -p "$SCRIPT_DIR/backups"
    mkdir -p "$SCRIPT_DIR/monitoring/grafana/dashboards"
    mkdir -p "$SCRIPT_DIR/monitoring/grafana/datasources"
    mkdir -p "$SCRIPT_DIR/nginx/ssl"
    verbose "Directories created successfully"
}

start_production() {
    log "Starting BlackHole Bridge in production mode..."
    check_dependencies
    check_env
    setup_directories
    
    verbose "Using compose file: $COMPOSE_FILE"
    docker-compose -f "$COMPOSE_FILE" up -d
    
    log "Waiting for services to start..."
    sleep 10
    
    check_health
    
    echo ""
    echo -e "${GREEN}🚀 BlackHole Bridge is now running!${NC}"
    echo -e "${CYAN}📊 Dashboard: http://localhost:8084${NC}"
    echo -e "${CYAN}📈 Monitoring: http://localhost:3000 (admin/admin123)${NC}"
    echo -e "${CYAN}🔍 Logs: $0 logs${NC}"
    echo ""
}

start_development() {
    log "Starting BlackHole Bridge in development mode..."
    check_dependencies
    check_env
    setup_directories
    
    verbose "Using compose files: $COMPOSE_FILE, $DEV_COMPOSE_FILE"
    docker-compose -f "$COMPOSE_FILE" -f "$DEV_COMPOSE_FILE" up -d
    
    log "Development server started with hot reload!"
    echo -e "${CYAN}📊 Dashboard: http://localhost:8084${NC}"
    echo -e "${CYAN}🔧 Development mode with hot reload enabled${NC}"
}

stop_services() {
    log "Stopping BlackHole Bridge services..."
    docker-compose -f "$COMPOSE_FILE" down
    log "Services stopped successfully"
}

restart_services() {
    log "Restarting BlackHole Bridge services..."
    stop_services
    sleep 5
    start_production
}

show_status() {
    log "Service Status:"
    docker-compose -f "$COMPOSE_FILE" ps
}

show_logs() {
    local service="$1"
    if [[ -n "$service" ]]; then
        log "Showing logs for $service..."
        docker-compose -f "$COMPOSE_FILE" logs -f "$service"
    else
        log "Showing logs for all services..."
        docker-compose -f "$COMPOSE_FILE" logs -f
    fi
}

check_health() {
    log "Checking service health..."
    
    # Check bridge health
    if curl -s http://localhost:8084/health > /dev/null; then
        echo -e "${GREEN}✓ Bridge service: Healthy${NC}"
    else
        echo -e "${RED}✗ Bridge service: Unhealthy${NC}"
    fi
    
    # Check database
    if docker-compose exec -T postgres pg_isready -U bridge > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PostgreSQL: Healthy${NC}"
    else
        echo -e "${RED}✗ PostgreSQL: Unhealthy${NC}"
    fi
    
    # Check Redis
    if docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Redis: Healthy${NC}"
    else
        echo -e "${RED}✗ Redis: Unhealthy${NC}"
    fi
}

setup_environment() {
    log "Setting up BlackHole Bridge environment..."
    check_dependencies
    setup_directories
    check_env
    
    log "Building Docker images..."
    docker-compose -f "$COMPOSE_FILE" build
    
    log "Environment setup complete!"
    echo -e "${CYAN}Next steps:${NC}"
    echo "1. Edit .env file with your configuration"
    echo "2. Run: $0 start"
}

create_backup() {
    local backup_dir="$SCRIPT_DIR/backups/$(date +%Y%m%d_%H%M%S)"
    log "Creating backup in $backup_dir..."
    
    mkdir -p "$backup_dir"
    
    # Backup database
    if docker-compose exec -T postgres pg_dump -U bridge bridge_db > "$backup_dir/database.sql" 2>/dev/null; then
        echo -e "${GREEN}✓ Database backup created${NC}"
    else
        warn "Failed to backup database"
    fi
    
    # Backup volumes
    docker run --rm -v bridge-data:/data -v "$backup_dir":/backup alpine tar czf /backup/bridge-data.tar.gz -C /data . 2>/dev/null
    docker run --rm -v bridge-logs:/logs -v "$backup_dir":/backup alpine tar czf /backup/bridge-logs.tar.gz -C /logs . 2>/dev/null
    
    log "Backup completed: $backup_dir"
}

clean_environment() {
    log "Cleaning up containers and volumes..."
    docker-compose -f "$COMPOSE_FILE" down -v --remove-orphans
    docker system prune -f
    log "Cleanup completed"
}

update_services() {
    log "Updating services to latest versions..."
    docker-compose -f "$COMPOSE_FILE" pull
    docker-compose -f "$COMPOSE_FILE" up -d
    log "Update completed"
}

open_shell() {
    log "Opening shell in bridge container..."
    docker-compose -f "$COMPOSE_FILE" exec bridge-node sh
}

# Parse command line arguments
VERBOSE=false
QUIET=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_banner
            print_help
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        start)
            COMMAND="start"
            shift
            ;;
        dev)
            COMMAND="dev"
            shift
            ;;
        stop)
            COMMAND="stop"
            shift
            ;;
        restart)
            COMMAND="restart"
            shift
            ;;
        status)
            COMMAND="status"
            shift
            ;;
        logs)
            COMMAND="logs"
            SERVICE="$2"
            shift 2 || shift
            ;;
        health)
            COMMAND="health"
            shift
            ;;
        setup)
            COMMAND="setup"
            shift
            ;;
        clean)
            COMMAND="clean"
            shift
            ;;
        backup)
            COMMAND="backup"
            shift
            ;;
        update)
            COMMAND="update"
            shift
            ;;
        shell)
            COMMAND="shell"
            shift
            ;;
        *)
            error "Unknown command: $1"
            print_help
            exit 1
            ;;
    esac
done

# Main execution
if [[ "$QUIET" != "true" ]]; then
    print_banner
fi

case "${COMMAND:-start}" in
    start)
        start_production
        ;;
    dev)
        start_development
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$SERVICE"
        ;;
    health)
        check_health
        ;;
    setup)
        setup_environment
        ;;
    clean)
        clean_environment
        ;;
    backup)
        create_backup
        ;;
    update)
        update_services
        ;;
    shell)
        open_shell
        ;;
    *)
        error "Invalid command: $COMMAND"
        print_help
        exit 1
        ;;
esac
