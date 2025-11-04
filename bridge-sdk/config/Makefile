# BlackHole Bridge Makefile
# ========================

.PHONY: help build start stop restart logs clean test dev prod backup restore quick-start deploy-local deploy-dev deploy-staging deploy-prod

# Default target
help: ## Show this help message
	@echo "🌉 BlackHole Bridge - Available Commands:"
	@echo "=========================================="
	@echo ""
	@echo "🚀 ONE-LINER DEPLOYMENTS:"
	@echo "  quick-start     - Ultimate one-command deployment (local)"
	@echo "  deploy-local    - Deploy locally with full stack"
	@echo "  deploy-dev      - Deploy development environment (testnets)"
	@echo "  deploy-staging  - Deploy staging environment"
	@echo "  deploy-prod     - Deploy production environment"
	@echo ""
	@echo "🔧 DEVELOPMENT COMMANDS:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# 🚀 ONE-LINER DEPLOYMENT COMMANDS
quick-start: ## Ultimate one-command deployment (local)
	@echo "🚀 BlackHole Bridge - Ultimate One-Liner Deployment"
	@echo "===================================================="
	@chmod +x deploy-one-liner.sh
	@./deploy-one-liner.sh local

deploy-local: ## Deploy locally with full stack
	@echo "🏠 Deploying locally..."
	@chmod +x deploy-one-liner.sh
	@./deploy-one-liner.sh local

deploy-dev: ## Deploy development environment (testnets)
	@echo "🧪 Deploying development environment..."
	@chmod +x deploy-one-liner.sh
	@./deploy-one-liner.sh dev

deploy-staging: ## Deploy staging environment
	@echo "🎭 Deploying staging environment..."
	@chmod +x deploy-one-liner.sh
	@./deploy-one-liner.sh staging

deploy-prod: ## Deploy production environment
	@echo "🏭 Deploying production environment..."
	@chmod +x deploy-one-liner.sh
	@./deploy-one-liner.sh prod

# Environment setup
setup: ## Initial setup and environment preparation
	@echo "Setting up BlackHole Bridge environment..."
	@cp .env.example .env 2>/dev/null || echo ".env already exists"
	@mkdir -p data logs monitoring/grafana/dashboards monitoring/grafana/datasources nginx/ssl
	@echo "Environment setup complete!"

# Build commands
build: ## Build the bridge application
	@echo "Building BlackHole Bridge..."
	@docker-compose build --no-cache

build-dev: ## Build development version
	@echo "Building development version..."
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml build

# Start commands
start: ## Start the bridge in production mode
	@echo "Starting BlackHole Bridge (Production)..."
	@docker-compose up -d
	@echo "Bridge started! Dashboard: http://localhost:8084"
	@echo "Monitoring: http://localhost:3000 (admin/admin123)"

dev: ## Start in development mode with hot reload
	@echo "Starting BlackHole Bridge (Development)..."
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
	@echo "Development server started with hot reload!"

prod: ## Start in production mode (alias for start)
	@make start

# Stop commands
stop: ## Stop all services
	@echo "Stopping BlackHole Bridge..."
	@docker-compose down

stop-dev: ## Stop development services
	@echo "Stopping development services..."
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml down

# Restart commands
restart: ## Restart all services
	@make stop
	@make start

restart-dev: ## Restart development services
	@make stop-dev
	@make dev

# Logs commands
logs: ## Show logs from all services
	@docker-compose logs -f

logs-bridge: ## Show logs from bridge service only
	@docker-compose logs -f bridge-node

logs-db: ## Show database logs
	@docker-compose logs -f postgres

logs-redis: ## Show Redis logs
	@docker-compose logs -f redis

# Status commands
status: ## Show status of all services
	@docker-compose ps

health: ## Check health of all services
	@echo "Checking service health..."
	@curl -s http://localhost:8084/health | jq . || echo "Bridge service not responding"
	@docker-compose exec redis redis-cli ping || echo "Redis not responding"
	@docker-compose exec postgres pg_isready -U bridge || echo "PostgreSQL not responding"

# Database commands
db-migrate: ## Run database migrations
	@echo "Running database migrations..."
	@docker-compose exec postgres psql -U bridge -d bridge_db -f /docker-entrypoint-initdb.d/init-db.sql

db-backup: ## Backup database
	@echo "Creating database backup..."
	@mkdir -p backups
	@docker-compose exec postgres pg_dump -U bridge bridge_db > backups/bridge_backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "Backup created in backups/ directory"

db-restore: ## Restore database from backup (specify BACKUP_FILE=filename)
	@echo "Restoring database from $(BACKUP_FILE)..."
	@docker-compose exec -T postgres psql -U bridge -d bridge_db < $(BACKUP_FILE)

db-shell: ## Connect to database shell
	@docker-compose exec postgres psql -U bridge -d bridge_db

# Testing commands
test: ## Run tests
	@echo "Running tests..."
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm test-runner

test-unit: ## Run unit tests only
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm test-runner go test -short ./...

test-integration: ## Run integration tests
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm test-runner go test -tags=integration ./...

test-coverage: ## Run tests with coverage
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm test-runner go test -coverprofile=coverage.out ./...
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml run --rm test-runner go tool cover -html=coverage.out -o coverage.html

# Maintenance commands
clean: ## Clean up containers, volumes, and images
	@echo "Cleaning up..."
	@docker-compose down -v --remove-orphans
	@docker system prune -f
	@docker volume prune -f

clean-all: ## Clean everything including images
	@echo "Cleaning everything..."
	@docker-compose down -v --remove-orphans --rmi all
	@docker system prune -af
	@docker volume prune -f

update: ## Update all services to latest versions
	@echo "Updating services..."
	@docker-compose pull
	@docker-compose up -d

# Monitoring commands
monitor: ## Open monitoring dashboard
	@echo "Opening monitoring dashboard..."
	@open http://localhost:3000 || xdg-open http://localhost:3000 || echo "Please open http://localhost:3000"

dashboard: ## Open bridge dashboard
	@echo "Opening bridge dashboard..."
	@open http://localhost:8084 || xdg-open http://localhost:8084 || echo "Please open http://localhost:8084"

# Security commands
security-scan: ## Run security scan on containers
	@echo "Running security scan..."
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image blackhole-bridge_bridge-node

# Backup and restore
backup: ## Create full backup of data and configuration
	@echo "Creating full backup..."
	@mkdir -p backups/$(shell date +%Y%m%d_%H%M%S)
	@docker-compose exec postgres pg_dump -U bridge bridge_db > backups/$(shell date +%Y%m%d_%H%M%S)/database.sql
	@docker run --rm -v bridge-data:/data -v $(PWD)/backups/$(shell date +%Y%m%d_%H%M%S):/backup alpine tar czf /backup/bridge-data.tar.gz -C /data .
	@docker run --rm -v bridge-logs:/logs -v $(PWD)/backups/$(shell date +%Y%m%d_%H%M%S):/backup alpine tar czf /backup/bridge-logs.tar.gz -C /logs .
	@echo "Backup completed in backups/$(shell date +%Y%m%d_%H%M%S)/"

restore: ## Restore from backup (specify BACKUP_DIR=directory)
	@echo "Restoring from $(BACKUP_DIR)..."
	@docker-compose down
	@docker run --rm -v bridge-data:/data -v $(PWD)/$(BACKUP_DIR):/backup alpine tar xzf /backup/bridge-data.tar.gz -C /data
	@docker run --rm -v bridge-logs:/logs -v $(PWD)/$(BACKUP_DIR):/backup alpine tar xzf /backup/bridge-logs.tar.gz -C /logs
	@docker-compose up -d postgres redis
	@sleep 10
	@docker-compose exec -T postgres psql -U bridge -d bridge_db < $(BACKUP_DIR)/database.sql
	@docker-compose up -d
	@echo "Restore completed!"

# Development helpers
shell: ## Open shell in bridge container
	@docker-compose exec bridge-node sh

shell-db: ## Open shell in database container
	@docker-compose exec postgres bash

shell-redis: ## Open shell in Redis container
	@docker-compose exec redis sh

# Quick start command
quick-start: setup build start ## Complete setup and start (one command deployment)
	@echo ""
	@echo "🚀 BlackHole Bridge is now running!"
	@echo "=================================="
	@echo "📊 Dashboard: http://localhost:8084"
	@echo "📈 Monitoring: http://localhost:3000 (admin/admin123)"
	@echo "🔍 Logs: make logs"
	@echo "❤️  Health: make health"
	@echo ""
	@echo "Use 'make help' to see all available commands"
