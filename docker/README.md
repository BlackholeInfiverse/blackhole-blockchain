# BlackHole Bridge SDK Docker Setup

## Quick Start

### Single Command Execution

```bash
# From the project root directory
cd docker
docker-compose up
```

### Alternative Commands

```bash
# Build and run in detached mode
docker-compose up -d

# View logs
docker-compose logs -f bridge-sdk

# Stop the service
docker-compose down

# Rebuild and restart
docker-compose up --build
```

## Access

- **Bridge SDK Dashboard**: http://localhost:8084
- **Health Check**: http://localhost:8084/health
- **API Documentation**: http://localhost:8084/docs

## Configuration

Edit the `.env` file to customize:
- Log levels
- Security features
- RPC endpoints
- Retry settings

## Data Persistence

- Database: Stored in `bridge_data` Docker volume
- Logs: Stored in `bridge_logs` Docker volume

## Requirements

- Docker
- Docker Compose
- 2GB RAM minimum
- Port 8084 available
