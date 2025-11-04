# Blackhole Wallet Service - Quick Start Guide

## 🚀 Quick Start (Local Development - BadgerDB Only)

The wallet service now supports multiple storage backends with graceful fallbacks:
- **PostgreSQL** - Primary relational database (optional)
- **Redis** - Caching layer (optional)
- **BadgerDB** - Embedded key-value store (always available, fallback)
- **MongoDB** - Legacy support (being phased out)

### Prerequisites

- Go 1.24 or higher
- Windows PowerShell 5.1+

### Option 1: Run with BadgerDB Only (Recommended for Quick Testing)

This mode requires NO external databases - everything runs in-memory with BadgerDB.

```powershell
# 1. Build the service
go build -o wallet-service.exe .

# 2. Run the wallet service (web UI mode)
.\wallet-service.exe -web -port 9000

# 3. Open your browser
# Navigate to: http://localhost:9000
```

The service will automatically:
- ✅ Use in-memory BadgerDB for storage
- ✅ Connect to MongoDB for legacy data
- ⊗ Skip PostgreSQL and Redis (not required)

### Option 2: Run with Full Stack (PostgreSQL + Redis + BadgerDB)

For production-like testing with all storage layers:

```powershell
# 1. Start the development databases
docker-compose -f docker-compose.dev.yml up -d

# 2. Wait for services to be healthy
docker-compose -f docker-compose.dev.yml ps

# 3. Build and run
go build -o wallet-service.exe .
.\wallet-service.exe -web -port 9000
```

The service will automatically detect and use all available storage backends.

## 🧪 Running Tests

### Automated Integration Tests

```powershell
# 1. Start the wallet service in another terminal
.\wallet-service.exe -web -port 9000

# 2. Run the test script
.\test-wallet-service.ps1
```

### Manual Testing via Web UI

1. **Start the service:**
   ```powershell
   .\wallet-service.exe -web -port 9000
   ```

2. **Open browser:** http://localhost:9000

3. **Test workflow:**
   - Register a new user
   - Login
   - Create a wallet
   - View wallet details
   - Check balance (requires blockchain connection)

### Check Service Status

```powershell
# Using curl or Invoke-RestMethod
Invoke-RestMethod -Uri "http://localhost:9000/api/status" -Method GET | ConvertTo-Json
```

Expected response:
```json
{
  "success": true,
  "message": "Service status retrieved successfully",
  "data": {
    "service": "blackhole-wallet",
    "version": "2.0.0",
    "status": "running",
    "blockchain_connected": false,
    "storage_system": {
      "postgresql_available": false,
      "redis_available": false,
      "badgerdb_available": true,
      "health_details": {...}
    }
  }
}
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file (or use `.env.local` for local development):

```bash
# Application
APP_ENV=development
APP_PORT=9000

# Storage Mode
STORAGE_MODE=badger-only   # or "hybrid" for full stack

# BadgerDB (In-Memory Mode for Development)
BADGER_PATH=./data/badger
BADGER_IN_MEMORY=true
BADGER_ENCRYPTION=false

# PostgreSQL (Optional)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=blackhole_wallet
POSTGRES_USER=postgres
POSTGRES_PASSWORD=wallet_dev_password_2025

# Redis (Optional)
REDIS_ADDRESS=localhost:6379
REDIS_PASSWORD=wallet_redis_password_2025
```

### Blockchain Connection

To enable blockchain features (balance checking, transactions):

```powershell
.\wallet-service.exe -web -port 9000 -peerAddr "/ip4/127.0.0.1/tcp/3000/p2p/YOUR_PEER_ID"
```

## 📊 Storage Architecture

### Current Implementation

```
┌─────────────────────────────────────────┐
│         Wallet Service API              │
└──────────────┬──────────────────────────┘
               │
       ┌───────┴────────┐
       │                │
   ┌───▼───┐     ┌─────▼──────┐
   │MongoDB│     │   Storage   │
   │(Legacy)│     │   Manager   │
   └───────┘     └──────┬──────┘
                        │
          ┌─────────────┼─────────────┐
          │             │             │
     ┌────▼────┐   ┌────▼────┐  ┌────▼──────┐
     │PostgreSQL│   │  Redis  │  │  BadgerDB │
     │(Primary)│   │ (Cache) │  │ (Fallback)│
     └─────────┘   └─────────┘  └───────────┘
```

### Fallback Logic

1. Try PostgreSQL → If unavailable, use BadgerDB
2. Try Redis for caching → If unavailable, skip caching
3. BadgerDB always available as fallback

## 🐳 Docker Development Environment

### Start Full Stack

```powershell
docker-compose -f docker-compose.dev.yml up -d
```

This starts:
- PostgreSQL (port 5432)
- Redis (port 6379)
- pgAdmin (port 5050) - Optional admin UI

### Access pgAdmin

1. Open: http://localhost:5050
2. Login:
   - Email: `admin@blackhole.local`
   - Password: `admin_password_2025`
3. Add server:
   - Host: `postgres`
   - Port: `5432`
   - Database: `blackhole_wallet`
   - Username: `postgres`
   - Password: `wallet_dev_password_2025`

### Stop Services

```powershell
docker-compose -f docker-compose.dev.yml down
```

## 🎯 API Endpoints

### New Endpoints (v2.0)

- `GET /api/status` - Service health and storage status
- `GET /api/user` - Current authenticated user info

### Existing Endpoints

- `POST /api/register` - Register new user
- `POST /api/login` - User authentication
- `POST /api/logout` - End session
- `GET /api/wallets` - List user wallets
- `POST /api/wallets/create` - Create new wallet
- `POST /api/wallets/balance` - Check balance
- `POST /api/wallets/transfer` - Transfer tokens
- `POST /api/wallets/stake` - Stake tokens
- And more... (see API_ENDPOINTS_ADDED.md)

## 🔍 Troubleshooting

### Service won't start

```powershell
# Check if port 9000 is already in use
netstat -ano | findstr :9000

# Try a different port
.\wallet-service.exe -web -port 9001
```

### BadgerDB errors

```powershell
# Clear BadgerDB data
Remove-Item -Recurse -Force ./data/badger

# Restart service
.\wallet-service.exe -web
```

### MongoDB connection issues

The service will continue to work with BadgerDB even if MongoDB is unavailable. Check connection string in code or use environment variables.

## 📚 Next Steps

- [ ] Read MIGRATION_GUIDE.md for production deployment
- [ ] Review API_ENDPOINTS_ADDED.md for API documentation
- [ ] Configure blockchain peer address for full functionality
- [ ] Set up PostgreSQL and Redis for production use

## 🆘 Getting Help

- Check logs: Service outputs detailed logs to console
- Review health status: `GET /api/status`
- Test script: `.\test-wallet-service.ps1`
- Documentation: See `docs/` directory (coming soon)

---

**Version:** 2.0.0
**Last Updated:** 2025-10-09
