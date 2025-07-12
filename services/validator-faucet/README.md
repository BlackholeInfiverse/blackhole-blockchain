# 🌍 Real-World Blockchain Faucet

A production-grade blockchain faucet system with enterprise features, real blockchain integration, and comprehensive admin controls.

## 🚀 Quick Start

### Prerequisites
- Go 1.19 or higher
- Access to a Blackhole blockchain node (optional at startup)

### Running the Faucet

**Option 1: Start without peer connection (recommended)**
```bash
# Start faucet and configure peer through admin panel
go run real_world_faucet.go
```

**Option 2: Start with immediate peer connection**
```bash
# Start with peer address for immediate connection
go run real_world_faucet.go <peer_address>

# Example:
go run real_world_faucet.go /ip4/192.168.0.86/tcp/3000/p2p/12D3KooWG5v7Kff6pcNjAyd9upk53d47vLADeD1DkKJ55mfsiwEL
```

### Using the Startup Scripts

**Windows:**
```cmd
run_faucet.bat
```

**Linux/Mac:**
```bash
chmod +x run_faucet.sh
./run_faucet.sh
```

## 🌐 Access Points

- **Web Interface**: http://localhost:8095
- **Admin Panel**: http://localhost:8095/admin
- **API Base**: http://localhost:8095/api/v1
- **Health Check**: http://localhost:8095/api/v1/health

## 🔧 Admin Panel Features

### Peer Connection Management
- **Dynamic peer address configuration**
- **Real-time connection status monitoring**
- **One-click connect/disconnect controls**
- **Live faucet balance display**

### System Monitoring
- **Real-time statistics dashboard**
- **Advanced analytics and metrics**
- **Connected peers monitoring**
- **Success rate tracking**

### API Authentication
- **API Key**: `real_world_admin_2024`
- **Header**: `X-API-Key: real_world_admin_2024`

## 📡 API Endpoints

### Public APIs
- `POST /api/v1/request` - Request tokens
- `GET /api/v1/balance/{address}` - Check balance
- `GET /api/v1/info` - Network information
- `GET /api/v1/stats` - Public statistics
- `GET /api/v1/history` - Request history
- `GET /api/v1/health` - Health check

### Admin APIs (Require API Key)
- `GET/POST /api/v1/admin/peer` - Manage peer addresses
- `GET/POST /api/v1/admin/connection` - Control connections
- `GET /api/v1/admin/config` - View configuration
- `GET /api/v1/admin/analytics` - Advanced analytics

## 🎯 Configuration

### Default Settings
- **Port**: 8095
- **Default Amount**: 1000 BHX
- **Amount Range**: 100-5000 BHX
- **Cooldown Period**: 15 minutes
- **Daily Limit**: 10 requests per address
- **IP Daily Limit**: 25 requests per IP
- **Max Balance**: 10,000 BHX

### Token Request Limits
- **Minimum**: 100 BHX
- **Maximum**: 5,000 BHX
- **Cooldown**: 15 minutes between requests
- **Daily Limit**: 10 requests per address

## 🔒 Security Features

- **Advanced rate limiting** (per address + per IP)
- **Input validation and sanitization**
- **API key authentication for admin functions**
- **CORS support for web integration**
- **Request logging and monitoring**

## 📊 Real-World Features

### Production Architecture
- **RESTful API design** with proper HTTP status codes
- **Middleware for logging and authentication**
- **Background monitoring services**
- **Real-time analytics engine**

### Enterprise Security
- **Multi-layer rate limiting**
- **Admin API with key authentication**
- **Input validation and error handling**
- **Professional logging and monitoring**

### Professional Interface
- **Modern, responsive web design**
- **Real-time data updates**
- **Professional animations and styling**
- **Comprehensive admin management panel**

## 🌍 Real-World Standards

This faucet follows industry best practices used by:
- **Ethereum Sepolia Faucet**
- **Polygon Mumbai Faucet**
- **Avalanche Fuji Faucet**
- **Other production blockchain faucets**

## 🛠️ Development

### File Structure
```
validator-faucet/
├── real_world_faucet.go    # Main production faucet
├── run_faucet.bat          # Windows startup script
├── run_faucet.sh           # Linux/Mac startup script
├── go.mod                  # Go module dependencies
└── README.md               # This documentation
```

### Adding Features
The faucet is designed with modular architecture for easy extension:
- Add new API endpoints in the router setup
- Extend analytics with new metrics
- Add new security features in the middleware
- Enhance the admin panel with additional controls

## 📈 Monitoring

### Health Checks
- **Blockchain connection status**
- **Faucet balance monitoring**
- **Request success rates**
- **System performance metrics**

### Analytics
- **Request volume tracking**
- **Success/failure rates**
- **Unique user metrics**
- **Token distribution analytics**

## 🚨 Troubleshooting

### Common Issues

**Connection Failed:**
- Verify the peer address format
- Check if the blockchain node is running
- Ensure network connectivity

**Low Faucet Balance:**
- Monitor the system address balance
- Check for excessive token distribution
- Review rate limiting settings

**API Authentication Errors:**
- Verify the API key is correct
- Check the X-API-Key header format
- Ensure admin endpoints are being used

## 📞 Support

For issues or questions:
1. Check the health endpoint: `/api/v1/health`
2. Review the admin panel for system status
3. Check the console logs for error messages
4. Verify blockchain node connectivity
