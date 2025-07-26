# BlackHole Bridge SDK - Troubleshooting Guide

## 🔧 Common Issues and Solutions

This guide covers common issues you might encounter when using the BlackHole Bridge SDK and their solutions.

## 🚀 Installation Issues

### Issue: Go Module Download Fails

**Symptoms:**
```bash
go: github.com/blackhole-network/bridge-sdk@latest: module github.com/blackhole-network/bridge-sdk: reading https://proxy.golang.org/github.com/blackhole-network/bridge-sdk/@latest: 404 Not Found
```

**Solutions:**
1. **Check Go version**: Ensure you're using Go 1.21 or higher
   ```bash
   go version
   ```

2. **Update Go modules**:
   ```bash
   go clean -modcache
   go mod download
   ```

3. **Use local development**:
   ```bash
   # Clone the repository locally
   git clone https://github.com/blackhole-network/bridge-sdk.git
   cd bridge-sdk
   go mod download
   ```

### Issue: Build Failures

**Symptoms:**
```bash
# command-line-arguments
./main.go:10:2: no required module provides package github.com/blackhole-network/bridge-sdk
```

**Solutions:**
1. **Initialize Go module**:
   ```bash
   go mod init your-project-name
   go mod tidy
   ```

2. **Check import paths**:
   ```go
   import (
       bridgesdk "github.com/blackhole-network/bridge-sdk"
       "github.com/blackhole-network/blackhole-blockchain/core/relay-chain/chain"
   )
   ```

## 🌐 Network Connection Issues

### Issue: RPC Connection Failures

**Symptoms:**
```
ERROR: Failed to connect to Ethereum RPC: dial tcp: lookup eth-mainnet.alchemyapi.io: no such host
```

**Solutions:**
1. **Check RPC URLs**:
   ```bash
   # Test Ethereum RPC
   curl -X POST https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
   
   # Test Solana RPC
   curl -X POST https://api.mainnet-beta.solana.com \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
   ```

2. **Verify API keys**:
   ```bash
   # Check environment variables
   echo $ETHEREUM_RPC_URL
   echo $SOLANA_RPC_URL
   ```

3. **Use alternative RPC providers**:
   ```env
   # Ethereum alternatives
   ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/YOUR_PROJECT_ID
   ETHEREUM_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY
   
   # Solana alternatives
   SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
   SOLANA_RPC_URL=https://solana-api.projectserum.com
   ```

### Issue: WebSocket Connection Drops

**Symptoms:**
```
WARN: WebSocket connection lost, attempting to reconnect...
ERROR: Max reconnection attempts reached
```

**Solutions:**
1. **Enable connection retry**:
   ```go
   config := &bridgesdk.Config{
       MaxRetries:    5,
       RetryDelay:    10 * time.Second,
       ReconnectEnabled: true,
   }
   ```

2. **Use HTTP fallback**:
   ```go
   config := &bridgesdk.Config{
       EthereumRPC: "https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY", // HTTP instead of WSS
       HTTPFallback: true,
   }
   ```

## 🗄️ Database Issues

### Issue: Database Lock Errors

**Symptoms:**
```
ERROR: database is locked
ERROR: unable to open database file
```

**Solutions:**
1. **Check file permissions**:
   ```bash
   ls -la ./data/bridge.db
   chmod 644 ./data/bridge.db
   ```

2. **Close existing connections**:
   ```bash
   # Find processes using the database
   lsof ./data/bridge.db
   
   # Kill processes if necessary
   pkill -f bridge-sdk
   ```

3. **Use different database path**:
   ```go
   config := &bridgesdk.Config{
       DatabasePath: "./data/bridge_" + time.Now().Format("20060102") + ".db",
   }
   ```

### Issue: Database Corruption

**Symptoms:**
```
ERROR: database disk image is malformed
ERROR: file is not a database
```

**Solutions:**
1. **Backup and restore**:
   ```bash
   # Backup current database
   cp ./data/bridge.db ./data/bridge.db.backup
   
   # Remove corrupted database
   rm ./data/bridge.db
   
   # Restart bridge (will create new database)
   go run main.go
   ```

2. **Use PostgreSQL for production**:
   ```go
   config := &bridgesdk.Config{
       DatabaseType: "postgres",
       DatabaseURL:  "postgres://user:pass@localhost/bridge_db",
   }
   ```

## 🔐 Security Issues

### Issue: Private Key Errors

**Symptoms:**
```
ERROR: invalid private key format
ERROR: private key not found
```

**Solutions:**
1. **Validate private key format**:
   ```bash
   # Ethereum private key should be 64 hex characters
   echo $ETHEREUM_PRIVATE_KEY | wc -c  # Should be 65 (including newline)
   
   # Remove 0x prefix if present
   ETHEREUM_PRIVATE_KEY=${ETHEREUM_PRIVATE_KEY#0x}
   ```

2. **Use environment variables**:
   ```bash
   # Set in .env file
   echo "ETHEREUM_PRIVATE_KEY=your_private_key_here" >> .env
   echo "SOLANA_PRIVATE_KEY=your_solana_private_key_here" >> .env
   
   # Load environment
   source .env
   ```

3. **Test key validity**:
   ```go
   // Test Ethereum private key
   privateKey, err := crypto.HexToECDSA(ethereumPrivateKey)
   if err != nil {
       log.Fatal("Invalid Ethereum private key:", err)
   }
   ```

### Issue: Replay Protection Errors

**Symptoms:**
```
ERROR: duplicate transaction detected
WARN: replay protection cache full
```

**Solutions:**
1. **Clear replay protection cache**:
   ```bash
   # Delete replay protection data
   rm -rf ./data/replay_protection/
   ```

2. **Increase cache size**:
   ```go
   config := &bridgesdk.Config{
       ReplayProtectionCacheSize: 50000,
       ReplayProtectionTTL:       48 * time.Hour,
   }
   ```

## 📊 Performance Issues

### Issue: High Memory Usage

**Symptoms:**
```
WARN: Memory usage high: 2.5GB
ERROR: out of memory
```

**Solutions:**
1. **Optimize batch size**:
   ```go
   config := &bridgesdk.Config{
       BatchSize:    50,  // Reduce from default 100
       MaxConcurrency: 5, // Limit concurrent operations
   }
   ```

2. **Enable garbage collection**:
   ```go
   import "runtime/debug"
   
   // Force garbage collection periodically
   go func() {
       ticker := time.NewTicker(5 * time.Minute)
       for range ticker.C {
           debug.FreeOSMemory()
       }
   }()
   ```

3. **Monitor memory usage**:
   ```bash
   # Check memory usage
   ps aux | grep bridge-sdk
   
   # Use memory profiling
   go tool pprof http://localhost:8084/debug/pprof/heap
   ```

### Issue: Slow Transaction Processing

**Symptoms:**
```
WARN: Transaction processing taking longer than expected
INFO: Average processing time: 45s
```

**Solutions:**
1. **Optimize RPC connections**:
   ```go
   config := &bridgesdk.Config{
       EthereumRPC: "wss://eth-mainnet.alchemyapi.io/v2/YOUR_KEY", // Use WebSocket
       ConnectionPoolSize: 10,
       RequestTimeout: 30 * time.Second,
   }
   ```

2. **Increase concurrency**:
   ```go
   config := &bridgesdk.Config{
       MaxConcurrency: 10,
       WorkerPoolSize: 20,
   }
   ```

3. **Use faster RPC providers**:
   ```env
   # Use premium RPC endpoints
   ETHEREUM_RPC_URL=wss://eth-mainnet.alchemyapi.io/v2/YOUR_KEY
   SOLANA_RPC_URL=wss://api.mainnet-beta.solana.com
   ```

## 🔄 Circuit Breaker Issues

### Issue: Circuit Breaker Stuck Open

**Symptoms:**
```
ERROR: Circuit breaker open for ethereum_listener
WARN: All requests being rejected
```

**Solutions:**
1. **Manual circuit breaker reset**:
   ```bash
   curl -X POST http://localhost:8084/circuit-breakers/reset \
     -H "Content-Type: application/json" \
     -d '{"component": "ethereum_listener"}'
   ```

2. **Adjust circuit breaker settings**:
   ```go
   config := &bridgesdk.Config{
       CircuitBreakerThreshold: 10,    // Increase threshold
       CircuitBreakerTimeout:   30 * time.Second, // Reduce timeout
   }
   ```

3. **Check underlying issues**:
   ```bash
   # Check RPC connectivity
   curl -s https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY
   
   # Check logs for root cause
   tail -f ./logs/bridge.log | grep ERROR
   ```

## 🐳 Docker Issues

### Issue: Docker Container Won't Start

**Symptoms:**
```
ERROR: failed to start container
ERROR: port already in use
```

**Solutions:**
1. **Check port conflicts**:
   ```bash
   # Check what's using port 8084
   netstat -tulpn | grep 8084
   lsof -i :8084
   
   # Kill conflicting processes
   sudo kill -9 $(lsof -t -i:8084)
   ```

2. **Use different ports**:
   ```bash
   # Change port in docker-compose.yml
   ports:
     - "8085:8084"  # Use port 8085 instead
   ```

3. **Clean Docker state**:
   ```bash
   # Stop all containers
   docker-compose down
   
   # Remove volumes
   docker-compose down -v
   
   # Clean system
   docker system prune -f
   ```

### Issue: Docker Build Failures

**Symptoms:**
```
ERROR: failed to solve: process "/bin/sh -c go build" did not complete successfully
```

**Solutions:**
1. **Check Dockerfile**:
   ```dockerfile
   # Ensure proper Go version
   FROM golang:1.21-alpine AS builder
   
   # Add build dependencies
   RUN apk add --no-cache git gcc musl-dev
   ```

2. **Clear build cache**:
   ```bash
   docker-compose build --no-cache
   ```

3. **Check available disk space**:
   ```bash
   df -h
   docker system df
   ```

## 📝 Logging Issues

### Issue: No Logs Appearing

**Symptoms:**
```
# No output in terminal or log files
```

**Solutions:**
1. **Check log level**:
   ```go
   config := &bridgesdk.Config{
       LogLevel: "debug", // Change from "error" to "debug"
   }
   ```

2. **Verify log file permissions**:
   ```bash
   mkdir -p ./logs
   chmod 755 ./logs
   touch ./logs/bridge.log
   chmod 644 ./logs/bridge.log
   ```

3. **Enable console logging**:
   ```go
   config := &bridgesdk.Config{
       LogToConsole: true,
       LogToFile:    true,
   }
   ```

## 🔍 Debugging Tools

### Enable Debug Mode

```go
config := &bridgesdk.Config{
    LogLevel:     "debug",
    DebugMode:    true,
    EnablePprof:  true, // Enable profiling
}
```

### Health Check Commands

```bash
# Check overall health
curl http://localhost:8084/health

# Check specific components
curl http://localhost:8084/circuit-breakers
curl http://localhost:8084/errors
curl http://localhost:8084/stats
```

### Log Analysis

```bash
# Follow logs in real-time
tail -f ./logs/bridge.log

# Search for errors
grep ERROR ./logs/bridge.log

# Count error types
grep ERROR ./logs/bridge.log | cut -d' ' -f4 | sort | uniq -c
```

### Performance Profiling

```bash
# CPU profiling
go tool pprof http://localhost:8084/debug/pprof/profile

# Memory profiling
go tool pprof http://localhost:8084/debug/pprof/heap

# Goroutine profiling
go tool pprof http://localhost:8084/debug/pprof/goroutine
```

## 🆘 Getting Help

### Before Asking for Help

1. **Check logs** for error messages
2. **Verify configuration** settings
3. **Test network connectivity** to RPC endpoints
4. **Check system resources** (CPU, memory, disk)
5. **Review recent changes** to your setup

### Information to Include

When reporting issues, please include:

- **Bridge SDK version**
- **Go version** (`go version`)
- **Operating system** and version
- **Configuration** (sanitized, no private keys)
- **Error messages** and logs
- **Steps to reproduce** the issue

### Support Channels

- 📧 **Email**: support@blackhole.network
- 💬 **Discord**: [BlackHole Community](https://discord.gg/blackhole)
- 🐛 **GitHub Issues**: [Report bugs](https://github.com/blackhole-network/bridge-sdk/issues)
- 📖 **Documentation**: [docs.blackhole.network](https://docs.blackhole.network)

---

This troubleshooting guide covers the most common issues. For additional help, please refer to the support channels above.
