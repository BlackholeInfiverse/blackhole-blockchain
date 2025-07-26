# BlackHole Bridge SDK - Developer Guide

## 👨‍💻 Developer Integration Guide

This guide provides comprehensive instructions for BlackHole developers to integrate and use the Bridge SDK in their applications.

## 📦 Installation & Setup

### Prerequisites

```bash
# Go 1.21 or higher
go version

# Git for version control
git --version

# Optional: Docker for containerized development
docker --version
```

### Adding Bridge SDK to Your Project

```bash
# Initialize your Go module (if not already done)
go mod init your-project-name

# Add the Bridge SDK dependency
go get github.com/blackhole-network/bridge-sdk

# Download dependencies
go mod download
```

### Project Structure

```
your-project/
├── main.go                 # Your main application
├── config/                 # Configuration files
├── handlers/               # Custom event handlers
├── middleware/             # Custom middleware
├── go.mod                  # Go module file
└── go.sum                  # Go dependencies
```

## 🚀 Quick Integration

### Basic Bridge Integration

```go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"
    
    bridgesdk "github.com/blackhole-network/bridge-sdk"
    "github.com/blackhole-network/blackhole-blockchain/core/relay-chain/chain"
)

func main() {
    // Initialize BlackHole blockchain
    blockchain := chain.NewBlockchain()
    
    // Create bridge SDK instance
    sdk := bridgesdk.NewBridgeSDK(blockchain, nil)
    
    // Setup graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // Start blockchain listeners
    go func() {
        if err := sdk.StartEthereumListener(ctx); err != nil {
            log.Printf("Ethereum listener error: %v", err)
        }
    }()
    
    go func() {
        if err := sdk.StartSolanaListener(ctx); err != nil {
            log.Printf("Solana listener error: %v", err)
        }
    }()
    
    // Start web server
    go func() {
        log.Println("Starting web server on :8084")
        if err := sdk.StartWebServer(":8084"); err != nil {
            log.Printf("Web server error: %v", err)
        }
    }()
    
    // Wait for interrupt signal
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan
    
    log.Println("Shutting down bridge...")
    cancel()
}
```

### Advanced Configuration

```go
package main

import (
    "context"
    "log"
    "time"
    
    bridgesdk "github.com/blackhole-network/bridge-sdk"
    "github.com/blackhole-network/blackhole-blockchain/core/relay-chain/chain"
)

func main() {
    // Create custom configuration
    config := &bridgesdk.Config{
        // Blockchain RPC endpoints
        EthereumRPC: "wss://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY",
        SolanaRPC:   "wss://api.mainnet-beta.solana.com",
        
        // Database configuration
        DatabasePath: "./data/bridge.db",
        
        // Logging configuration
        LogLevel: "info",
        LogFile:  "./logs/bridge.log",
        
        // Performance settings
        MaxRetries:    3,
        RetryDelay:    5 * time.Second,
        BatchSize:     100,
        
        // Security settings
        ReplayProtectionEnabled: true,
        CircuitBreakerEnabled:   true,
    }
    
    // Initialize blockchain
    blockchain := chain.NewBlockchain()
    
    // Create bridge SDK with custom config
    sdk := bridgesdk.NewBridgeSDK(blockchain, config)
    
    // Setup custom event handlers
    setupEventHandlers(sdk)
    
    // Start services
    ctx := context.Background()
    startServices(ctx, sdk)
}

func setupEventHandlers(sdk *bridgesdk.BridgeSDK) {
    // Ethereum event handler
    sdk.OnEthereumEvent(func(event *bridgesdk.EthereumEvent) {
        log.Printf("Ethereum event received: %+v", event)
        
        // Custom processing logic
        if event.EventType == "Transfer" {
            handleTransferEvent(event)
        }
    })
    
    // Solana event handler
    sdk.OnSolanaEvent(func(event *bridgesdk.SolanaEvent) {
        log.Printf("Solana event received: %+v", event)
        
        // Custom processing logic
        if event.ProgramID == "YourProgramID" {
            handleSolanaProgram(event)
        }
    })
    
    // Error handler
    sdk.OnError(func(err error) {
        log.Printf("Bridge error: %v", err)
        
        // Custom error handling
        handleBridgeError(err)
    })
}

func handleTransferEvent(event *bridgesdk.EthereumEvent) {
    // Implement your custom transfer logic
    log.Printf("Processing transfer: %s", event.TxHash)
}

func handleSolanaProgram(event *bridgesdk.SolanaEvent) {
    // Implement your custom Solana program logic
    log.Printf("Processing Solana program: %s", event.Signature)
}

func handleBridgeError(err error) {
    // Implement your custom error handling
    // Send alerts, log to external systems, etc.
}

func startServices(ctx context.Context, sdk *bridgesdk.BridgeSDK) {
    // Start listeners
    go sdk.StartEthereumListener(ctx)
    go sdk.StartSolanaListener(ctx)
    
    // Start web server
    go sdk.StartWebServer(":8084")
    
    // Keep running
    select {}
}
```

## 🔧 Core SDK Methods

### Bridge Management

```go
// Initialize bridge SDK
sdk := bridgesdk.NewBridgeSDK(blockchain, config)

// Start blockchain listeners
err := sdk.StartEthereumListener(ctx)
err := sdk.StartSolanaListener(ctx)

// Stop listeners
sdk.StopListeners()

// Start web server
err := sdk.StartWebServer(":8084")
```

### Transaction Operations

```go
// Manual relay to specific chain
err := sdk.RelayToChain(transaction, "ethereum")
err := sdk.RelayToChain(transaction, "solana")
err := sdk.RelayToChain(transaction, "blackhole")

// Get transaction status
status, err := sdk.GetTransactionStatus("tx_hash")

// Get all transactions
transactions, err := sdk.GetAllTransactions()

// Get transactions by status
pending, err := sdk.GetTransactionsByStatus("pending")
completed, err := sdk.GetTransactionsByStatus("completed")
failed, err := sdk.GetTransactionsByStatus("failed")
```

### Monitoring & Statistics

```go
// Get bridge statistics
stats := sdk.GetBridgeStats()
log.Printf("Total transactions: %d", stats.TotalTransactions)
log.Printf("Success rate: %.2f%%", stats.SuccessRate)

// Get health status
health := sdk.GetHealth()
log.Printf("System healthy: %t", health.Healthy)

// Get error metrics
errors := sdk.GetErrorMetrics()
log.Printf("Error rate: %.2f%%", errors.ErrorRate)
```

## 🎯 Custom Event Handlers

### Ethereum Event Handler

```go
sdk.OnEthereumEvent(func(event *bridgesdk.EthereumEvent) {
    switch event.EventType {
    case "Transfer":
        handleEthereumTransfer(event)
    case "Approval":
        handleEthereumApproval(event)
    case "BridgeDeposit":
        handleBridgeDeposit(event)
    default:
        log.Printf("Unknown Ethereum event: %s", event.EventType)
    }
})

func handleEthereumTransfer(event *bridgesdk.EthereumEvent) {
    // Extract transfer details
    from := event.Data["from"].(string)
    to := event.Data["to"].(string)
    amount := event.Data["amount"].(string)
    
    log.Printf("Transfer: %s -> %s, Amount: %s", from, to, amount)
    
    // Custom business logic
    if isBlackHoleAddress(to) {
        // Handle bridge deposit
        processBridgeDeposit(from, amount, event.TxHash)
    }
}
```

### Solana Event Handler

```go
sdk.OnSolanaEvent(func(event *bridgesdk.SolanaEvent) {
    switch event.InstructionType {
    case "Transfer":
        handleSolanaTransfer(event)
    case "BridgeWithdraw":
        handleBridgeWithdraw(event)
    default:
        log.Printf("Unknown Solana event: %s", event.InstructionType)
    }
})

func handleSolanaTransfer(event *bridgesdk.SolanaEvent) {
    // Extract Solana transfer details
    source := event.Accounts[0]
    destination := event.Accounts[1]
    amount := event.Data["amount"].(uint64)
    
    log.Printf("Solana Transfer: %s -> %s, Amount: %d", source, destination, amount)
    
    // Custom business logic
    if isBridgeAccount(destination) {
        // Handle bridge deposit
        processSolanaBridgeDeposit(source, amount, event.Signature)
    }
}
```

### Custom Relay Logic

```go
// Set custom relay handler
sdk.SetRelayHandler(func(tx *bridgesdk.Transaction) error {
    // Custom validation
    if err := validateTransaction(tx); err != nil {
        return err
    }
    
    // Custom fee calculation
    fee := calculateCustomFee(tx)
    tx.Fee = fee
    
    // Custom routing logic
    targetChain := determineTargetChain(tx)
    
    // Execute relay
    return sdk.StandardRelay(tx, targetChain)
})

func validateTransaction(tx *bridgesdk.Transaction) error {
    // Implement custom validation logic
    if tx.Amount.Cmp(big.NewInt(0)) <= 0 {
        return errors.New("invalid amount")
    }
    
    if !isValidAddress(tx.ToAddress) {
        return errors.New("invalid destination address")
    }
    
    return nil
}

func calculateCustomFee(tx *bridgesdk.Transaction) *big.Int {
    // Implement custom fee calculation
    baseFee := big.NewInt(1000) // Base fee in wei
    
    // Add percentage fee
    percentageFee := new(big.Int).Div(tx.Amount, big.NewInt(1000)) // 0.1%
    
    return new(big.Int).Add(baseFee, percentageFee)
}
```

## 🔒 Security Best Practices

### Private Key Management

```go
// Use environment variables for private keys
ethereumPrivateKey := os.Getenv("ETHEREUM_PRIVATE_KEY")
solanaPrivateKey := os.Getenv("SOLANA_PRIVATE_KEY")

// Validate private keys
if ethereumPrivateKey == "" {
    log.Fatal("ETHEREUM_PRIVATE_KEY environment variable required")
}

// Use secure key storage in production
config := &bridgesdk.Config{
    EthereumPrivateKey: ethereumPrivateKey,
    SolanaPrivateKey:   solanaPrivateKey,
}
```

### Input Validation

```go
func validateBridgeRequest(req *BridgeRequest) error {
    // Validate amount
    if req.Amount.Cmp(big.NewInt(0)) <= 0 {
        return errors.New("amount must be positive")
    }
    
    // Validate addresses
    if !isValidEthereumAddress(req.FromAddress) {
        return errors.New("invalid Ethereum address")
    }
    
    if !isValidSolanaAddress(req.ToAddress) {
        return errors.New("invalid Solana address")
    }
    
    // Validate amount limits
    minAmount := big.NewInt(1000000) // 0.001 ETH
    maxAmount := big.NewInt(1000000000000000000) // 1 ETH
    
    if req.Amount.Cmp(minAmount) < 0 {
        return errors.New("amount below minimum")
    }
    
    if req.Amount.Cmp(maxAmount) > 0 {
        return errors.New("amount above maximum")
    }
    
    return nil
}
```

## 📊 Monitoring Integration

### Custom Metrics

```go
// Add custom metrics
sdk.AddMetric("custom_transactions_total", func() float64 {
    return float64(getCustomTransactionCount())
})

sdk.AddMetric("custom_success_rate", func() float64 {
    return calculateCustomSuccessRate()
})

// Export metrics to external systems
sdk.OnMetricsUpdate(func(metrics map[string]float64) {
    // Send to external monitoring system
    sendToDatadog(metrics)
    sendToNewRelic(metrics)
})
```

### Health Checks

```go
// Add custom health checks
sdk.AddHealthCheck("database", func() bool {
    return isDatabaseHealthy()
})

sdk.AddHealthCheck("external_api", func() bool {
    return isExternalAPIHealthy()
})

// Custom health check endpoint
http.HandleFunc("/custom-health", func(w http.ResponseWriter, r *http.Request) {
    health := sdk.GetHealth()
    
    if health.Healthy {
        w.WriteHeader(http.StatusOK)
    } else {
        w.WriteHeader(http.StatusServiceUnavailable)
    }
    
    json.NewEncoder(w).Encode(health)
})
```

## 🧪 Testing

### Unit Testing

```go
package main

import (
    "testing"
    "context"
    
    bridgesdk "github.com/blackhole-network/bridge-sdk"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

func TestBridgeSDK(t *testing.T) {
    // Create test configuration
    config := &bridgesdk.Config{
        DatabasePath: ":memory:",
        LogLevel:     "debug",
    }
    
    // Create mock blockchain
    mockBlockchain := &MockBlockchain{}
    
    // Initialize SDK
    sdk := bridgesdk.NewBridgeSDK(mockBlockchain, config)
    
    // Test initialization
    assert.NotNil(t, sdk)
    
    // Test configuration
    assert.Equal(t, "debug", sdk.GetConfig().LogLevel)
}

func TestTransactionRelay(t *testing.T) {
    sdk := setupTestSDK()
    
    // Create test transaction
    tx := &bridgesdk.Transaction{
        ID:        "test-tx-1",
        FromChain: "ethereum",
        ToChain:   "solana",
        Amount:    big.NewInt(1000000),
        Status:    "pending",
    }
    
    // Test relay
    err := sdk.RelayToChain(tx, "solana")
    assert.NoError(t, err)
    
    // Verify transaction status
    status, err := sdk.GetTransactionStatus(tx.ID)
    assert.NoError(t, err)
    assert.Equal(t, "completed", status.Status)
}
```

### Integration Testing

```go
func TestIntegration(t *testing.T) {
    // Skip if not running integration tests
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    // Setup test environment
    sdk := setupIntegrationSDK()
    ctx := context.Background()
    
    // Start listeners
    go sdk.StartEthereumListener(ctx)
    go sdk.StartSolanaListener(ctx)
    
    // Wait for initialization
    time.Sleep(5 * time.Second)
    
    // Test end-to-end flow
    testEndToEndBridge(t, sdk)
}
```

## 🚀 Deployment Integration

### Docker Integration

```dockerfile
# Dockerfile for your application
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o bridge-app .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/bridge-app .
CMD ["./bridge-app"]
```

### Kubernetes Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bridge-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: bridge-app
  template:
    metadata:
      labels:
        app: bridge-app
    spec:
      containers:
      - name: bridge-app
        image: your-registry/bridge-app:latest
        ports:
        - containerPort: 8084
        env:
        - name: ETHEREUM_RPC
          valueFrom:
            secretKeyRef:
              name: bridge-secrets
              key: ethereum-rpc
        - name: SOLANA_RPC
          valueFrom:
            secretKeyRef:
              name: bridge-secrets
              key: solana-rpc
```

## 📚 Additional Resources

### Example Projects
- [Basic Bridge Integration](examples/basic/)
- [Advanced Custom Handlers](examples/advanced/)
- [Production Deployment](examples/production/)

### API Documentation
- [REST API Reference](API.md)
- [WebSocket API Reference](WEBSOCKET.md)
- [SDK Method Reference](SDK_REFERENCE.md)

### Troubleshooting
- [Common Issues](TROUBLESHOOTING.md)
- [Performance Tuning](PERFORMANCE.md)
- [Security Guidelines](SECURITY.md)

---

This developer guide provides comprehensive integration instructions for BlackHole developers. For additional support, please refer to the documentation links above or contact the development team.
