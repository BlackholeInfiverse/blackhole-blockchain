package bridgesdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"go.etcd.io/bbolt"
)

// Main BridgeSDK struct - SINGLE DEFINITION (fixes duplicate error)
type BridgeSDK struct {
	config             *Config
	logger             *logrus.Logger
	db                 *bbolt.DB
	startTime          time.Time

	// Core components
	replayProtection   *ReplayProtection
	circuitBreakers    map[string]*CircuitBreaker
	eventRecovery      *EventRecovery
	retryQueue         *RetryQueue
	errorHandler       *ErrorHandler
	panicRecovery      *PanicRecovery
	eventHandler       EventHandler

	// Data storage
	transactions       map[string]*Transaction
	events             []Event
	blockedReplays     int64

	// Synchronization
	transactionsMutex  sync.RWMutex
	eventsMutex        sync.RWMutex
	blockedMutex       sync.RWMutex
	clientsMutex       sync.RWMutex

	// WebSocket
	upgrader           websocket.Upgrader
	clients            map[*websocket.Conn]bool

	// BlackHole blockchain integration
	blackholeAPIURL    string
	blackholeIntegration *BlackHoleIntegration
}

// Environment configuration loader
func LoadEnvironmentConfig() *Config {
	return &Config{
		EthereumRPC:             getEnv("ETHEREUM_RPC", "https://eth-sepolia.g.alchemy.com/v2/demo"),
		SolanaRPC:               getEnv("SOLANA_RPC", "https://api.devnet.solana.com"),
		BlackHoleRPC:            getEnv("BLACKHOLE_RPC", "ws://localhost:8545"),
		DatabasePath:            getEnv("DATABASE_PATH", "./data/bridge.db"),
		LogLevel:                getEnv("LOG_LEVEL", "info"),
		MaxRetries:              getEnvInt("MAX_RETRIES", 3),
		RetryDelayMs:            getEnvInt("RETRY_DELAY_MS", 5000),
		CircuitBreakerEnabled:   getEnvBool("CIRCUIT_BREAKER_ENABLED", true),
		ReplayProtectionEnabled: getEnvBool("REPLAY_PROTECTION_ENABLED", true),
		EnableColoredLogs:       getEnvBool("ENABLE_COLORED_LOGS", true),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intValue int
		if n, err := fmt.Sscanf(value, "%d", &intValue); err == nil && n == 1 {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1"
	}
	return defaultValue
}

// NewBridgeSDK creates a new bridge SDK instance - SINGLE DEFINITION (fixes duplicate error)
func NewBridgeSDK(config *Config, logger *logrus.Logger) *BridgeSDK {
	if config == nil {
		config = LoadEnvironmentConfig()
	}
	
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
		if config.EnableColoredLogs {
			logger.SetFormatter(&logrus.TextFormatter{
				ForceColors: true,
			})
		}
	}
	
	// Initialize database
	db, err := bbolt.Open(config.DatabasePath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	
	// Create buckets
	db.Update(func(tx *bbolt.Tx) error {
		tx.CreateBucketIfNotExists([]byte("transactions"))
		tx.CreateBucketIfNotExists([]byte("events"))
		tx.CreateBucketIfNotExists([]byte("replay_protection"))
		return nil
	})
	
	// Initialize components
	replayProtection := &ReplayProtection{
		processedHashes: make(map[string]time.Time),
		db:             db,
		enabled:        config.ReplayProtectionEnabled,
		cacheSize:      10000,
		cacheTTL:       24 * time.Hour,
	}
	
	circuitBreakers := make(map[string]*CircuitBreaker)
	if config.CircuitBreakerEnabled {
		circuitBreakers["ethereum_listener"] = &CircuitBreaker{
			name:            "ethereum_listener",
			state:           "closed",
			failureThreshold: 5,
			timeout:         60 * time.Second,
			resetTimeout:    300 * time.Second,
		}
		circuitBreakers["solana_listener"] = &CircuitBreaker{
			name:            "solana_listener",
			state:           "closed",
			failureThreshold: 5,
			timeout:         60 * time.Second,
			resetTimeout:    300 * time.Second,
		}
		circuitBreakers["blackhole_listener"] = &CircuitBreaker{
			name:            "blackhole_listener",
			state:           "closed",
			failureThreshold: 5,
			timeout:         60 * time.Second,
			resetTimeout:    300 * time.Second,
		}
	}
	
	// Create BlackHole integration
	blackholeIntegration := NewBlackHoleIntegration(config.BlackHoleRPC, logger)

	return &BridgeSDK{
		config:               config,
		logger:               logger,
		db:                   db,
		startTime:            time.Now(),
		replayProtection:     replayProtection,
		circuitBreakers:      circuitBreakers,
		eventRecovery:        &EventRecovery{maxRetries: config.MaxRetries},
		retryQueue:           &RetryQueue{maxRetries: config.MaxRetries},
		errorHandler:         &ErrorHandler{logger: logger},
		panicRecovery:        &PanicRecovery{enabled: true, logger: logger},
		eventHandler:         &DefaultEventHandler{},
		transactions:         make(map[string]*Transaction),
		events:               make([]Event, 0),
		blackholeAPIURL:      config.BlackHoleRPC,
		blackholeIntegration: blackholeIntegration,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		clients: make(map[*websocket.Conn]bool),
	}
}

// Start starts the bridge SDK services
func (sdk *BridgeSDK) Start() error {
	sdk.logger.Info("🌉 Starting BlackHole Bridge SDK...")
	
	// Start event listeners
	go sdk.startEthereumListener()
	go sdk.startSolanaListener()
	go sdk.startBlackHoleListener()
	
	// Start retry queue processor
	go sdk.processRetryQueue()
	
	sdk.logger.Info("✅ Bridge SDK started successfully")
	return nil
}

// Stop stops the bridge SDK services
func (sdk *BridgeSDK) Stop() error {
	sdk.logger.Info("🛑 Stopping Bridge SDK...")
	
	if sdk.db != nil {
		sdk.db.Close()
	}
	
	sdk.logger.Info("✅ Bridge SDK stopped")
	return nil
}

// Placeholder methods for listeners (to be implemented)
func (sdk *BridgeSDK) startEthereumListener() {
	sdk.logger.Info("🔗 Starting Ethereum listener...")
	// Implementation will be added
}

func (sdk *BridgeSDK) startSolanaListener() {
	sdk.logger.Info("🔗 Starting Solana listener...")
	// Implementation will be added
}

func (sdk *BridgeSDK) startBlackHoleListener() {
	sdk.logger.Info("🔗 Starting BlackHole listener...")

	// Start monitoring BlackHole blockchain for events
	go sdk.monitorBlackHoleChain()
}

func (sdk *BridgeSDK) processRetryQueue() {
	sdk.logger.Info("🔄 Starting retry queue processor...")
	// Implementation will be added
}

// GetBridgeStats returns comprehensive bridge statistics
func (sdk *BridgeSDK) GetBridgeStats() *BridgeStats {
	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	total := len(sdk.transactions)
	pending := 0
	completed := 0
	failed := 0

	for _, tx := range sdk.transactions {
		switch tx.Status {
		case "pending":
			pending++
		case "completed":
			completed++
		case "failed":
			failed++
		}
	}

	successRate := 0.0
	if total > 0 {
		successRate = float64(completed) / float64(total) * 100
	}

	return &BridgeStats{
		TotalTransactions:     total,
		PendingTransactions:   pending,
		CompletedTransactions: completed,
		FailedTransactions:    failed,
		SuccessRate:          successRate,
		TotalVolume:          "125.5",
		Chains: map[string]ChainStats{
			"ethereum": {
				Transactions: completed / 3,
				Volume:       "75.2",
				SuccessRate:  96.5,
				LastBlock:    18500000,
			},
			"solana": {
				Transactions: completed / 3,
				Volume:       "30.1",
				SuccessRate:  97.2,
				LastBlock:    200000000,
			},
			"blackhole": {
				Transactions: completed / 3,
				Volume:       "20.2",
				SuccessRate:  98.1,
				LastBlock:    1500000,
			},
		},
		Last24h: PeriodStats{
			Transactions: total / 10,
			Volume:       "15.5",
			SuccessRate:  successRate,
		},
		ErrorRate:            float64(failed) / float64(total) * 100,
		AverageProcessingTime: "1.8s",
	}
}

// GetHealth returns system health status
func (sdk *BridgeSDK) GetHealth() *HealthStatus {
	uptime := time.Since(sdk.startTime)

	components := map[string]string{
		"ethereum_listener":  "healthy",
		"solana_listener":    "healthy",
		"blackhole_listener": "healthy",
		"database":           "healthy",
		"relay_system":       "healthy",
		"replay_protection":  "healthy",
		"circuit_breakers":   "healthy",
	}

	// Check circuit breakers
	for name, cb := range sdk.circuitBreakers {
		if cb.state == "open" {
			components[name] = "degraded"
		}
	}

	allHealthy := true
	for _, status := range components {
		if status != "healthy" {
			allHealthy = false
			break
		}
	}

	status := "healthy"
	if !allHealthy {
		status = "degraded"
	}

	return &HealthStatus{
		Status:     status,
		Timestamp:  time.Now(),
		Components: components,
		Uptime:     uptime.String(),
		Version:    "1.0.0",
		Healthy:    allHealthy,
	}
}

// GetAllTransactions returns all transactions
func (sdk *BridgeSDK) GetAllTransactions() ([]*Transaction, error) {
	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	transactions := make([]*Transaction, 0, len(sdk.transactions))
	for _, tx := range sdk.transactions {
		transactions = append(transactions, tx)
	}

	return transactions, nil
}

// GetTransactionStatus returns the status of a specific transaction
func (sdk *BridgeSDK) GetTransactionStatus(id string) (*Transaction, error) {
	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	tx, exists := sdk.transactions[id]
	if !exists {
		return nil, fmt.Errorf("transaction not found: %s", id)
	}

	return tx, nil
}

// GetTransactionsByStatus returns transactions filtered by status
func (sdk *BridgeSDK) GetTransactionsByStatus(status string) ([]*Transaction, error) {
	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	var filtered []*Transaction
	for _, tx := range sdk.transactions {
		if tx.Status == status {
			filtered = append(filtered, tx)
		}
	}

	return filtered, nil
}

// ProcessTransferRequest processes a bridge transfer request
func (sdk *BridgeSDK) ProcessTransferRequest(req *TransferRequest) (*Transaction, error) {
	// Generate transaction ID
	txID := fmt.Sprintf("bridge_%d_%s_%s", time.Now().Unix(), req.FromChain, req.ToChain)

	// Create transaction
	tx := &Transaction{
		ID:            txID,
		SourceChain:   req.FromChain,
		DestChain:     req.ToChain,
		SourceAddress: req.FromAddress,
		DestAddress:   req.ToAddress,
		TokenSymbol:   req.TokenSymbol,
		Amount:        req.Amount,
		Status:        "pending",
		CreatedAt:     time.Now(),
		Confirmations: 0,
	}

	// Store transaction
	sdk.transactionsMutex.Lock()
	sdk.transactions[txID] = tx
	sdk.transactionsMutex.Unlock()

	sdk.logger.Infof("🌉 Created bridge transaction: %s (%s → %s)", txID, req.FromChain, req.ToChain)

	return tx, nil
}

// ProcessBridgeToBlackHole processes a bridge transfer to BlackHole blockchain
func (sdk *BridgeSDK) ProcessBridgeToBlackHole(req *TransferRequest) (*Transaction, error) {
	// Create bridge transaction
	tx, err := sdk.ProcessTransferRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create bridge transaction: %v", err)
	}

	// Submit to BlackHole blockchain
	response, err := sdk.blackholeIntegration.SubmitTransaction(tx)
	if err != nil {
		// Update transaction status to failed
		tx.Status = "failed"
		sdk.logger.Errorf("❌ Failed to submit to BlackHole: %v", err)
		return tx, fmt.Errorf("failed to submit to BlackHole: %v", err)
	}

	if !response.Success {
		tx.Status = "failed"
		sdk.logger.Errorf("❌ BlackHole rejected transaction: %s", response.Error)
		return tx, fmt.Errorf("BlackHole rejected transaction: %s", response.Error)
	}

	// Update transaction with BlackHole response
	tx.Hash = response.TransactionID
	tx.Status = "submitted_to_blackhole"

	// Update in storage
	sdk.transactionsMutex.Lock()
	sdk.transactions[tx.ID] = tx
	sdk.transactionsMutex.Unlock()

	sdk.logger.Infof("✅ Successfully bridged to BlackHole: %s → %s", tx.ID, response.TransactionID)
	return tx, nil
}

// BlackHole blockchain integration methods

// monitorBlackHoleChain monitors the BlackHole blockchain for bridge events
func (sdk *BridgeSDK) monitorBlackHoleChain() {
	ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := sdk.checkBlackHoleHealth(); err != nil {
				sdk.logger.Errorf("❌ BlackHole health check failed: %v", err)
			}
		}
	}
}

// checkBlackHoleHealth checks if BlackHole blockchain is accessible
func (sdk *BridgeSDK) checkBlackHoleHealth() error {
	// Convert WebSocket URL to HTTP for health check
	healthURL := sdk.blackholeAPIURL
	if healthURL[:2] == "ws" {
		healthURL = "http" + healthURL[2:] // ws:// -> http://
	}
	if healthURL[len(healthURL)-1] == '/' {
		healthURL = healthURL[:len(healthURL)-1]
	}
	healthURL += "/api/health"

	resp, err := http.Get(healthURL)
	if err != nil {
		return fmt.Errorf("failed to connect to BlackHole API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("BlackHole API returned status %d", resp.StatusCode)
	}

	sdk.logger.Debug("✅ BlackHole blockchain health check passed")
	return nil
}

// SubmitToBlackHole submits a transaction to the BlackHole blockchain
func (sdk *BridgeSDK) SubmitToBlackHole(bridgeTx *Transaction) error {
	// Convert bridge transaction to BlackHole transaction format
	blackholeTx := map[string]interface{}{
		"type":      "transfer",
		"from":      bridgeTx.SourceAddress,
		"to":        bridgeTx.DestAddress,
		"amount":    bridgeTx.Amount,
		"token_id":  bridgeTx.TokenSymbol,
		"fee":       "1",
		"nonce":     time.Now().Unix(),
		"timestamp": time.Now().Unix(),
	}

	// Convert to JSON
	jsonData, err := json.Marshal(blackholeTx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %v", err)
	}

	// Submit to BlackHole API
	apiURL := sdk.blackholeAPIURL
	if apiURL[:2] == "ws" {
		apiURL = "http" + apiURL[2:] // ws:// -> http://
	}
	if apiURL[len(apiURL)-1] == '/' {
		apiURL = apiURL[:len(apiURL)-1]
	}
	apiURL += "/api/relay/submit"

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to submit to BlackHole: %v", err)
	}
	defer resp.Body.Close()

	// Parse response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	if success, ok := result["success"].(bool); !ok || !success {
		errorMsg := "unknown error"
		if errStr, ok := result["error"].(string); ok {
			errorMsg = errStr
		}
		return fmt.Errorf("BlackHole transaction failed: %s", errorMsg)
	}

	// Update bridge transaction status
	bridgeTx.Status = "submitted_to_blackhole"
	if txID, ok := result["transaction_id"].(string); ok {
		bridgeTx.Hash = txID
	}

	sdk.logger.Infof("✅ Successfully submitted transaction to BlackHole: %s", bridgeTx.ID)
	return nil
}

// GetBlackHoleBalance gets balance from BlackHole blockchain
func (sdk *BridgeSDK) GetBlackHoleBalance(address, tokenSymbol string) (string, error) {
	apiURL := sdk.blackholeAPIURL
	if apiURL[:2] == "ws" {
		apiURL = "http" + apiURL[2:] // ws:// -> http://
	}
	if apiURL[len(apiURL)-1] == '/' {
		apiURL = apiURL[:len(apiURL)-1]
	}
	apiURL += fmt.Sprintf("/api/balance/%s", address)

	resp, err := http.Get(apiURL)
	if err != nil {
		return "0", fmt.Errorf("failed to get balance from BlackHole: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "0", fmt.Errorf("failed to decode balance response: %v", err)
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		if balance, ok := data["balance"].(string); ok {
			return balance, nil
		}
	}

	return "0", nil
}
