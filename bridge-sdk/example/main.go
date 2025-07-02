package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"go.etcd.io/bbolt"

	// BlackHole blockchain imports

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// BlackHoleBlockchainInterface represents the interface to the real blockchain
type BlackHoleBlockchainInterface struct {
	blockchain *chain.Blockchain
	logger     *logrus.Logger
}

// ProcessBridgeTransaction processes a bridge transaction on the BlackHole blockchain
func (bhi *BlackHoleBlockchainInterface) ProcessBridgeTransaction(bridgeTx *Transaction) error {
	if bhi.blockchain == nil {
		return fmt.Errorf("blockchain not available")
	}

	bhi.logger.Infof("🔗 Processing bridge transaction on BlackHole blockchain: %s", bridgeTx.ID)

	// Convert bridge transaction to core blockchain transaction
	coreTx, err := bhi.convertBridgeToCoreTx(bridgeTx)
	if err != nil {
		return fmt.Errorf("failed to convert bridge transaction: %v", err)
	}

	// Process transaction through core blockchain
	err = bhi.blockchain.ProcessTransaction(coreTx)
	if err != nil {
		return fmt.Errorf("failed to process transaction on blockchain: %v", err)
	}

	// Update bridge transaction status
	bridgeTx.Status = "confirmed"
	bridgeTx.BlockNumber = uint64(len(bhi.blockchain.Blocks))
	now := time.Now()
	bridgeTx.CompletedAt = &now
	bridgeTx.ProcessingTime = fmt.Sprintf("%.2fs", time.Since(bridgeTx.CreatedAt).Seconds())

	bhi.logger.Infof("✅ Bridge transaction processed successfully: %s", bridgeTx.ID)
	return nil
}

// convertBridgeToCoreTx converts bridge transaction to core blockchain transaction
func (bhi *BlackHoleBlockchainInterface) convertBridgeToCoreTx(bridgeTx *Transaction) (*chain.Transaction, error) {
	// Parse amount from string to uint64
	amount, err := strconv.ParseUint(bridgeTx.Amount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %s", bridgeTx.Amount)
	}

	// Create core blockchain transaction
	coreTx := &chain.Transaction{
		ID:        bridgeTx.Hash,
		Type:      chain.TokenTransfer,
		From:      bridgeTx.SourceAddress,
		To:        bridgeTx.DestAddress,
		Amount:    amount,
		TokenID:   bridgeTx.TokenSymbol,
		Timestamp: bridgeTx.CreatedAt.Unix(),
		Nonce:     0, // Will be set by blockchain
	}

	return coreTx, nil
}

// GetBlockchainStats returns current blockchain statistics
func (bhi *BlackHoleBlockchainInterface) GetBlockchainStats() map[string]interface{} {
	if bhi.blockchain == nil {
		return map[string]interface{}{
			"mode":         "simulation",
			"blocks":       0,
			"transactions": 0,
			"tokens":       0,
		}
	}

	totalTxs := 0
	for _, block := range bhi.blockchain.Blocks {
		totalTxs += len(block.Transactions)
	}

	return map[string]interface{}{
		"mode":         "live",
		"blocks":       len(bhi.blockchain.Blocks),
		"transactions": totalTxs,
		"tokens":       len(bhi.blockchain.TokenRegistry),
		"total_supply": bhi.blockchain.TotalSupply,
	}
}

// GetTokenBalance retrieves token balance from the blockchain
func (bhi *BlackHoleBlockchainInterface) GetTokenBalance(address, tokenSymbol string) (uint64, error) {
	if bhi.blockchain == nil {
		return 1000000, nil // Mock balance for simulation
	}

	token, exists := bhi.blockchain.TokenRegistry[tokenSymbol]
	if !exists {
		return 0, fmt.Errorf("token %s not found in registry", tokenSymbol)
	}

	balance, err := token.BalanceOf(address)
	if err != nil {
		return 0, fmt.Errorf("failed to get balance: %v", err)
	}

	return balance, nil
}

// BridgeSDK represents the main bridge SDK
type BridgeSDK struct {
	blockchain          interface{}                   // Can be BlackHoleBlockchainInterface or nil for simulation
	blockchainInterface *BlackHoleBlockchainInterface // Real blockchain interface
	config              *Config
	db                  *bbolt.DB
	logger              *logrus.Logger
	upgrader            websocket.Upgrader
	clients             map[*websocket.Conn]bool
	clientsMutex        sync.RWMutex
	replayProtection    *ReplayProtection
	circuitBreakers     map[string]*CircuitBreaker
	errorHandler        *ErrorHandler
	eventRecovery       *EventRecovery
	logStreamer         *LogStreamer
	retryQueue          *RetryQueue
	panicRecovery       *PanicRecovery
	startTime           time.Time
	transactions        map[string]*Transaction
	transactionsMutex   sync.RWMutex
	events              []Event
	eventsMutex         sync.RWMutex
	blockedReplays      int64
	blockedMutex        sync.RWMutex
}

// Config holds the bridge configuration
type Config struct {
	EthereumRPC             string
	SolanaRPC               string
	BlackHoleRPC            string
	DatabasePath            string
	LogLevel                string
	LogFile                 string
	ReplayProtectionEnabled bool
	CircuitBreakerEnabled   bool
	Port                    string
	MaxRetries              int
	RetryDelay              time.Duration
	BatchSize               int
}

// Transaction represents a bridge transaction
type Transaction struct {
	ID             string     `json:"id"`
	Hash           string     `json:"hash"`
	SourceChain    string     `json:"source_chain"`
	DestChain      string     `json:"dest_chain"`
	SourceAddress  string     `json:"source_address"`
	DestAddress    string     `json:"dest_address"`
	TokenSymbol    string     `json:"token_symbol"`
	Amount         string     `json:"amount"`
	Fee            string     `json:"fee"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	Confirmations  int        `json:"confirmations"`
	BlockNumber    uint64     `json:"block_number"`
	GasUsed        uint64     `json:"gas_used,omitempty"`
	GasPrice       string     `json:"gas_price,omitempty"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	RetryCount     int        `json:"retry_count"`
	LastRetryAt    *time.Time `json:"last_retry_at,omitempty"`
	ProcessingTime string     `json:"processing_time,omitempty"`
}

type Event struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Chain        string                 `json:"chain"`
	BlockNumber  uint64                 `json:"block_number"`
	TxHash       string                 `json:"tx_hash"`
	Timestamp    time.Time              `json:"timestamp"`
	Data         map[string]interface{} `json:"data"`
	Processed    bool                   `json:"processed"`
	ProcessedAt  *time.Time             `json:"processed_at,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	RetryCount   int                    `json:"retry_count"`
}

// ReplayProtection handles duplicate event detection
type ReplayProtection struct {
	processedHashes map[string]time.Time
	mutex           sync.RWMutex
	db              *bbolt.DB
	enabled         bool
	cacheSize       int
	cacheTTL        time.Duration
}

// Replay protection methods
func (rp *ReplayProtection) isProcessed(hash string) bool {
	if !rp.enabled {
		return false
	}

	rp.mutex.RLock()
	defer rp.mutex.RUnlock()

	// Check in-memory cache first
	if processedTime, exists := rp.processedHashes[hash]; exists {
		// Check if not expired
		if time.Since(processedTime) < rp.cacheTTL {
			return true
		}
		// Remove expired entry
		delete(rp.processedHashes, hash)
	}

	// Check in database
	var exists bool
	rp.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("replay_protection"))
		if bucket != nil {
			value := bucket.Get([]byte(hash))
			exists = value != nil
		}
		return nil
	})

	return exists
}

func (rp *ReplayProtection) markProcessed(hash string) error {
	if !rp.enabled {
		return nil
	}

	rp.mutex.Lock()
	defer rp.mutex.Unlock()

	now := time.Now()

	// Add to in-memory cache
	rp.processedHashes[hash] = now

	// Cleanup old entries if cache is too large
	if len(rp.processedHashes) > rp.cacheSize {
		rp.cleanupExpiredEntries()
	}

	// Persist to database
	return rp.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("replay_protection"))
		if bucket == nil {
			return fmt.Errorf("replay protection bucket not found")
		}

		// Store with timestamp
		value := fmt.Sprintf("%d", now.Unix())
		return bucket.Put([]byte(hash), []byte(value))
	})
}

func (rp *ReplayProtection) cleanupExpiredEntries() {
	now := time.Now()
	for hash, processedTime := range rp.processedHashes {
		if now.Sub(processedTime) > rp.cacheTTL {
			delete(rp.processedHashes, hash)
		}
	}
}

func (rp *ReplayProtection) getStats() map[string]interface{} {
	rp.mutex.RLock()
	defer rp.mutex.RUnlock()

	var dbCount int
	rp.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("replay_protection"))
		if bucket != nil {
			dbCount = bucket.Stats().KeyN
		}
		return nil
	})

	return map[string]interface{}{
		"enabled":          rp.enabled,
		"cache_size":       len(rp.processedHashes),
		"max_cache_size":   rp.cacheSize,
		"database_entries": dbCount,
		"cache_ttl":        rp.cacheTTL.String(),
	}
}

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	name             string
	state            string
	failureCount     int
	failureThreshold int
	lastFailure      *time.Time
	nextAttempt      *time.Time
	mutex            sync.RWMutex
	timeout          time.Duration
	resetTimeout     time.Duration
}

// Circuit breaker methods
func (cb *CircuitBreaker) recordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failureCount++
	now := time.Now()
	cb.lastFailure = &now

	if cb.failureCount >= cb.failureThreshold {
		cb.state = "open"
		nextAttempt := now.Add(cb.resetTimeout)
		cb.nextAttempt = &nextAttempt
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failureCount = 0
	cb.state = "closed"
	cb.lastFailure = nil
	cb.nextAttempt = nil
}

func (cb *CircuitBreaker) canExecute() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	if cb.state == "closed" {
		return true
	}

	if cb.state == "open" && cb.nextAttempt != nil && time.Now().After(*cb.nextAttempt) {
		return true
	}

	return false
}

func (cb *CircuitBreaker) getState() string {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// ErrorHandler manages error handling and recovery
type ErrorHandler struct {
	errors          []ErrorEntry
	mutex           sync.RWMutex
	circuitBreakers map[string]*CircuitBreaker
}

// ErrorEntry represents an error entry
type ErrorEntry struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Component string    `json:"component"`
	Resolved  bool      `json:"resolved"`
}

// EventRecovery handles failed event recovery
type EventRecovery struct {
	failedEvents []FailedEvent
	mutex        sync.RWMutex
}

// FailedEvent represents a failed event
type FailedEvent struct {
	ID           string     `json:"id"`
	EventType    string     `json:"event_type"`
	Chain        string     `json:"chain"`
	TxHash       string     `json:"transaction_hash"`
	ErrorMessage string     `json:"error_message"`
	RetryCount   int        `json:"retry_count"`
	MaxRetries   int        `json:"max_retries"`
	NextRetry    *time.Time `json:"next_retry,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// LogStreamer handles real-time log streaming
type LogStreamer struct {
	clients map[*websocket.Conn]bool
	mutex   sync.RWMutex
	logs    []LogEntry
}

// LogEntry represents a log entry
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Component string                 `json:"component"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// BridgeStats represents bridge statistics
type BridgeStats struct {
	TotalTransactions     int                   `json:"total_transactions"`
	PendingTransactions   int                   `json:"pending_transactions"`
	CompletedTransactions int                   `json:"completed_transactions"`
	FailedTransactions    int                   `json:"failed_transactions"`
	SuccessRate           float64               `json:"success_rate"`
	TotalVolume           string                `json:"total_volume"`
	Chains                map[string]ChainStats `json:"chains"`
	Last24h               PeriodStats           `json:"last_24h"`
	ErrorRate             float64               `json:"error_rate"`
	AverageProcessingTime string                `json:"average_processing_time"`
}

// ChainStats represents statistics for a specific chain
type ChainStats struct {
	Transactions int     `json:"transactions"`
	Volume       string  `json:"volume"`
	SuccessRate  float64 `json:"success_rate"`
	LastBlock    uint64  `json:"last_block"`
}

// PeriodStats represents statistics for a time period
type PeriodStats struct {
	Transactions int     `json:"transactions"`
	Volume       string  `json:"volume"`
	SuccessRate  float64 `json:"success_rate"`
}

// HealthStatus represents system health
type HealthStatus struct {
	Status     string            `json:"status"`
	Timestamp  time.Time         `json:"timestamp"`
	Components map[string]string `json:"components"`
	Uptime     string            `json:"uptime"`
	Version    string            `json:"version"`
	Healthy    bool              `json:"healthy"`
}

// ErrorMetrics represents error metrics
type ErrorMetrics struct {
	ErrorRate    float64        `json:"error_rate"`
	TotalErrors  int            `json:"total_errors"`
	ErrorsByType map[string]int `json:"errors_by_type"`
	RecentErrors []ErrorEntry   `json:"recent_errors"`
}

// TransferRequest represents a token transfer request
type TransferRequest struct {
	FromChain   string `json:"from_chain"`
	ToChain     string `json:"to_chain"`
	TokenSymbol string `json:"token_symbol"`
	Amount      string `json:"amount"`
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
}

// RetryQueue handles failed operations with exponential backoff
type RetryQueue struct {
	items      []RetryItem
	mutex      sync.RWMutex
	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration
}

// RetryItem represents an item in the retry queue
type RetryItem struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Data       map[string]interface{} `json:"data"`
	Attempts   int                    `json:"attempts"`
	MaxRetries int                    `json:"max_retries"`
	NextRetry  time.Time              `json:"next_retry"`
	LastError  string                 `json:"last_error"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// PanicRecovery handles panic recovery and logging
type PanicRecovery struct {
	recoveries []PanicEntry
	mutex      sync.RWMutex
	logger     *logrus.Logger
}

// PanicEntry represents a panic recovery entry
type PanicEntry struct {
	ID        string    `json:"id"`
	Message   string    `json:"message"`
	Stack     string    `json:"stack"`
	Component string    `json:"component"`
	Timestamp time.Time `json:"timestamp"`
	Recovered bool      `json:"recovered"`
}

// EnhancedToken represents enhanced token information
type EnhancedToken struct {
	Symbol      string `json:"symbol"`
	Name        string `json:"name"`
	Decimals    int    `json:"decimals"`
	Address     string `json:"address"`
	Chain       string `json:"chain"`
	LogoURL     string `json:"logo_url"`
	IsNative    bool   `json:"is_native"`
	TotalSupply string `json:"total_supply"`
}

// EnvironmentConfig represents environment configuration
type EnvironmentConfig struct {
	Port                    string
	EthereumRPC             string
	SolanaRPC               string
	BlackHoleRPC            string
	DatabasePath            string
	LogLevel                string
	LogFile                 string
	ReplayProtectionEnabled bool
	CircuitBreakerEnabled   bool
	MaxRetries              int
	RetryDelay              time.Duration
	BatchSize               int
	EnableColoredLogs       bool
	EnableDocumentation     bool
}

// LoadEnvironmentConfig loads configuration from environment variables and .env file
func LoadEnvironmentConfig() *EnvironmentConfig {
	config := &EnvironmentConfig{
		Port:                    getEnvOrDefault("PORT", "8084"),
		EthereumRPC:             getEnvOrDefault("ETHEREUM_RPC", "wss://eth-mainnet.alchemyapi.io/v2/demo"),
		SolanaRPC:               getEnvOrDefault("SOLANA_RPC", "wss://api.mainnet-beta.solana.com"),
		BlackHoleRPC:            getEnvOrDefault("BLACKHOLE_RPC", "ws://localhost:8545"),
		DatabasePath:            getEnvOrDefault("DATABASE_PATH", "./data/bridge.db"),
		LogLevel:                getEnvOrDefault("LOG_LEVEL", "info"),
		LogFile:                 getEnvOrDefault("LOG_FILE", "./logs/bridge.log"),
		ReplayProtectionEnabled: getEnvBoolOrDefault("REPLAY_PROTECTION_ENABLED", true),
		CircuitBreakerEnabled:   getEnvBoolOrDefault("CIRCUIT_BREAKER_ENABLED", true),
		MaxRetries:              getEnvIntOrDefault("MAX_RETRIES", 3),
		BatchSize:               getEnvIntOrDefault("BATCH_SIZE", 100),
		EnableColoredLogs:       getEnvBoolOrDefault("ENABLE_COLORED_LOGS", true),
		EnableDocumentation:     getEnvBoolOrDefault("ENABLE_DOCUMENTATION", true),
	}

	retryDelayMs := getEnvIntOrDefault("RETRY_DELAY_MS", 5000)
	config.RetryDelay = time.Duration(retryDelayMs) * time.Millisecond

	// Try to load .env file if it exists
	loadDotEnv()

	return config
}

// Helper functions for environment variables
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func loadDotEnv() {
	file, err := os.Open(".env")
	if err != nil {
		return // .env file doesn't exist, which is fine
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Remove quotes if present
			if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
				value = value[1 : len(value)-1]
			}
			os.Setenv(key, value)
		}
	}
}

// NewBridgeSDK creates a new bridge SDK instance
func NewBridgeSDK(blockchain interface{}, config *Config) *BridgeSDK {
	// Load environment configuration
	envConfig := LoadEnvironmentConfig()

	if config == nil {
		config = &Config{
			EthereumRPC:             envConfig.EthereumRPC,
			SolanaRPC:               envConfig.SolanaRPC,
			BlackHoleRPC:            envConfig.BlackHoleRPC,
			DatabasePath:            envConfig.DatabasePath,
			LogLevel:                envConfig.LogLevel,
			LogFile:                 envConfig.LogFile,
			ReplayProtectionEnabled: envConfig.ReplayProtectionEnabled,
			CircuitBreakerEnabled:   envConfig.CircuitBreakerEnabled,
			Port:                    envConfig.Port,
			MaxRetries:              envConfig.MaxRetries,
			RetryDelay:              envConfig.RetryDelay,
			BatchSize:               envConfig.BatchSize,
		}
	}

	logger := logrus.New()
	level, _ := logrus.ParseLevel(config.LogLevel)
	logger.SetLevel(level)

	// Configure colored logging if enabled
	if envConfig.EnableColoredLogs {
		logger.SetFormatter(&logrus.TextFormatter{
			ForceColors:     true,
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
	} else {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
		})
	}

	// Ensure directories exist
	os.MkdirAll(filepath.Dir(config.DatabasePath), 0755)
	os.MkdirAll(filepath.Dir(config.LogFile), 0755)

	// Open database
	db, err := bbolt.Open(config.DatabasePath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	// Initialize buckets
	db.Update(func(tx *bbolt.Tx) error {
		tx.CreateBucketIfNotExists([]byte("transactions"))
		tx.CreateBucketIfNotExists([]byte("events"))
		tx.CreateBucketIfNotExists([]byte("replay_protection"))
		tx.CreateBucketIfNotExists([]byte("failed_events"))
		tx.CreateBucketIfNotExists([]byte("errors"))
		return nil
	})

	// Initialize blockchain interface if real blockchain is provided
	var blockchainInterface *BlackHoleBlockchainInterface
	if coreBlockchain, ok := blockchain.(*chain.Blockchain); ok && coreBlockchain != nil {
		blockchainInterface = &BlackHoleBlockchainInterface{
			blockchain: coreBlockchain,
			logger:     logger,
		}
		logger.Info("🔗 Initialized with real BlackHole blockchain")
	} else {
		logger.Info("🎭 Running in simulation mode - no real blockchain connected")
	}

	// Initialize components
	replayProtection := &ReplayProtection{
		processedHashes: make(map[string]time.Time),
		db:              db,
		enabled:         config.ReplayProtectionEnabled,
		cacheSize:       10000,
		cacheTTL:        24 * time.Hour,
	}

	circuitBreakers := make(map[string]*CircuitBreaker)
	if config.CircuitBreakerEnabled {
		circuitBreakers["ethereum_listener"] = &CircuitBreaker{
			name:             "ethereum_listener",
			state:            "closed",
			failureThreshold: 5,
			timeout:          60 * time.Second,
			resetTimeout:     300 * time.Second,
		}
		circuitBreakers["solana_listener"] = &CircuitBreaker{
			name:             "solana_listener",
			state:            "closed",
			failureThreshold: 5,
			timeout:          60 * time.Second,
			resetTimeout:     300 * time.Second,
		}
		circuitBreakers["blackhole_listener"] = &CircuitBreaker{
			name:             "blackhole_listener",
			state:            "closed",
			failureThreshold: 5,
			timeout:          60 * time.Second,
			resetTimeout:     300 * time.Second,
		}
	}

	errorHandler := &ErrorHandler{
		errors:          make([]ErrorEntry, 0),
		circuitBreakers: circuitBreakers,
	}

	eventRecovery := &EventRecovery{
		failedEvents: make([]FailedEvent, 0),
	}

	logStreamer := &LogStreamer{
		clients: make(map[*websocket.Conn]bool),
		logs:    make([]LogEntry, 0),
	}

	retryQueue := &RetryQueue{
		items:      make([]RetryItem, 0),
		maxRetries: config.MaxRetries,
		baseDelay:  1 * time.Second,
		maxDelay:   60 * time.Second,
	}

	panicRecovery := &PanicRecovery{
		recoveries: make([]PanicEntry, 0),
		logger:     logger,
	}

	return &BridgeSDK{
		blockchain:          blockchain,
		blockchainInterface: blockchainInterface,
		config:              config,
		db:                  db,
		logger:              logger,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for demo
			},
		},
		clients:          make(map[*websocket.Conn]bool),
		replayProtection: replayProtection,
		circuitBreakers:  circuitBreakers,
		errorHandler:     errorHandler,
		eventRecovery:    eventRecovery,
		logStreamer:      logStreamer,
		retryQueue:       retryQueue,
		panicRecovery:    panicRecovery,
		startTime:        time.Now(),
		transactions:     make(map[string]*Transaction),
		events:           make([]Event, 0),
		blockedReplays:   0,
	}
}

// StartEthereumListener starts the Ethereum blockchain listener
func (sdk *BridgeSDK) StartEthereumListener(ctx context.Context) error {
	sdk.logger.Info("🔗 Starting Ethereum listener...")

	// Simulate Ethereum events with realistic data
	go func() {
		ticker := time.NewTicker(8 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				sdk.logger.Info("🛑 Ethereum listener stopped")
				return
			case <-ticker.C:
				// Generate realistic Ethereum transaction with enhanced token data
				destChain := []string{"solana", "blackhole"}[rand.Intn(2)]
				token := getRandomToken("ethereum")
				tx := &Transaction{
					ID:            fmt.Sprintf("eth_%d", time.Now().Unix()),
					Hash:          fmt.Sprintf("0x%x", rand.Uint64()),
					SourceChain:   "ethereum",
					DestChain:     destChain,
					SourceAddress: fmt.Sprintf("0x%x", rand.Uint64()),
					DestAddress:   generateRandomAddress(destChain),
					TokenSymbol:   token.Symbol,
					Amount:        generateRealisticAmount(token),
					Fee:           fmt.Sprintf("%.6f", rand.Float64()*0.01),
					Status:        "pending",
					CreatedAt:     time.Now(),
					Confirmations: 0,
					BlockNumber:   uint64(18500000 + rand.Intn(1000)),
					GasUsed:       uint64(21000 + rand.Intn(50000)),
					GasPrice:      fmt.Sprintf("%d", 20000000000+rand.Int63n(10000000000)),
				}

				// Check replay protection
				if sdk.replayProtection.enabled {
					hash := sdk.generateEventHash(tx)
					if sdk.replayProtection.isProcessed(hash) {
						sdk.logger.Warnf("🚫 Replay attack detected for transaction %s", tx.ID)
						sdk.incrementBlockedReplays()
						continue
					}
					if err := sdk.replayProtection.markProcessed(hash); err != nil {
						sdk.logger.Errorf("Failed to mark transaction as processed: %v", err)
					}
				}

				sdk.saveTransaction(tx)
				sdk.addEvent("transfer", "ethereum", tx.Hash, map[string]interface{}{
					"amount": tx.Amount,
					"token":  tx.TokenSymbol,
					"from":   tx.SourceAddress,
					"to":     tx.DestAddress,
				})

				sdk.logger.Infof("💰 Ethereum transaction detected: %s (%s %s)", tx.ID, tx.Amount, tx.TokenSymbol)

				// Simulate processing delay and completion
				go func(transaction *Transaction) {
					time.Sleep(time.Duration(5+rand.Intn(10)) * time.Second)
					transaction.Status = "completed"
					now := time.Now()
					transaction.CompletedAt = &now
					transaction.Confirmations = 12 + rand.Intn(10)
					transaction.ProcessingTime = fmt.Sprintf("%.1fs", time.Since(transaction.CreatedAt).Seconds())
					sdk.saveTransaction(transaction)
					sdk.logger.Infof("✅ Ethereum transaction completed: %s", transaction.ID)
				}(tx)
			}
		}
	}()

	return nil
}

// StartSolanaListener starts the Solana blockchain listener
func (sdk *BridgeSDK) StartSolanaListener(ctx context.Context) error {
	sdk.logger.Info("🔗 Starting Solana listener...")

	// Simulate Solana events with realistic data
	go func() {
		ticker := time.NewTicker(12 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				sdk.logger.Info("🛑 Solana listener stopped")
				return
			case <-ticker.C:
				// Generate realistic Solana transaction with enhanced token data
				destChain := []string{"ethereum", "blackhole"}[rand.Intn(2)]
				token := getRandomToken("solana")
				tx := &Transaction{
					ID:            fmt.Sprintf("sol_%d", time.Now().Unix()),
					Hash:          generateSolanaSignature(),
					SourceChain:   "solana",
					DestChain:     destChain,
					SourceAddress: generateSolanaAddress(),
					DestAddress:   generateRandomAddress(destChain),
					TokenSymbol:   token.Symbol,
					Amount:        generateRealisticAmount(token),
					Fee:           fmt.Sprintf("%.6f", rand.Float64()*0.001),
					Status:        "pending",
					CreatedAt:     time.Now(),
					Confirmations: 0,
					BlockNumber:   uint64(200000000 + rand.Intn(1000)),
				}

				// Check replay protection
				if sdk.replayProtection.enabled {
					hash := sdk.generateEventHash(tx)
					if sdk.replayProtection.isProcessed(hash) {
						sdk.logger.Warnf("🚫 Replay attack detected for transaction %s", tx.ID)
						sdk.incrementBlockedReplays()
						continue
					}
					if err := sdk.replayProtection.markProcessed(hash); err != nil {
						sdk.logger.Errorf("Failed to mark transaction as processed: %v", err)
					}
				}

				sdk.saveTransaction(tx)
				sdk.addEvent("transfer", "solana", tx.Hash, map[string]interface{}{
					"amount": tx.Amount,
					"token":  tx.TokenSymbol,
					"from":   tx.SourceAddress,
					"to":     tx.DestAddress,
				})

				sdk.logger.Infof("💰 Solana transaction detected: %s (%s %s)", tx.ID, tx.Amount, tx.TokenSymbol)

				// Simulate processing delay and completion (faster)
				go func(transaction *Transaction) {
					time.Sleep(time.Duration(1+rand.Intn(3)) * time.Second)
					transaction.Status = "completed"
					now := time.Now()
					transaction.CompletedAt = &now
					transaction.Confirmations = 32 + rand.Intn(20)
					transaction.ProcessingTime = fmt.Sprintf("%.1fs", time.Since(transaction.CreatedAt).Seconds())
					sdk.saveTransaction(transaction)
					sdk.logger.Infof("✅ Solana transaction completed: %s", transaction.ID)
				}(tx)
			}
		}
	}()

	return nil
}

// Retry Queue Methods
func (rq *RetryQueue) AddItem(itemType string, data map[string]interface{}) string {
	rq.mutex.Lock()
	defer rq.mutex.Unlock()

	id := fmt.Sprintf("retry_%d_%d", time.Now().Unix(), rand.Intn(10000))
	item := RetryItem{
		ID:         id,
		Type:       itemType,
		Data:       data,
		Attempts:   0,
		MaxRetries: rq.maxRetries,
		NextRetry:  time.Now(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	rq.items = append(rq.items, item)
	return id
}

func (rq *RetryQueue) ProcessRetries(ctx context.Context, processor func(RetryItem) error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rq.processReadyItems(processor)
		}
	}
}

func (rq *RetryQueue) processReadyItems(processor func(RetryItem) error) {
	rq.mutex.Lock()
	defer rq.mutex.Unlock()

	now := time.Now()
	var remainingItems []RetryItem

	for _, item := range rq.items {
		if now.Before(item.NextRetry) {
			remainingItems = append(remainingItems, item)
			continue
		}

		if item.Attempts >= item.MaxRetries {
			// Item has exceeded max retries, remove it
			continue
		}

		// Try to process the item
		err := processor(item)
		if err != nil {
			// Failed, schedule for retry with exponential backoff
			item.Attempts++
			item.LastError = err.Error()
			item.UpdatedAt = now

			// Calculate exponential backoff delay
			delay := time.Duration(math.Pow(2, float64(item.Attempts))) * time.Second
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
			item.NextRetry = now.Add(delay)

			remainingItems = append(remainingItems, item)
		}
		// If successful, item is not added back to the queue
	}

	rq.items = remainingItems
}

func (rq *RetryQueue) GetStats() map[string]interface{} {
	rq.mutex.RLock()
	defer rq.mutex.RUnlock()

	totalItems := len(rq.items)
	readyItems := 0
	now := time.Now()

	for _, item := range rq.items {
		if now.After(item.NextRetry) {
			readyItems++
		}
	}

	return map[string]interface{}{
		"total_items":   totalItems,
		"ready_items":   readyItems,
		"pending_items": totalItems - readyItems,
		"max_retries":   rq.maxRetries,
		"base_delay":    rq.baseDelay.String(),
		"max_delay":     rq.maxDelay.String(),
	}
}

// Panic Recovery Methods
func (pr *PanicRecovery) RecoverFromPanic(component string) {
	if r := recover(); r != nil {
		stack := make([]byte, 4096)
		length := runtime.Stack(stack, false)

		entry := PanicEntry{
			ID:        fmt.Sprintf("panic_%d", time.Now().Unix()),
			Message:   fmt.Sprintf("%v", r),
			Stack:     string(stack[:length]),
			Component: component,
			Timestamp: time.Now(),
			Recovered: true,
		}

		pr.mutex.Lock()
		pr.recoveries = append(pr.recoveries, entry)
		// Keep only last 100 panic entries
		if len(pr.recoveries) > 100 {
			pr.recoveries = pr.recoveries[len(pr.recoveries)-100:]
		}
		pr.mutex.Unlock()

		pr.logger.WithFields(logrus.Fields{
			"component": component,
			"panic_id":  entry.ID,
			"message":   entry.Message,
		}).Error("Panic recovered")
	}
}

func (pr *PanicRecovery) GetRecoveries() []PanicEntry {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()

	return pr.recoveries
}

func (pr *PanicRecovery) GetStats() map[string]interface{} {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()

	return map[string]interface{}{
		"total_recoveries": len(pr.recoveries),
		"last_recovery": func() interface{} {
			if len(pr.recoveries) > 0 {
				return pr.recoveries[len(pr.recoveries)-1].Timestamp
			}
			return nil
		}(),
	}
}

// Enhanced token database with valid cross-chain addresses
var enhancedTokens = map[string][]EnhancedToken{
	"ethereum": {
		{Symbol: "ETH", Name: "Ethereum", Decimals: 18, Address: "0x0000000000000000000000000000000000000000", Chain: "ethereum", IsNative: true, TotalSupply: "120000000"},
		{Symbol: "USDC", Name: "USD Coin", Decimals: 6, Address: "0xA0b86a33E6441E6C7D3E4C2C4C6C6C6C6C6C", Chain: "ethereum", IsNative: false, TotalSupply: "50000000000"},
		{Symbol: "USDT", Name: "Tether USD", Decimals: 6, Address: "0xdAC17F958D2ee523a2206206994597C13D831ec7", Chain: "ethereum", IsNative: false, TotalSupply: "80000000000"},
		{Symbol: "WBTC", Name: "Wrapped Bitcoin", Decimals: 8, Address: "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", Chain: "ethereum", IsNative: false, TotalSupply: "250000"},
		{Symbol: "LINK", Name: "Chainlink", Decimals: 18, Address: "0x514910771AF9Ca656af840dff83E8264EcF986CA", Chain: "ethereum", IsNative: false, TotalSupply: "1000000000"},
		{Symbol: "UNI", Name: "Uniswap", Decimals: 18, Address: "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", Chain: "ethereum", IsNative: false, TotalSupply: "1000000000"},
	},
	"solana": {
		{Symbol: "SOL", Name: "Solana", Decimals: 9, Address: "11111111111111111111111111111111", Chain: "solana", IsNative: true, TotalSupply: "500000000"},
		{Symbol: "USDC", Name: "USD Coin", Decimals: 6, Address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", Chain: "solana", IsNative: false, TotalSupply: "50000000000"},
		{Symbol: "USDT", Name: "Tether USD", Decimals: 6, Address: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", Chain: "solana", IsNative: false, TotalSupply: "80000000000"},
		{Symbol: "RAY", Name: "Raydium", Decimals: 6, Address: "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R", Chain: "solana", IsNative: false, TotalSupply: "555000000"},
		{Symbol: "SRM", Name: "Serum", Decimals: 6, Address: "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt", Chain: "solana", IsNative: false, TotalSupply: "10000000000"},
		{Symbol: "ORCA", Name: "Orca", Decimals: 6, Address: "orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE", Chain: "solana", IsNative: false, TotalSupply: "100000000"},
	},
	"blackhole": {
		{Symbol: "BHX", Name: "BlackHole Token", Decimals: 18, Address: "0xBH0000000000000000000000000000000000000000", Chain: "blackhole", IsNative: true, TotalSupply: "1000000000"},
		{Symbol: "BHUSDC", Name: "BlackHole USD Coin", Decimals: 6, Address: "0xBHUSDC000000000000000000000000000000000000", Chain: "blackhole", IsNative: false, TotalSupply: "10000000000"},
		{Symbol: "BHETH", Name: "BlackHole Ethereum", Decimals: 18, Address: "0xBHETH0000000000000000000000000000000000000", Chain: "blackhole", IsNative: false, TotalSupply: "21000000"},
		{Symbol: "BHSOL", Name: "BlackHole Solana", Decimals: 9, Address: "0xBHSOL0000000000000000000000000000000000000", Chain: "blackhole", IsNative: false, TotalSupply: "500000000"},
	},
}

// Helper functions for generating realistic data
func generateRandomAddress(chain string) string {
	switch chain {
	case "ethereum", "blackhole":
		return fmt.Sprintf("0x%x", rand.Uint64())
	case "solana":
		return generateSolanaAddress()
	default:
		return fmt.Sprintf("addr_%x", rand.Uint64())
	}
}

func getRandomToken(chain string) EnhancedToken {
	tokens := enhancedTokens[chain]
	if len(tokens) == 0 {
		return EnhancedToken{Symbol: "UNKNOWN", Name: "Unknown Token", Decimals: 18, Chain: chain}
	}
	return tokens[rand.Intn(len(tokens))]
}

func generateRealisticAmount(token EnhancedToken) string {
	var amount float64

	switch token.Symbol {
	case "ETH", "SOL", "BHX":
		amount = rand.Float64() * 10 // 0-10 native tokens
	case "USDC", "USDT", "BHUSDC":
		amount = rand.Float64() * 1000 // 0-1000 stablecoins
	case "WBTC":
		amount = rand.Float64() * 0.1 // 0-0.1 BTC
	default:
		amount = rand.Float64() * 100 // 0-100 other tokens
	}

	// Format based on decimals
	format := fmt.Sprintf("%%.%df", min(token.Decimals, 6))
	return fmt.Sprintf(format, amount)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func generateSolanaAddress() string {
	chars := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	result := make([]byte, 44)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func generateSolanaSignature() string {
	chars := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	result := make([]byte, 88)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

// Helper methods for SDK functionality
func (sdk *BridgeSDK) generateEventHash(tx *Transaction) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s",
		tx.ID, tx.Hash, tx.SourceChain, tx.DestChain,
		tx.SourceAddress, tx.DestAddress, tx.TokenSymbol, tx.Amount)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (sdk *BridgeSDK) isReplayAttack(hash string) bool {
	return sdk.replayProtection.isProcessed(hash)
}

func (sdk *BridgeSDK) markAsProcessed(hash string) error {
	return sdk.replayProtection.markProcessed(hash)
}

func (sdk *BridgeSDK) incrementBlockedReplays() {
	sdk.blockedMutex.Lock()
	defer sdk.blockedMutex.Unlock()
	sdk.blockedReplays++
}

func (sdk *BridgeSDK) saveTransaction(tx *Transaction) {
	sdk.transactionsMutex.Lock()
	defer sdk.transactionsMutex.Unlock()
	sdk.transactions[tx.ID] = tx

	// Also save to database
	sdk.db.Update(func(boltTx *bbolt.Tx) error {
		bucket := boltTx.Bucket([]byte("transactions"))
		if bucket == nil {
			return fmt.Errorf("transactions bucket not found")
		}

		data, err := json.Marshal(tx)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(tx.ID), data)
	})
}

func (sdk *BridgeSDK) addEvent(eventType, chain, txHash string, data map[string]interface{}) {
	sdk.eventsMutex.Lock()
	defer sdk.eventsMutex.Unlock()

	event := Event{
		ID:        fmt.Sprintf("event_%d", time.Now().UnixNano()),
		Type:      eventType,
		Chain:     chain,
		TxHash:    txHash,
		Timestamp: time.Now(),
		Data:      data,
		Processed: false,
	}

	sdk.events = append(sdk.events, event)

	// Keep only last 1000 events
	if len(sdk.events) > 1000 {
		sdk.events = sdk.events[len(sdk.events)-1000:]
	}

	// --- NEW: Sync to Validator and Token Modules ---
	// Sync to validator (if available)
	go func(ev Event) {
		defer func() { recover() }()
		// Import validation package if not already
		// Run bridge test suite for event validation
		// This is a no-op if validator is not initialized
		// (You may want to add a build tag or interface for real integration)
		// Example:
		// import "github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/validation"
		// if validation.GlobalValidator != nil {
		//     validation.GlobalValidator.RunTestSuite(context.Background(), "bridge_functionality")
		// }
	}(event)

	// Sync to token module (if available)
	go func(ev Event) {
		defer func() { recover() }()
		// Import token package if not already
		// Example: log as a token event if token registry is available
		// if sdk.blockchainInterface != nil && sdk.blockchainInterface.blockchain != nil {
		//     tokenMod := sdk.blockchainInterface.blockchain.TokenRegistry[ev.Data["token"].(string)]
		//     if tokenMod != nil {
		//         tokenMod.emitEvent(token.Event{
		//             Type: token.EventType(ev.Type),
		//             From: ev.Data["from"].(string),
		//             To: ev.Data["to"].(string),
		//             Amount: uint64(ev.Data["amount"].(float64)),
		//         })
		//     }
		// }
	}(event)
	// --- END NEW ---
}

// RelayToChain relays a transaction to the specified chain
func (sdk *BridgeSDK) RelayToChain(tx *Transaction, targetChain string) error {
	sdk.logger.Infof("🔄 Relaying transaction %s to %s", tx.ID, targetChain)

	// Handle BlackHole chain transactions with real blockchain
	if targetChain == "blackhole" && sdk.blockchainInterface != nil {
		sdk.logger.Infof("🔗 Processing real BlackHole blockchain transaction: %s", tx.ID)

		// Use real blockchain interface for BlackHole transactions
		err := sdk.blockchainInterface.ProcessBridgeTransaction(tx)
		if err != nil {
			sdk.logger.Errorf("❌ Failed to process BlackHole transaction: %v", err)
			tx.Status = "failed"
			now := time.Now()
			tx.CompletedAt = &now
			tx.ProcessingTime = fmt.Sprintf("%.1fs", time.Since(tx.CreatedAt).Seconds())
			sdk.saveTransaction(tx)
			return err
		}

		sdk.logger.Infof("✅ BlackHole transaction processed successfully: %s", tx.ID)
		sdk.saveTransaction(tx)
		return nil
	}

	// Simulate relay processing for external chains (ETH/SOL)
	sdk.logger.Infof("🎭 Simulating %s chain transaction: %s", targetChain, tx.ID)
	time.Sleep(time.Duration(2+rand.Intn(3)) * time.Second)

	tx.Status = "completed"
	now := time.Now()
	tx.CompletedAt = &now
	tx.ProcessingTime = fmt.Sprintf("%.1fs", time.Since(tx.CreatedAt).Seconds())
	sdk.saveTransaction(tx)

	return nil
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

	// Get real blockchain stats if available
	var blackholeStats ChainStats
	if sdk.blockchainInterface != nil {
		blockchainData := sdk.blockchainInterface.GetBlockchainStats()
		blackholeStats = ChainStats{
			Transactions: blockchainData["transactions"].(int),
			Volume:       "20.2", // Keep mock volume for now
			SuccessRate:  98.1,   // Keep mock success rate
			LastBlock:    uint64(blockchainData["blocks"].(int)),
		}
	} else {
		blackholeStats = ChainStats{
			Transactions: completed / 3,
			Volume:       "20.2",
			SuccessRate:  98.1,
			LastBlock:    1500000,
		}
	}

	return &BridgeStats{
		TotalTransactions:     total,
		PendingTransactions:   pending,
		CompletedTransactions: completed,
		FailedTransactions:    failed,
		SuccessRate:           successRate,
		TotalVolume:           "125.5",
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
			"blackhole": blackholeStats,
		},
		Last24h: PeriodStats{
			Transactions: total / 10,
			Volume:       "15.5",
			SuccessRate:  successRate,
		},
		ErrorRate:             float64(failed) / float64(total) * 100,
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

// GetErrorMetrics returns error metrics
func (sdk *BridgeSDK) GetErrorMetrics() *ErrorMetrics {
	sdk.errorHandler.mutex.RLock()
	defer sdk.errorHandler.mutex.RUnlock()

	total := len(sdk.errorHandler.errors)
	errorsByType := make(map[string]int)

	for _, err := range sdk.errorHandler.errors {
		errorsByType[err.Type]++
	}

	recentErrors := sdk.errorHandler.errors
	if len(recentErrors) > 10 {
		recentErrors = recentErrors[len(recentErrors)-10:]
	}

	return &ErrorMetrics{
		ErrorRate:    2.5,
		TotalErrors:  total,
		ErrorsByType: errorsByType,
		RecentErrors: recentErrors,
	}
}

// getBlockedReplays safely gets the blocked replays count
func (sdk *BridgeSDK) getBlockedReplays() int64 {
	sdk.blockedMutex.RLock()
	defer sdk.blockedMutex.RUnlock()
	return sdk.blockedReplays
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

// GetCircuitBreakerStatus returns circuit breaker status
func (sdk *BridgeSDK) GetCircuitBreakerStatus() map[string]*CircuitBreaker {
	result := make(map[string]*CircuitBreaker)
	for name, cb := range sdk.circuitBreakers {
		result[name] = cb
	}
	return result
}

// GetFailedEvents returns failed events
func (sdk *BridgeSDK) GetFailedEvents() []FailedEvent {
	sdk.eventRecovery.mutex.RLock()
	defer sdk.eventRecovery.mutex.RUnlock()

	return sdk.eventRecovery.failedEvents
}

// GetProcessedEvents returns recently processed events
func (sdk *BridgeSDK) GetProcessedEvents() []Event {
	sdk.eventsMutex.RLock()
	defer sdk.eventsMutex.RUnlock()

	// Return last 100 events
	start := 0
	if len(sdk.events) > 100 {
		start = len(sdk.events) - 100
	}

	return sdk.events[start:]
}

// GetReplayProtectionStatus returns replay protection status
func (sdk *BridgeSDK) GetReplayProtectionStatus() map[string]interface{} {
	sdk.replayProtection.mutex.RLock()
	defer sdk.replayProtection.mutex.RUnlock()

	// Find oldest entry
	var oldestEntry *time.Time
	for _, timestamp := range sdk.replayProtection.processedHashes {
		if oldestEntry == nil || timestamp.Before(*oldestEntry) {
			oldestEntry = &timestamp
		}
	}

	return map[string]interface{}{
		"enabled":          sdk.replayProtection.enabled,
		"processed_hashes": len(sdk.replayProtection.processedHashes),
		"blocked_replays":  sdk.getBlockedReplays(),
		"cache_size":       10000,
		"oldest_entry":     oldestEntry,
		"cleanup_interval": "1h",
		"last_cleanup":     time.Now().Add(-1 * time.Hour),
		"protection_rate": func() float64 {
			total := int64(len(sdk.replayProtection.processedHashes)) + sdk.getBlockedReplays()
			if total == 0 {
				return 100.0
			}
			return float64(len(sdk.replayProtection.processedHashes)) / float64(total) * 100.0
		}(),
	}
}

// StartWebServer starts the web server with all endpoints
func (sdk *BridgeSDK) StartWebServer(addr string) error {
	r := mux.NewRouter()

	// Main dashboard
	r.HandleFunc("/", sdk.handleDashboard).Methods("GET")

	// --- NEW: Infra Dashboard and API endpoints ---
	r.HandleFunc("/infra-dashboard", sdk.handleInfraDashboard).Methods("GET")
	r.HandleFunc("/infra/listener-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data := map[string]interface{}{
			"ethereum":   "unknown",
			"solana":     "unknown",
			"blackhole":  "unknown",
			"last_event": nil,
		}
		if sdk.circuitBreakers != nil {
			if cb, ok := sdk.circuitBreakers["ethereum_listener"]; ok {
				data["ethereum"] = cb.getState()
			}
			if cb, ok := sdk.circuitBreakers["solana_listener"]; ok {
				data["solana"] = cb.getState()
			}
			if cb, ok := sdk.circuitBreakers["blackhole_listener"]; ok {
				data["blackhole"] = cb.getState()
			}
		}
		if len(sdk.events) > 0 {
			data["last_event"] = sdk.events[len(sdk.events)-1].Timestamp.Format(time.RFC3339)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    data,
		})
	}).Methods("GET")
	r.HandleFunc("/infra/retry-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := sdk.retryQueue.GetStats()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    stats,
		})
	}).Methods("GET")
	r.HandleFunc("/infra/relay-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data := map[string]interface{}{
			"relay_server": "running",
			"last_relay":   nil,
		}
		if len(sdk.events) > 0 {
			for i := len(sdk.events) - 1; i >= 0; i-- {
				if sdk.events[i].Type == "relay" {
					data["last_relay"] = sdk.events[i].Timestamp.Format(time.RFC3339)
					break
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    data,
		})
	}).Methods("GET")
	r.HandleFunc("/mock/bridge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Create a mock transaction event
		tx := &Transaction{
			ID:            fmt.Sprintf("mock_%d", time.Now().UnixNano()),
			Hash:          fmt.Sprintf("0xMOCK_%d", time.Now().UnixNano()),
			SourceChain:   "ethereum",
			DestChain:     "solana",
			SourceAddress: "0xMOCK_SOURCE",
			DestAddress:   "MOCK_DEST",
			TokenSymbol:   "USDC",
			Amount:        "123.45",
			Fee:           "0.001",
			Status:        "pending",
			CreatedAt:     time.Now(),
			Confirmations: 0,
			BlockNumber:   99999999,
		}
		sdk.saveTransaction(tx)
		sdk.addEvent("relay", "ethereum", tx.Hash, map[string]interface{}{
			"amount": tx.Amount,
			"token":  tx.TokenSymbol,
			"from":   tx.SourceAddress,
			"to":     tx.DestAddress,
		})
		// Simulate relay processing
		err := sdk.RelayToChain(tx, tx.DestChain)
		result := map[string]interface{}{
			"mock":           "event sent",
			"transaction_id": tx.ID,
			"status":         tx.Status,
			"timestamp":      time.Now().Format(time.RFC3339),
		}
		if err != nil {
			result["relay_error"] = err.Error()
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    result,
		})
	}).Methods("POST")
	// --- END NEW ---

	// --- NEW: Log/Event/Status Endpoints ---
	r.HandleFunc("/log/event", sdk.handleLogEvent).Methods("GET")
	r.HandleFunc("/log/retry", sdk.handleLogRetry).Methods("GET")
	r.HandleFunc("/bridge/status", sdk.handleBridgeStatus).Methods("GET")
	// --- END NEW ---

	// API endpoints
	r.HandleFunc("/health", sdk.handleHealth).Methods("GET")
	r.HandleFunc("/stats", sdk.handleStats).Methods("GET")
	r.HandleFunc("/transactions", sdk.handleTransactions).Methods("GET")
	r.HandleFunc("/transaction/{id}", sdk.handleTransactionDetail).Methods("GET")
	r.HandleFunc("/errors", sdk.handleErrors).Methods("GET")
	r.HandleFunc("/circuit-breakers", sdk.handleCircuitBreakers).Methods("GET")
	r.HandleFunc("/failed-events", sdk.handleFailedEvents).Methods("GET")
	r.HandleFunc("/replay-protection", sdk.handleReplayProtection).Methods("GET")
	r.HandleFunc("/processed-events", sdk.handleProcessedEvents).Methods("GET")
	r.HandleFunc("/logs", sdk.handleDocs).Methods("GET")
	r.HandleFunc("/docs", sdk.handleDocs).Methods("GET")
	r.HandleFunc("/retry-queue", sdk.handleRetryQueue).Methods("GET")
	r.HandleFunc("/panic-recovery", sdk.handlePanicRecovery).Methods("GET")
	r.HandleFunc("/simulation", sdk.handleSimulation).Methods("GET")
	r.HandleFunc("/api/simulation/run", sdk.handleRunSimulation).Methods("POST")

	// Static file serving for logo and media
	r.HandleFunc("/blackhole-logo.jpg", sdk.handleLogo).Methods("GET")
	r.PathPrefix("/media/").Handler(http.StripPrefix("/media/", http.FileServer(http.Dir("../media/"))))

	// Transfer endpoints
	r.HandleFunc("/transfer", sdk.handleTransfer).Methods("POST")
	r.HandleFunc("/relay", sdk.handleRelay).Methods("POST")

	// WebSocket endpoints
	r.HandleFunc("/ws/logs", sdk.handleWebSocketLogs)
	r.HandleFunc("/ws/events", sdk.handleWebSocketEvents)
	r.HandleFunc("/ws/metrics", sdk.handleWebSocketMetrics)

	// Add CORS headers
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// Register advanced infra-dashboard endpoints
	r.HandleFunc("/core/validator-status", sdk.handleCoreValidatorStatus).Methods("GET")
	r.HandleFunc("/core/token-stats", sdk.handleCoreTokenStats).Methods("GET")
	r.HandleFunc("/core/block-height", sdk.handleCoreBlockHeight).Methods("GET")
	r.HandleFunc("/core/peer-count", sdk.handleCorePeerCount).Methods("GET")

	sdk.logger.Infof("🌐 Starting web server on %s", addr)
	return http.ListenAndServe(addr, r)
}

// HTTP Handlers
func (sdk *BridgeSDK) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := sdk.GetHealth()
	response := map[string]interface{}{
		"success": true,
		"data":    health,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := sdk.GetBridgeStats()
	response := map[string]interface{}{
		"success": true,
		"data":    stats,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleTransactions(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")

	var transactions []*Transaction
	var err error

	if status != "" {
		transactions, err = sdk.GetTransactionsByStatus(status)
	} else {
		transactions, err = sdk.GetAllTransactions()
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"transactions": transactions,
			"total":        len(transactions),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleTransactionDetail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	tx, err := sdk.GetTransactionStatus(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    tx,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleErrors(w http.ResponseWriter, r *http.Request) {
	errors := sdk.GetErrorMetrics()
	response := map[string]interface{}{
		"success": true,
		"data":    errors,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleCircuitBreakers(w http.ResponseWriter, r *http.Request) {
	breakers := sdk.GetCircuitBreakerStatus()
	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"circuit_breakers": breakers,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleFailedEvents(w http.ResponseWriter, r *http.Request) {
	events := sdk.GetFailedEvents()
	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"failed_events": events,
			"total":         len(events),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleReplayProtection(w http.ResponseWriter, r *http.Request) {
	status := sdk.GetReplayProtectionStatus()
	response := map[string]interface{}{
		"success": true,
		"data":    status,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// --- STUBS for missing handler methods to fix linter errors ---
func (sdk *BridgeSDK) handleInfraDashboard(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlackHole Bridge Infra Dashboard</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #181a20;
            color: #e5e7eb;
            margin: 0;
            padding: 0;
        }
        .infra-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 32px 16px 16px 16px;
        }
        .infra-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 32px;
        }
        .infra-header h1 {
            font-size: 2.2rem;
            color: #60a5fa;
            margin: 0;
            letter-spacing: 1px;
        }
        .infra-header button {
            background: #23272f;
            color: #60a5fa;
            border: none;
            border-radius: 8px;
            padding: 10px 22px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        .infra-header button:hover {
            background: #374151;
        }
        .infra-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
            gap: 24px;
        }
        .infra-card {
            background: #23272f;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(37,99,235,0.07);
            padding: 24px 20px;
            display: flex;
            flex-direction: column;
            margin-bottom: 16px;
        }
        .infra-card h2 {
            color: #60a5fa;
            font-size: 1.2rem;
            margin-bottom: 12px;
        }
        .section-content {
            font-size: 1rem;
            color: #e5e7eb;
        }
        .modular {
            cursor: move;
        }
        .mock-btn {
            background: #60a5fa;
            color: #181a20;
            border: none;
            border-radius: 6px;
            padding: 8px 18px;
            font-weight: 600;
            cursor: pointer;
            font-size: 1rem;
            margin-top: 10px;
        }
        .mock-btn:hover {
            background: #2563eb;
            color: #fff;
        }
        .nav-link {
            color: #60a5fa;
            text-decoration: underline;
            cursor: pointer;
        }
        @media (max-width: 900px) {
            .infra-header { flex-direction: column; align-items: flex-start; }
        }
        @media (max-width: 600px) {
            .infra-container { padding: 10px; }
            .infra-card { padding: 12px 6px; }
        }
    </style>
</head>
<body>
    <div class="infra-container">
        <div class="infra-header">
            <h1>Infra Dashboard</h1>
            <button onclick="window.location.href='/'">Back to Main Dashboard</button>
        </div>
        <div class="infra-grid" id="infraGrid">
            <div class="infra-card modular" draggable="true" id="listenerCard">
                <h2>Listener Status</h2>
                <div class="section-content" id="listenerStatus">Loading...</div>
            </div>
            <div class="infra-card modular" draggable="true" id="retryCard">
                <h2>Retry Queue</h2>
                <div class="section-content" id="retryStatus">Loading...</div>
            </div>
            <div class="infra-card modular" draggable="true" id="relayCard">
                <h2>Relay Server</h2>
                <div class="section-content" id="relayStatus">Loading...</div>
            </div>
            <div class="infra-card modular" draggable="true" id="eventLogCard">
                <h2>Bridge Events</h2>
                <div class="section-content" id="eventLogStatus">Loading...</div>
            </div>
            <div class="infra-card modular" draggable="true" id="bridgeStatusCard">
                <h2>Bridge Status</h2>
                <div class="section-content" id="bridgeStatusSection">Loading...</div>
            </div>
            <div class="infra-card modular" draggable="true" id="mockCard">
                <h2>Mock Endpoint</h2>
                <div class="section-content" id="mockStatus">Ready for test.<br><button class="mock-btn" onclick="triggerMock()">Send Mock Event</button></div>
            </div>
            <div class="infra-card modular" draggable="true" id="validatorStatusCard">
                <h2>Validator Status</h2>
                <div class="section-content" id="validatorStatus">Loading...</div>
            </div>
            <div class="infra-card modular" draggable="true" id="tokenStatsCard">
                <h2>Token Stats</h2>
                <div class="section-content" id="tokenStats">Loading...</div>
            </div>
            <div class="infra-card modular" draggable="true" id="blockHeightCard">
                <h2>Block Height</h2>
                <div class="section-content" id="blockHeight">Loading...</div>
            </div>
            <div class="infra-card modular" draggable="true" id="peerCountCard">
                <h2>Peer Count</h2>
                <div class="section-content" id="peerCount">Loading...</div>
            </div>
            <div class="infra-card modular" draggable="true" id="systemUsageCard">
                <h2>System Usage</h2>
                <div class="section-content" id="systemUsage">Loading...</div>
            </div>
        </div>
    </div>
    <script>
        // Modular rearrangeable cards (drag and drop)
        const grid = document.getElementById('infraGrid');
        let dragged;
        document.querySelectorAll('.modular').forEach(card => {
            card.addEventListener('dragstart', e => { dragged = card; });
            card.addEventListener('dragover', e => { e.preventDefault(); });
            card.addEventListener('drop', e => {
                e.preventDefault();
                if (dragged && dragged !== card) {
                    grid.insertBefore(dragged, card.nextSibling);
                }
            });
        });
        // Fetch and update status sections
        async function updateInfraSections() {
            // Listener status
            try {
                const res = await fetch('/infra/listener-status');
                const data = await res.json();
                document.getElementById('listenerStatus').textContent = data.success ? JSON.stringify(data.data, null, 2) : 'Error loading listener status';
            } catch (e) { document.getElementById('listenerStatus').textContent = 'Error loading listener status'; }
            // Retry queue
            try {
                const res = await fetch('/infra/retry-status');
                const data = await res.json();
                document.getElementById('retryStatus').textContent = data.success ? JSON.stringify(data.data, null, 2) : 'Error loading retry status';
            } catch (e) { document.getElementById('retryStatus').textContent = 'Error loading retry status'; }
            // Relay server
            try {
                const res = await fetch('/infra/relay-status');
                const data = await res.json();
                document.getElementById('relayStatus').textContent = data.success ? JSON.stringify(data.data, null, 2) : 'Error loading relay status';
            } catch (e) { document.getElementById('relayStatus').textContent = 'Error loading relay status'; }
            // Bridge events
            try {
                const res = await fetch('/log/event');
                const data = await res.json();
                if (data.success && data.data && data.data.events) {
                    document.getElementById('eventLogStatus').textContent = JSON.stringify(data.data.events.slice(-10), null, 2);
                } else {
                    document.getElementById('eventLogStatus').textContent = 'No events found';
                }
            } catch (e) { document.getElementById('eventLogStatus').textContent = 'Error loading events'; }
            // Bridge status
            try {
                const res = await fetch('/bridge/status');
                const data = await res.json();
                if (data.success && data.data) {
                    document.getElementById('bridgeStatusSection').textContent = JSON.stringify(data.data, null, 2);
                } else {
                    document.getElementById('bridgeStatusSection').textContent = 'No status found';
                }
            } catch (e) { document.getElementById('bridgeStatusSection').textContent = 'Error loading bridge status'; }
            // Validator status
            try {
                const res = await fetch('/core/validator-status');
                const data = await res.json();
                if (data.success && data.data) {
                    let html = '<b>Active:</b> ' + data.data.validators_active + '<br>';
                    html += '<b>Validators:</b> ' + (data.data.validators ? data.data.validators.join(', ') : '-') + '<br>';
                    if (data.data.results) {
                        html += '<b>Latest Results:</b><br><pre>' + JSON.stringify(data.data.results, null, 2) + '</pre>';
                    }
                    html += '<b>Status:</b> ' + data.data.status;
                    document.getElementById('validatorStatus').innerHTML = html;
                } else {
                    document.getElementById('validatorStatus').textContent = 'No validator data';
                }
            } catch (e) { document.getElementById('validatorStatus').textContent = 'Error loading validator status'; }
            // Token stats
            try {
                const res = await fetch('/core/token-stats');
                const data = await res.json();
                if (data.success && data.data) {
                    let html = '<table style="width:100%;color:#e5e7eb;background:#23272f;border-radius:8px;"><tr><th>Symbol</th><th>Name</th><th>Decimals</th><th>Circulating</th><th>Max</th><th>Utilization (%)</th></tr>';
                    for (const t of data.data) {
                        html += `<tr><td>${t.symbol}</td><td>${t.name}</td><td>${t.decimals}</td><td>${t.circulatingSupply}</td><td>${t.maxSupply}</td><td>${t.utilization.toFixed(2)}</td></tr>`;
                    }
                    html += '</table>';
                    document.getElementById('tokenStats').innerHTML = html;
                } else {
                    document.getElementById('tokenStats').textContent = 'No token data';
                }
            } catch (e) { document.getElementById('tokenStats').textContent = 'Error loading token stats'; }
            // Block height
            try {
                const res = await fetch('/core/block-height');
                const data = await res.json();
                document.getElementById('blockHeight').textContent = data.success ? data.data.height : 'Error';
            } catch (e) { document.getElementById('blockHeight').textContent = 'Error loading block height'; }
            // Peer count
            try {
                const res = await fetch('/core/peer-count');
                const data = await res.json();
                document.getElementById('peerCount').textContent = data.success ? data.data.count : 'Error';
            } catch (e) { document.getElementById('peerCount').textContent = 'Error loading peer count'; }
            // System usage (placeholder)
            document.getElementById('systemUsage').textContent = 'CPU/Memory/Net: (TODO)';
        }
        // Auto-refresh every 5 seconds
        setInterval(updateInfraSections, 5000);
        updateInfraSections();
        // WebSocket for live event streaming
        let ws;
        function connectEventWS() {
            ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws/events');
            ws.onmessage = function(event) {
                try {
                    const ev = JSON.parse(event.data);
                    // Prepend new event to event log
                    let log = document.getElementById('eventLogStatus');
                    let current = log.textContent;
                    let newEntry = JSON.stringify(ev, null, 2) + '\n' + current;
                    log.textContent = newEntry.substring(0, 4000); // Limit log size
                } catch (e) {}
            };
            ws.onclose = function() {
                setTimeout(connectEventWS, 3000);
            };
        }
        connectEventWS();
    </script>
</body>
</html>`))
}

func (sdk *BridgeSDK) handleLogEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	events := sdk.GetProcessedEvents()
	result := make([]interface{}, len(events))
	for i, ev := range events {
		result[i] = ev
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"events": result,
			"total": len(result),
		},
	})
}

func (sdk *BridgeSDK) handleLogRetry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := sdk.retryQueue.GetStats()
	items := sdk.retryQueue.items
	queue := make([]interface{}, len(items))
	for i, item := range items {
		queue[i] = item
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"status": "OK",
			"queue": queue,
			"stats": stats,
		},
	})
}

func (sdk *BridgeSDK) handleBridgeStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	health := sdk.GetHealth()
	var lastEvent interface{} = nil
	events := sdk.GetProcessedEvents()
	if len(events) > 0 {
		lastEvent = events[len(events)-1]
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"status": health.Status,
			"uptime": health.Uptime,
			"last_event": lastEvent,
		},
	})
}

func (sdk *BridgeSDK) handleProcessedEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": map[string]interface{}{"processed_events": []interface{}{}, "total_processed": 0, "average_processing_time": "0s"}})
}

func (sdk *BridgeSDK) handleDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<html><body><h1>API Docs (TODO)</h1></body></html>"))
}

func (sdk *BridgeSDK) handleRetryQueue(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": map[string]interface{}{"status": "TODO"}})
}

func (sdk *BridgeSDK) handlePanicRecovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": map[string]interface{}{"status": "TODO"}})
}

func (sdk *BridgeSDK) handleSimulation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<html><body><h1>Simulation (TODO)</h1></body></html>"))
}

func (sdk *BridgeSDK) handleRunSimulation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": map[string]interface{}{"status": "TODO"}})
}

func (sdk *BridgeSDK) handleLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write([]byte("<svg><!-- TODO: Logo --></svg>"))
}

func (sdk *BridgeSDK) handleTransfer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": map[string]interface{}{"status": "TODO"}})
}

func (sdk *BridgeSDK) handleRelay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": map[string]interface{}{"status": "TODO"}})
}

func (sdk *BridgeSDK) handleWebSocketLogs(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("WebSocket logs (TODO)"))
}

func (sdk *BridgeSDK) handleWebSocketEvents(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("WebSocket events (TODO)"))
}

func (sdk *BridgeSDK) handleWebSocketMetrics(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("WebSocket metrics (TODO)"))
}

// --- STUBS for /core/* endpoints to fix linter errors ---
func (sdk *BridgeSDK) handleCoreValidatorStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var data map[string]interface{}
	// Try to get validator results from core blockchain
	if sdk.blockchainInterface != nil && sdk.blockchainInterface.blockchain != nil {
		// Try to get validator info from blockchain
		validatorList := []string{}
		validatorsActive := 0
		if sdk.blockchainInterface.blockchain.StakeLedger != nil {
			stakes := sdk.blockchainInterface.blockchain.StakeLedger.GetAllStakes()
			for addr, stake := range stakes {
				if stake > 0 {
					validatorList = append(validatorList, addr)
					validatorsActive++
				}
			}
		}
		// Try to get latest validator results if available
		var results interface{} = nil
		// If you have a global validator instance, use it
		// (This is a placeholder; wire up your validator as needed)
		// Example: results = validation.GlobalValidator.GetLatestResults(5)
		data = map[string]interface{}{
			"validators_active": validatorsActive,
			"validators":        validatorList,
			"results":           results,
			"status":            "healthy",
		}
	} else {
		data = map[string]interface{}{
			"validators_active": 3,
			"validators":        []string{"validator1", "validator2", "validator3"},
			"results":           nil,
			"status":            "simulation",
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": data})
}

func (sdk *BridgeSDK) handleCoreTokenStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var tokens []map[string]interface{}
	if sdk.blockchainInterface != nil && sdk.blockchainInterface.blockchain != nil {
		info := sdk.blockchainInterface.blockchain.GetBlockchainInfo()
		if reg, ok := info["tokenRegistry"].(map[string]interface{}); ok {
			for symbol, t := range reg {
				tok := t.(map[string]interface{})
				tokens = append(tokens, map[string]interface{}{
					"symbol":            symbol,
					"name":              tok["name"],
					"decimals":          tok["decimals"],
					"circulatingSupply": tok["circulatingSupply"],
					"maxSupply":         tok["maxSupply"],
					"utilization":       tok["utilization"],
				})
			}
		}
	} else {
		tokens = []map[string]interface{}{
			{"symbol": "BHX", "name": "BlackHole Token", "decimals": 18, "circulatingSupply": 100000000, "maxSupply": 1000000000, "utilization": 10.0},
			{"symbol": "USDC", "name": "USD Coin", "decimals": 6, "circulatingSupply": 500000000, "maxSupply": 50000000000, "utilization": 1.0},
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": tokens})
}

func (sdk *BridgeSDK) handleCoreBlockHeight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	height := 0
	if sdk.blockchainInterface != nil && sdk.blockchainInterface.blockchain != nil {
		height = len(sdk.blockchainInterface.blockchain.Blocks)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": map[string]interface{}{"height": height}})
}

func (sdk *BridgeSDK) handleCorePeerCount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	count := 0
	if sdk.blockchainInterface != nil && sdk.blockchainInterface.blockchain != nil && sdk.blockchainInterface.blockchain.P2PNode != nil {
		count = sdk.blockchainInterface.blockchain.P2PNode.PeerCount()
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": map[string]interface{}{"count": count}})
}
