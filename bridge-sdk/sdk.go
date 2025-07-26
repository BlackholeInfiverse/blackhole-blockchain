package bridgesdk

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/bridge/core"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"go.uber.org/zap"
)

// BridgeSDK is the main SDK interface for bridge operations
type BridgeSDK struct {
	config           *BridgeSDKConfig
	Logger           *BridgeLogger
	LogStreamer      *LogStreamer
	TransferManager  *core.TokenTransferManager
	ethListener      *EthereumListener
	solanaListener   *SolanaListener
	relay            *BridgeRelay
	blockchain       *chain.Blockchain
	errorHandler     *ErrorHandler
	recoverySystem   *EventRecoverySystem
	replayProtection *ReplayProtection
	isInitialized    bool
	isShuttingDown   bool
	mu               sync.RWMutex
	shutdownChan     chan struct{}
}

// NewBridgeSDK creates a new instance of the Bridge SDK
func NewBridgeSDK(blockchain *chain.Blockchain, config *BridgeSDKConfig) *BridgeSDK {
	if config == nil {
		config = DefaultConfig()
	}

	// Initialize structured logger first
	logger, err := NewBridgeLogger(DefaultLoggerConfig())
	if err != nil {
		// Fallback to basic logging if structured logger fails
		fmt.Printf("⚠️ Failed to initialize structured logger: %v\n", err)
		logger = nil
	}

	// Initialize error handler
	errorHandler := NewErrorHandler(&config.ErrorHandling)

	sdk := &BridgeSDK{
		config:       config,
		Logger:       logger,
		blockchain:   blockchain,
		errorHandler: errorHandler,
		shutdownChan: make(chan struct{}),
	}

	// Initialize log streamer if logger is available
	if logger != nil {
		sdk.LogStreamer = NewLogStreamer(logger)
		logger.Info("sdk", "Bridge SDK logger initialized successfully")
	}

	// Initialize token transfer manager
	factory := &core.TransferManagerFactory{}
	transferManager, err := factory.CreateConfiguredTransferManager()
	if err != nil {
		if logger != nil {
			logger.Error("sdk", "Failed to initialize token transfer manager", err)
		} else {
			log.Printf("⚠️ Failed to initialize token transfer manager: %v", err)
		}
	} else {
		sdk.TransferManager = transferManager
		if logger != nil {
			logger.Info("sdk", "Token transfer manager initialized successfully")
		}
	}

	// Initialize the relay with error handler
	sdk.relay = NewBridgeRelay(blockchain, &config.Relay, &config.Retry, errorHandler)
	sdk.relay.SetEventHandler(sdk.relay) // Use relay as its own event handler

	// Initialize event recovery system
	sdk.recoverySystem = NewEventRecoverySystem(errorHandler, sdk.relay)

	// Initialize replay protection
	replayProtection, err := NewReplayProtection("./data")
	if err != nil {
		log.Printf("⚠️ Warning: Failed to initialize replay protection: %v", err)
		// Continue without replay protection
	} else {
		sdk.replayProtection = replayProtection
	}

	return sdk
}

// Initialize initializes the SDK components
func (sdk *BridgeSDK) Initialize() error {
	defer sdk.errorHandler.RecoverFromPanic("bridge-sdk-initialize")

	sdk.mu.Lock()
	defer sdk.mu.Unlock()

	if sdk.isInitialized {
		return fmt.Errorf("SDK is already initialized")
	}

	log.Println("🚀 Initializing Bridge SDK...")

	// Initialize Ethereum listener with error handler, recovery system, and replay protection
	ethListener, err := NewEthereumListener(&sdk.config.Listeners, &sdk.config.Retry, sdk.relay, sdk.errorHandler, sdk.recoverySystem, sdk.replayProtection)
	if err != nil {
		sdk.errorHandler.recordFailure("sdk-initialization", err)
		return fmt.Errorf("failed to initialize Ethereum listener: %v", err)
	}
	sdk.ethListener = ethListener

	// Initialize Solana listener with error handler, recovery system, and replay protection
	sdk.solanaListener = NewSolanaListener(&sdk.config.Listeners, &sdk.config.Retry, sdk.relay, sdk.errorHandler, sdk.recoverySystem, sdk.replayProtection)

	// Start event recovery system
	sdk.recoverySystem.Start()

	sdk.isInitialized = true
	sdk.errorHandler.updateHealthStatus("bridge-sdk", "healthy", "")
	log.Println("✅ Bridge SDK initialized successfully")

	return nil
}

// StartEthListener starts the Ethereum blockchain listener
func (sdk *BridgeSDK) StartEthListener() error {
	defer sdk.errorHandler.RecoverFromPanic("bridge-sdk-start-eth-listener")

	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.isShuttingDown {
		return fmt.Errorf("SDK is shutting down")
	}

	if !sdk.isInitialized {
		return fmt.Errorf("SDK not initialized. Call Initialize() first")
	}

	if sdk.ethListener == nil {
		return fmt.Errorf("Ethereum listener not available")
	}

	if sdk.ethListener.IsRunning() {
		return fmt.Errorf("Ethereum listener is already running")
	}

	log.Println("🔗 Starting Ethereum listener...")

	// Use retry logic for starting the listener
	return sdk.errorHandler.WithRetry("start-ethereum-listener", func() error {
		return sdk.ethListener.Start()
	}, &sdk.config.Retry)
}

// StartSolanaListener starts the Solana blockchain listener
func (sdk *BridgeSDK) StartSolanaListener() error {
	defer sdk.errorHandler.RecoverFromPanic("bridge-sdk-start-solana-listener")

	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.isShuttingDown {
		return fmt.Errorf("SDK is shutting down")
	}

	if !sdk.isInitialized {
		return fmt.Errorf("SDK not initialized. Call Initialize() first")
	}

	if sdk.solanaListener == nil {
		return fmt.Errorf("Solana listener not available")
	}

	if sdk.solanaListener.IsRunning() {
		return fmt.Errorf("Solana listener is already running")
	}

	log.Println("🔗 Starting Solana listener...")

	// Use retry logic for starting the listener
	return sdk.errorHandler.WithRetry("start-solana-listener", func() error {
		return sdk.solanaListener.Start()
	}, &sdk.config.Retry)
}

// StartAllListeners starts all available blockchain listeners
func (sdk *BridgeSDK) StartAllListeners() error {
	var errors []error

	if err := sdk.StartEthListener(); err != nil {
		errors = append(errors, fmt.Errorf("Ethereum listener: %v", err))
	}

	if err := sdk.StartSolanaListener(); err != nil {
		errors = append(errors, fmt.Errorf("Solana listener: %v", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to start some listeners: %v", errors)
	}

	log.Println("🌟 All listeners started successfully")
	return nil
}

// StopEthListener stops the Ethereum blockchain listener
func (sdk *BridgeSDK) StopEthListener() {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.ethListener != nil {
		sdk.ethListener.Stop()
	}
}

// StopSolanaListener stops the Solana blockchain listener
func (sdk *BridgeSDK) StopSolanaListener() {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.solanaListener != nil {
		sdk.solanaListener.Stop()
	}
}

// StopAllListeners stops all blockchain listeners
func (sdk *BridgeSDK) StopAllListeners() {
	log.Println("🛑 Stopping all listeners...")
	sdk.StopEthListener()
	sdk.StopSolanaListener()
	log.Println("✅ All listeners stopped")
}

// RelayToChain relays a transaction to the specified target chain
func (sdk *BridgeSDK) RelayToChain(txID string, targetChain ChainType) error {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if !sdk.isInitialized {
		return fmt.Errorf("SDK not initialized. Call Initialize() first")
	}

	if sdk.relay == nil {
		return fmt.Errorf("relay not available")
	}

	// Get the transaction
	tx, err := sdk.relay.GetTransaction(txID)
	if err != nil {
		return fmt.Errorf("failed to get transaction: %v", err)
	}

	// Relay to the target chain
	return sdk.relay.RelayToChain(tx, targetChain)
}

// GetTransactionStatus returns the status of a transaction
func (sdk *BridgeSDK) GetTransactionStatus(txID string) (string, error) {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.relay == nil {
		return "", fmt.Errorf("relay not available")
	}

	return sdk.relay.GetTransactionStatus(txID)
}

// GetTransaction returns a transaction by ID
func (sdk *BridgeSDK) GetTransaction(txID string) (*RelayTransaction, error) {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.relay == nil {
		return nil, fmt.Errorf("relay not available")
	}

	return sdk.relay.GetTransaction(txID)
}

// GetAllTransactions returns all transactions
func (sdk *BridgeSDK) GetAllTransactions() []*RelayTransaction {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.relay == nil {
		return nil
	}

	return sdk.relay.GetAllTransactions()
}

// GetTransactionsByStatus returns transactions with the specified status
func (sdk *BridgeSDK) GetTransactionsByStatus(status string) []*RelayTransaction {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.relay == nil {
		return nil
	}

	return sdk.relay.GetTransactionsByStatus(status)
}

// GetTransactionsByChain returns transactions for the specified chain
func (sdk *BridgeSDK) GetTransactionsByChain(chain ChainType) []*RelayTransaction {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.relay == nil {
		return nil
	}

	return sdk.relay.GetTransactionsByChain(chain)
}

// GetStats returns bridge statistics
func (sdk *BridgeSDK) GetStats() map[string]interface{} {
	defer sdk.errorHandler.RecoverFromPanic("bridge-sdk-get-stats")

	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.relay == nil {
		return map[string]interface{}{
			"error": "relay not available",
		}
	}

	stats := sdk.relay.GetStats()

	// Add listener status
	stats["eth_listener_running"] = sdk.ethListener != nil && sdk.ethListener.IsRunning()
	stats["solana_listener_running"] = sdk.solanaListener != nil && sdk.solanaListener.IsRunning()
	stats["sdk_initialized"] = sdk.isInitialized
	stats["sdk_shutting_down"] = sdk.isShuttingDown

	// Add error handling metrics
	errorMetrics := sdk.errorHandler.GetMetrics()
	stats["total_errors"] = errorMetrics.TotalErrors
	stats["recovery_count"] = errorMetrics.RecoveryCount
	stats["errors_by_type"] = errorMetrics.ErrorsByType

	// Add health status summary
	healthStatus := sdk.errorHandler.GetHealthStatus()
	healthySystems := 0
	totalSystems := len(healthStatus)
	for _, health := range healthStatus {
		if health.Status == "healthy" {
			healthySystems++
		}
	}
	stats["health_score"] = float64(healthySystems) / float64(totalSystems) * 100

	// Add circuit breaker status
	circuitBreakers := sdk.errorHandler.GetCircuitBreakerStatus()
	openCircuits := 0
	for _, cb := range circuitBreakers {
		if cb.State == "open" {
			openCircuits++
		}
	}
	stats["open_circuit_breakers"] = openCircuits

	// Add recovery system metrics
	stats["failed_events_count"] = sdk.GetFailedEventsCount()
	stats["recovery_system_active"] = sdk.recoverySystem != nil

	// Add replay protection metrics
	if sdk.replayProtection != nil {
		replayStats := sdk.replayProtection.GetStats()
		stats["replay_protection_active"] = true
		stats["processed_events_total"] = replayStats["total_events"]
		stats["replay_cache_size"] = replayStats["cache_size"]
		stats["unique_transactions"] = replayStats["unique_transactions"]
	} else {
		stats["replay_protection_active"] = false
	}

	return stats
}

// GetConfig returns the current SDK configuration
func (sdk *BridgeSDK) GetConfig() *BridgeSDKConfig {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	return sdk.config
}

// IsInitialized returns whether the SDK is initialized
func (sdk *BridgeSDK) IsInitialized() bool {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	return sdk.isInitialized
}

// Shutdown gracefully shuts down the SDK
func (sdk *BridgeSDK) Shutdown() {
	defer sdk.errorHandler.RecoverFromPanic("bridge-sdk-shutdown")

	log.Println("🔄 Starting graceful shutdown of Bridge SDK...")

	sdk.mu.Lock()
	if sdk.isShuttingDown {
		sdk.mu.Unlock()
		log.Println("⚠️ Shutdown already in progress")
		return
	}
	sdk.isShuttingDown = true
	sdk.mu.Unlock()

	// Signal shutdown to all components
	close(sdk.shutdownChan)

	// Update health status
	sdk.errorHandler.updateHealthStatus("bridge-sdk", "shutting-down", "Graceful shutdown in progress")

	// Stop all listeners with timeout
	done := make(chan struct{})
	go func() {
		defer sdk.errorHandler.RecoverFromPanic("bridge-sdk-shutdown-listeners")
		sdk.StopAllListeners()
		close(done)
	}()

	// Wait for listeners to stop with timeout
	select {
	case <-done:
		log.Println("✅ All listeners stopped successfully")
	case <-time.After(sdk.config.ErrorHandling.GracefulShutdownTime / 2):
		log.Println("⚠️ Listener shutdown timed out, forcing shutdown")
	}

	// Shutdown recovery system
	if sdk.recoverySystem != nil {
		sdk.recoverySystem.Stop()
	}

	// Shutdown replay protection
	if sdk.replayProtection != nil {
		sdk.replayProtection.Close()
	}

	// Shutdown error handler (this will drain queues)
	sdk.errorHandler.GracefulShutdown()

	sdk.mu.Lock()
	sdk.isInitialized = false
	sdk.mu.Unlock()

	// Final health status update
	sdk.errorHandler.updateHealthStatus("bridge-sdk", "stopped", "")

	log.Println("✅ Bridge SDK shutdown complete")
}

// GetErrorMetrics returns current error metrics
func (sdk *BridgeSDK) GetErrorMetrics() *ErrorMetrics {
	return sdk.errorHandler.GetMetrics()
}

// GetHealthStatus returns current health status of all components
func (sdk *BridgeSDK) GetHealthStatus() map[string]*HealthStatus {
	return sdk.errorHandler.GetHealthStatus()
}

// GetCircuitBreakerStatus returns current circuit breaker status
func (sdk *BridgeSDK) GetCircuitBreakerStatus() map[string]*CircuitBreakerState {
	return sdk.errorHandler.GetCircuitBreakerStatus()
}

// GetFailedEventsCount returns the number of failed events in recovery
func (sdk *BridgeSDK) GetFailedEventsCount() int {
	if sdk.recoverySystem == nil {
		return 0
	}
	return sdk.recoverySystem.GetFailedEventsCount()
}

// GetFailedEvents returns all failed events
func (sdk *BridgeSDK) GetFailedEvents() []*TransactionEvent {
	if sdk.recoverySystem == nil {
		return nil
	}
	return sdk.recoverySystem.GetFailedEvents()
}

// ForceRecoveryAll forces recovery of all failed events
func (sdk *BridgeSDK) ForceRecoveryAll() {
	if sdk.recoverySystem != nil {
		sdk.recoverySystem.ForceRecoveryAll()
	}
}

// GetReplayProtectionStats returns replay protection statistics
func (sdk *BridgeSDK) GetReplayProtectionStats() map[string]interface{} {
	if sdk.replayProtection == nil {
		return map[string]interface{}{"error": "replay protection not initialized"}
	}
	return sdk.replayProtection.GetStats()
}

// GetProcessedEventsCount returns the number of processed events
func (sdk *BridgeSDK) GetProcessedEventsCount() (int, error) {
	if sdk.replayProtection == nil {
		return 0, fmt.Errorf("replay protection not initialized")
	}
	return sdk.replayProtection.GetProcessedEventsCount()
}

// GetRecentProcessedEvents returns recent processed events
func (sdk *BridgeSDK) GetRecentProcessedEvents(limit int) ([]*EventRecord, error) {
	if sdk.replayProtection == nil {
		return nil, fmt.Errorf("replay protection not initialized")
	}
	return sdk.replayProtection.GetRecentEvents(limit)
}

// CleanupOldEvents removes old processed events
func (sdk *BridgeSDK) CleanupOldEvents(maxAge time.Duration) (int, error) {
	if sdk.replayProtection == nil {
		return 0, fmt.Errorf("replay protection not initialized")
	}
	return sdk.replayProtection.CleanupOldEvents(maxAge)
}

// ValidateEventHash validates an event hash
func (sdk *BridgeSDK) ValidateEventHash(event *TransactionEvent, expectedHash string) bool {
	if sdk.replayProtection == nil {
		return false
	}
	actualHash := sdk.replayProtection.GenerateEventHash(event)
	return actualHash == expectedHash
}

// InitiateTokenTransfer initiates a cross-chain token transfer
func (sdk *BridgeSDK) InitiateTokenTransfer(req *core.TransferRequest) (*core.TransferResponse, error) {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if !sdk.isInitialized {
		return nil, fmt.Errorf("bridge SDK not initialized")
	}

	if sdk.TransferManager == nil {
		return nil, fmt.Errorf("token transfer manager not available")
	}

	if sdk.Logger != nil {
		sdk.Logger.Info("transfer", "Initiating cross-chain token transfer",
			zap.String("request_id", req.ID),
			zap.String("from_chain", string(req.FromChain)),
			zap.String("to_chain", string(req.ToChain)),
			zap.String("amount", req.Amount.String()),
			zap.String("token", req.Token.Symbol),
		)
	}

	return sdk.TransferManager.InitiateTransfer(req)
}

// GetTokenTransferStatus returns the status of a token transfer
func (sdk *BridgeSDK) GetTokenTransferStatus(requestID string) (*core.TransferResponse, error) {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if !sdk.isInitialized {
		return nil, fmt.Errorf("bridge SDK not initialized")
	}

	if sdk.TransferManager == nil {
		return nil, fmt.Errorf("token transfer manager not available")
	}

	return sdk.TransferManager.GetTransferStatus(requestID)
}

// GetSupportedTokenPairs returns all supported token swap pairs
func (sdk *BridgeSDK) GetSupportedTokenPairs() map[string]*core.SwapPair {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.TransferManager == nil {
		return make(map[string]*core.SwapPair)
	}

	return sdk.TransferManager.GetSupportedPairs()
}

// ValidateTokenTransferRequest validates a transfer request
func (sdk *BridgeSDK) ValidateTokenTransferRequest(req *core.TransferRequest) *core.TransferValidationResult {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.TransferManager == nil {
		return &core.TransferValidationResult{
			IsValid: false,
			Errors:  []string{"token transfer manager not available"},
		}
	}

	return sdk.TransferManager.ValidateTransferRequest(req)
}

// GetTokenChainConfig returns configuration for a specific chain
func (sdk *BridgeSDK) GetTokenChainConfig(chainType core.ChainType) (*core.ChainConfig, error) {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	if sdk.TransferManager == nil {
		return nil, fmt.Errorf("token transfer manager not available")
	}

	return sdk.TransferManager.GetChainConfig(chainType)
}
