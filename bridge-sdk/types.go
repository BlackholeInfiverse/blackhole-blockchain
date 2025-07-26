package bridgesdk

import (
	"sync"
	"time"
)

// ChainType represents different blockchain types
type ChainType string

const (
	ChainTypeBlackhole ChainType = "blackhole"
	ChainTypeEthereum  ChainType = "ethereum"
	ChainTypeSolana    ChainType = "solana"
	ChainTypePolkadot  ChainType = "polkadot"
)

// TransactionEvent represents a cross-chain transaction event
type TransactionEvent struct {
	SourceChain string  `json:"sourceChain"`
	TxHash      string  `json:"txHash"`
	Amount      float64 `json:"amount"`
	Timestamp   int64   `json:"timestamp"`
	FromAddress string  `json:"fromAddress,omitempty"`
	ToAddress   string  `json:"toAddress,omitempty"`
	TokenSymbol string  `json:"tokenSymbol,omitempty"`
}

// RelayTransaction represents a transaction being relayed
type RelayTransaction struct {
	ID              string    `json:"id"`
	SourceChain     ChainType `json:"source_chain"`
	DestChain       ChainType `json:"dest_chain"`
	SourceAddress   string    `json:"source_address"`
	DestAddress     string    `json:"dest_address"`
	TokenSymbol     string    `json:"token_symbol"`
	Amount          uint64    `json:"amount"`
	Status          string    `json:"status"` // "pending", "confirmed", "completed", "failed"
	CreatedAt       int64     `json:"created_at"`
	ConfirmedAt     int64     `json:"confirmed_at,omitempty"`
	CompletedAt     int64     `json:"completed_at,omitempty"`
	SourceTxHash    string    `json:"source_tx_hash,omitempty"`
	DestTxHash      string    `json:"dest_tx_hash,omitempty"`
	RelaySignatures []string  `json:"relay_signatures"`
	mu              sync.RWMutex
}

// ListenerConfig holds configuration for blockchain listeners
type ListenerConfig struct {
	EthereumRPC string `json:"ethereum_rpc"`
	SolanaRPC   string `json:"solana_rpc"`
	PolkadotRPC string `json:"polkadot_rpc"`
}

// RelayConfig holds configuration for the relay system
type RelayConfig struct {
	MinConfirmations int           `json:"min_confirmations"`
	RelayTimeout     time.Duration `json:"relay_timeout"`
	MaxRetries       int           `json:"max_retries"`
	RetryDelay       time.Duration `json:"retry_delay"`
	MaxRetryDelay    time.Duration `json:"max_retry_delay"`
	BackoffMultiplier float64      `json:"backoff_multiplier"`
}

// RetryConfig holds configuration for retry mechanisms
type RetryConfig struct {
	MaxRetries        int           `json:"max_retries"`
	InitialDelay      time.Duration `json:"initial_delay"`
	MaxDelay          time.Duration `json:"max_delay"`
	BackoffMultiplier float64       `json:"backoff_multiplier"`
	MaxJitter         time.Duration `json:"max_jitter"`
}

// ErrorHandlingConfig holds configuration for error handling
type ErrorHandlingConfig struct {
	EnablePanicRecovery   bool          `json:"enable_panic_recovery"`
	GracefulShutdownTime  time.Duration `json:"graceful_shutdown_time"`
	RetryQueueSize        int           `json:"retry_queue_size"`
	DeadLetterQueueSize   int           `json:"dead_letter_queue_size"`
	HealthCheckInterval   time.Duration `json:"health_check_interval"`
}

// BridgeSDKConfig holds the complete configuration for the bridge SDK
type BridgeSDKConfig struct {
	Listeners     ListenerConfig      `json:"listeners"`
	Relay         RelayConfig         `json:"relay"`
	Retry         RetryConfig         `json:"retry"`
	ErrorHandling ErrorHandlingConfig `json:"error_handling"`
}

// DefaultConfig returns a default configuration for the bridge SDK
func DefaultConfig() *BridgeSDKConfig {
	return &BridgeSDKConfig{
		Listeners: ListenerConfig{
			EthereumRPC: "wss://mainnet.infura.io/ws/v3/688f2501b7114913a6b23a029bd43c9d",
			SolanaRPC:   "wss://api.mainnet-beta.solana.com",
			PolkadotRPC: "wss://rpc.polkadot.io",
		},
		Relay: RelayConfig{
			MinConfirmations:  2,
			RelayTimeout:      30 * time.Second,
			MaxRetries:        3,
			RetryDelay:        1 * time.Second,
			MaxRetryDelay:     60 * time.Second,
			BackoffMultiplier: 2.0,
		},
		Retry: RetryConfig{
			MaxRetries:        5,
			InitialDelay:      500 * time.Millisecond,
			MaxDelay:          30 * time.Second,
			BackoffMultiplier: 2.0,
			MaxJitter:         1 * time.Second,
		},
		ErrorHandling: ErrorHandlingConfig{
			EnablePanicRecovery:  true,
			GracefulShutdownTime: 30 * time.Second,
			RetryQueueSize:       1000,
			DeadLetterQueueSize:  100,
			HealthCheckInterval:  10 * time.Second,
		},
	}
}

// EventHandler defines the interface for handling cross-chain events
type EventHandler interface {
	HandleEvent(event *TransactionEvent) error
}

// RelayHandler defines the interface for handling relay operations
type RelayHandler interface {
	RelayToChain(tx *RelayTransaction, targetChain ChainType) error
	GetTransactionStatus(txID string) (string, error)
}

// RetryableEvent represents an event that can be retried
type RetryableEvent struct {
	Event       *TransactionEvent `json:"event"`
	RetryCount  int               `json:"retry_count"`
	LastError   string            `json:"last_error"`
	NextRetry   time.Time         `json:"next_retry"`
	CreatedAt   time.Time         `json:"created_at"`
	ID          string            `json:"id"`
}

// HealthStatus represents the health status of a component
type HealthStatus struct {
	Component   string    `json:"component"`
	Status      string    `json:"status"` // "healthy", "degraded", "unhealthy"
	LastCheck   time.Time `json:"last_check"`
	Error       string    `json:"error,omitempty"`
	Uptime      time.Duration `json:"uptime"`
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState struct {
	State         string    `json:"state"` // "closed", "open", "half-open"
	FailureCount  int       `json:"failure_count"`
	LastFailure   time.Time `json:"last_failure"`
	NextAttempt   time.Time `json:"next_attempt"`
	SuccessCount  int       `json:"success_count"`
}

// ErrorMetrics holds error statistics
type ErrorMetrics struct {
	TotalErrors     int64             `json:"total_errors"`
	ErrorsByType    map[string]int64  `json:"errors_by_type"`
	RecentErrors    []string          `json:"recent_errors"`
	LastError       time.Time         `json:"last_error"`
	RecoveryCount   int64             `json:"recovery_count"`
	mu              sync.RWMutex
}
