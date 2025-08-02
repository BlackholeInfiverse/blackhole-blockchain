package bridgesdk

import (
	"time"
)

// Core transaction structure for bridge operations
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
	ProcessingTime string     `json:"processing_time,omitempty"`
	Confirmations  int        `json:"confirmations"`
	BlockNumber    uint64     `json:"block_number"`
}

// Event represents a blockchain event
type Event struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Chain       string                 `json:"chain"`
	TxHash      string                 `json:"tx_hash"`
	Timestamp   time.Time              `json:"timestamp"`
	Data        map[string]interface{} `json:"data"`
	Processed   bool                   `json:"processed"`
	ProcessedAt *time.Time             `json:"processed_at,omitempty"`
	BlockNumber uint64                 `json:"block_number"`
}

// TransferRequest represents a bridge transfer request
type TransferRequest struct {
	FromChain   string `json:"from_chain"`
	ToChain     string `json:"to_chain"`
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
	TokenSymbol string `json:"token_symbol"`
	Amount      string `json:"amount"`
}

// Configuration for the bridge SDK
type Config struct {
	EthereumRPC             string `json:"ethereum_rpc"`
	SolanaRPC               string `json:"solana_rpc"`
	BlackHoleRPC            string `json:"blackhole_rpc"`
	DatabasePath            string `json:"database_path"`
	LogLevel                string `json:"log_level"`
	MaxRetries              int    `json:"max_retries"`
	RetryDelayMs            int    `json:"retry_delay_ms"`
	CircuitBreakerEnabled   bool   `json:"circuit_breaker_enabled"`
	ReplayProtectionEnabled bool   `json:"replay_protection_enabled"`
	EnableColoredLogs       bool   `json:"enable_colored_logs"`
}

// Statistics types
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

type ChainStats struct {
	Transactions int     `json:"transactions"`
	Volume       string  `json:"volume"`
	SuccessRate  float64 `json:"success_rate"`
	LastBlock    uint64  `json:"last_block"`
}

type PeriodStats struct {
	Transactions int     `json:"transactions"`
	Volume       string  `json:"volume"`
	SuccessRate  float64 `json:"success_rate"`
}

type HealthStatus struct {
	Status     string            `json:"status"`
	Timestamp  time.Time         `json:"timestamp"`
	Components map[string]string `json:"components"`
	Uptime     string            `json:"uptime"`
	Version    string            `json:"version"`
	Healthy    bool              `json:"healthy"`
}

// Circuit breaker for fault tolerance
type CircuitBreaker struct {
	name             string
	state            string // "closed", "open", "half-open"
	failureCount     int
	failureThreshold int
	timeout          time.Duration
	resetTimeout     time.Duration
	lastFailureTime  time.Time
	nextAttempt      time.Time
}

// Replay protection to prevent duplicate processing
type ReplayProtection struct {
	processedHashes map[string]time.Time
	db              interface{} // Will be *bbolt.DB
	enabled         bool
	cacheSize       int
	cacheTTL        time.Duration
}

// Event recovery system
type EventRecovery struct {
	failedEvents []Event
	retryCount   map[string]int
	maxRetries   int
}

// Retry queue for failed operations
type RetryQueue struct {
	queue      []Transaction
	processing bool
	maxRetries int
}

// Error handler for comprehensive error management
type ErrorHandler struct {
	errors []error
	logger interface{} // Will be *logrus.Logger
}

// Panic recovery system
type PanicRecovery struct {
	enabled bool
	logger  interface{} // Will be *logrus.Logger
}

// EventHandler interface for handling blockchain events
type EventHandler interface {
	HandleEvent(event Event) error
	GetProcessedEvents() []Event
	GetFailedEvents() []Event
}

// Default event handler implementation
type DefaultEventHandler struct {
	processedEvents []Event
	failedEvents    []Event
}

func (h *DefaultEventHandler) HandleEvent(event Event) error {
	// Process the event
	event.Processed = true
	now := time.Now()
	event.ProcessedAt = &now
	
	h.processedEvents = append(h.processedEvents, event)
	return nil
}

func (h *DefaultEventHandler) GetProcessedEvents() []Event {
	return h.processedEvents
}

func (h *DefaultEventHandler) GetFailedEvents() []Event {
	return h.failedEvents
}
