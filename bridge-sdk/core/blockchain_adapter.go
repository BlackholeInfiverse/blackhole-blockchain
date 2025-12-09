package bridgesdk

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

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
	SourceModule   *string    `json:"source_module,omitempty"` // DEX, TOKEN, STAKE
	Events         []Event    `json:"events,omitempty"`
	GasPrice       string     `json:"gas_price,omitempty"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	RetryCount     int        `json:"retry_count"`
	LastRetryAt    *time.Time `json:"last_retry_at,omitempty"`
	ProcessingTime string     `json:"processing_time,omitempty"`
}

// Event represents a blockchain event
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

// Config holds the bridge configuration
type Config struct {
	EthereumRPC             string `json:"ethereum_rpc"`
	SolanaRPC               string `json:"solana_rpc"`
	BlackHoleRPC            string `json:"blackhole_rpc"`
	DatabasePath            string `json:"database_path"`
	LogLevel                string `json:"log_level"`
	LogFile                 string
	ReplayProtectionEnabled bool   `json:"replay_protection_enabled"`
	CircuitBreakerEnabled   bool   `json:"circuit_breaker_enabled"`
	Port                    string
	MaxRetries              int    `json:"max_retries"`
	RetryDelay              time.Duration
	RetryDelayMs            int    `json:"retry_delay_ms"`
	BatchSize               int
	EnableColoredLogs       bool   `json:"enable_colored_logs"`
}

// BridgeSDKInterface defines the interface for bridge SDK
type BridgeSDKInterface interface {
	GetLogger() *logrus.Logger
	GetConfig() *Config
	SaveTransaction(tx *Transaction) error
	AddEvent(eventType string, chain string, txHash string, data map[string]interface{})
}

// BlockchainAdapter is an adapter that provides a unified interface for interacting with different blockchains
type BlockchainAdapter struct {
	sdk    BridgeSDKInterface
	logger *logrus.Logger
}

// NewBlockchainAdapter creates a new instance of BlockchainAdapter
func NewBlockchainAdapter(sdk BridgeSDKInterface) *BlockchainAdapter {
	return &BlockchainAdapter{
		sdk:    sdk,
		logger: sdk.GetLogger(),
	}
}

// StartEthereumListener starts the Ethereum blockchain listener
func (ba *BlockchainAdapter) StartEthereumListener(ctx context.Context) error {
	ba.logger.Info("🚀 Starting real Ethereum blockchain listener...")

	// Create a new real blockchain listener
	listener := NewRealBlockchainListener(ba.sdk)

	// Start the Ethereum listener
	return listener.StartEthereumListener(ctx)
}

// StartSolanaListener starts the Solana blockchain listener
func (ba *BlockchainAdapter) StartSolanaListener(ctx context.Context) error {
	ba.logger.Info("🚀 Starting real Solana blockchain listener...")

	// Create a new real blockchain listener
	listener := NewRealBlockchainListener(ba.sdk)

	// Start the Solana listener
	return listener.StartSolanaListener(ctx)
}
