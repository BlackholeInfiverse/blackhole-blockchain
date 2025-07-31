package workflow

import (
	"context"
	"time"
)

// WorkflowComponent represents the interface that all workflow components must implement
type WorkflowComponent interface {
	// GetName returns the unique name of the workflow component
	GetName() string
	
	// GetVersion returns the version of the workflow component
	GetVersion() string
	
	// Initialize sets up the workflow component with the given configuration
	Initialize(ctx context.Context, config map[string]interface{}) error
	
	// Start begins the workflow component's operations
	Start(ctx context.Context) error
	
	// Stop gracefully shuts down the workflow component
	Stop(ctx context.Context) error
	
	// IsHealthy returns the health status of the workflow component
	IsHealthy() bool
	
	// GetMetrics returns current metrics for the workflow component
	GetMetrics() map[string]interface{}
	
	// GetStatus returns the current status of the workflow component
	GetStatus() ComponentStatus
}

// ComponentStatus represents the status of a workflow component
type ComponentStatus struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Status      string                 `json:"status"` // "starting", "running", "stopping", "stopped", "error"
	Healthy     bool                   `json:"healthy"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	LastUpdate  time.Time              `json:"last_update"`
	Metrics     map[string]interface{} `json:"metrics"`
	ErrorCount  int                    `json:"error_count"`
	LastError   string                 `json:"last_error,omitempty"`
	Dependencies []string              `json:"dependencies"`
}

// MintComponent interface for token minting functionality
type MintComponent interface {
	WorkflowComponent
	
	// MintTokens mints new tokens for the specified address
	MintTokens(ctx context.Context, tokenSymbol string, amount uint64, toAddress string) error
	
	// GetMintingHistory returns the minting history for a token
	GetMintingHistory(tokenSymbol string, limit int) ([]MintRecord, error)
	
	// ValidateMintRequest validates a mint request before execution
	ValidateMintRequest(tokenSymbol string, amount uint64, toAddress string) error
}

// ApproveComponent interface for token approval functionality
type ApproveComponent interface {
	WorkflowComponent
	
	// ApproveTokens approves tokens for spending by another address
	ApproveTokens(ctx context.Context, tokenSymbol string, amount uint64, spender string) error
	
	// GetApprovalStatus returns the approval status for a token
	GetApprovalStatus(owner, spender, tokenSymbol string) (uint64, error)
	
	// RevokeApproval revokes token approval
	RevokeApproval(ctx context.Context, tokenSymbol string, spender string) error
}

// StakeComponent interface for staking functionality
type StakeComponent interface {
	WorkflowComponent
	
	// StakeTokens stakes tokens for rewards
	StakeTokens(ctx context.Context, tokenSymbol string, amount uint64, validator string) error
	
	// UnstakeTokens unstakes tokens
	UnstakeTokens(ctx context.Context, stakeID string, amount uint64) error
	
	// GetStakingRewards returns current staking rewards
	GetStakingRewards(address string) (map[string]uint64, error)
	
	// GetStakingHistory returns staking history for an address
	GetStakingHistory(address string, limit int) ([]StakeRecord, error)
}

// SwapComponent interface for DEX/AMM swap functionality
type SwapComponent interface {
	WorkflowComponent
	
	// SwapTokens executes a token swap
	SwapTokens(ctx context.Context, fromToken, toToken string, amount uint64, minOutput uint64) error
	
	// GetSwapQuote returns a quote for a token swap
	GetSwapQuote(fromToken, toToken string, amount uint64) (SwapQuote, error)
	
	// GetLiquidityPools returns available liquidity pools
	GetLiquidityPools() ([]LiquidityPool, error)
	
	// AddLiquidity adds liquidity to a pool
	AddLiquidity(ctx context.Context, tokenA, tokenB string, amountA, amountB uint64) error
}

// BridgeComponent interface for cross-chain bridging functionality
type BridgeComponent interface {
	WorkflowComponent
	
	// BridgeTokens initiates a cross-chain token transfer
	BridgeTokens(ctx context.Context, fromChain, toChain, tokenSymbol string, amount uint64, toAddress string) error
	
	// GetBridgeStatus returns the status of a bridge transaction
	GetBridgeStatus(transactionID string) (BridgeStatus, error)
	
	// GetSupportedChains returns supported blockchain networks
	GetSupportedChains() []ChainInfo
	
	// GetBridgeHistory returns bridge transaction history
	GetBridgeHistory(address string, limit int) ([]BridgeRecord, error)
}

// CybercrimeComponent interface for security/fraud detection functionality
type CybercrimeComponent interface {
	WorkflowComponent
	
	// AnalyzeTransaction analyzes a transaction for suspicious activity
	AnalyzeTransaction(ctx context.Context, txData map[string]interface{}) (SecurityAnalysis, error)
	
	// ReportSuspiciousActivity reports suspicious activity
	ReportSuspiciousActivity(ctx context.Context, report SecurityReport) error
	
	// GetSecurityAlerts returns current security alerts
	GetSecurityAlerts() ([]SecurityAlert, error)
	
	// BlockAddress blocks an address from transactions
	BlockAddress(ctx context.Context, address string, reason string) error
}

// Data structures for workflow components

type MintRecord struct {
	ID          string    `json:"id"`
	TokenSymbol string    `json:"token_symbol"`
	Amount      uint64    `json:"amount"`
	ToAddress   string    `json:"to_address"`
	Timestamp   time.Time `json:"timestamp"`
	TxHash      string    `json:"tx_hash"`
}

type StakeRecord struct {
	ID          string    `json:"id"`
	TokenSymbol string    `json:"token_symbol"`
	Amount      uint64    `json:"amount"`
	Validator   string    `json:"validator"`
	Timestamp   time.Time `json:"timestamp"`
	Status      string    `json:"status"`
	Rewards     uint64    `json:"rewards"`
}

type SwapQuote struct {
	FromToken    string  `json:"from_token"`
	ToToken      string  `json:"to_token"`
	InputAmount  uint64  `json:"input_amount"`
	OutputAmount uint64  `json:"output_amount"`
	Price        float64 `json:"price"`
	Slippage     float64 `json:"slippage"`
	Fee          uint64  `json:"fee"`
	Route        []string `json:"route"`
}

type LiquidityPool struct {
	ID       string `json:"id"`
	TokenA   string `json:"token_a"`
	TokenB   string `json:"token_b"`
	ReserveA uint64 `json:"reserve_a"`
	ReserveB uint64 `json:"reserve_b"`
	Fee      uint64 `json:"fee"`
	Volume24h uint64 `json:"volume_24h"`
}

type BridgeStatus struct {
	TransactionID string    `json:"transaction_id"`
	Status        string    `json:"status"`
	FromChain     string    `json:"from_chain"`
	ToChain       string    `json:"to_chain"`
	TokenSymbol   string    `json:"token_symbol"`
	Amount        uint64    `json:"amount"`
	CreatedAt     time.Time `json:"created_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Confirmations int       `json:"confirmations"`
	RequiredConfs int       `json:"required_confirmations"`
}

type ChainInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Symbol      string `json:"symbol"`
	RPC         string `json:"rpc"`
	Explorer    string `json:"explorer"`
	Supported   bool   `json:"supported"`
	MinConfirms int    `json:"min_confirmations"`
}

type BridgeRecord struct {
	ID            string    `json:"id"`
	FromChain     string    `json:"from_chain"`
	ToChain       string    `json:"to_chain"`
	TokenSymbol   string    `json:"token_symbol"`
	Amount        uint64    `json:"amount"`
	FromAddress   string    `json:"from_address"`
	ToAddress     string    `json:"to_address"`
	Status        string    `json:"status"`
	Timestamp     time.Time `json:"timestamp"`
	SourceTxHash  string    `json:"source_tx_hash"`
	DestTxHash    string    `json:"dest_tx_hash,omitempty"`
}

type SecurityAnalysis struct {
	TransactionID string                 `json:"transaction_id"`
	RiskScore     float64                `json:"risk_score"` // 0-100
	RiskLevel     string                 `json:"risk_level"` // "low", "medium", "high", "critical"
	Flags         []string               `json:"flags"`
	Recommendations []string             `json:"recommendations"`
	Details       map[string]interface{} `json:"details"`
	Timestamp     time.Time              `json:"timestamp"`
}

type SecurityReport struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // "fraud", "suspicious", "phishing", "malware"
	Address     string                 `json:"address"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Reporter    string                 `json:"reporter"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"` // "low", "medium", "high", "critical"
}

type SecurityAlert struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Message     string    `json:"message"`
	Severity    string    `json:"severity"`
	Address     string    `json:"address,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Acknowledged bool     `json:"acknowledged"`
	Actions     []string  `json:"actions"`
}

// WorkflowEvent represents events that can be emitted by workflow components
type WorkflowEvent struct {
	ID          string                 `json:"id"`
	Component   string                 `json:"component"`
	Type        string                 `json:"type"`
	Data        map[string]interface{} `json:"data"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"` // "info", "warning", "error", "critical"
}

// EventHandler defines the interface for handling workflow events
type EventHandler interface {
	HandleEvent(ctx context.Context, event WorkflowEvent) error
}
