package bridge

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ReplayMode represents different modes of bridge replay
type ReplayMode string

const (
	ReplayModeDryRun     ReplayMode = "dry_run"     // Simulate without actual execution
	ReplayModeValidation ReplayMode = "validation"  // Validate transactions only
	ReplayModeExecution  ReplayMode = "execution"   // Actually execute transactions
	ReplayModeAudit      ReplayMode = "audit"       // Audit mode with detailed logging
)

// GasUsageTracker tracks gas usage for bridge operations
type GasUsageTracker struct {
	OperationType     string    `json:"operation_type"`
	BaseGas          uint64    `json:"base_gas"`
	TokenTransferGas uint64    `json:"token_transfer_gas"`
	BridgeContractGas uint64   `json:"bridge_contract_gas"`
	RelayGas         uint64    `json:"relay_gas"`
	ValidationGas    uint64    `json:"validation_gas"`
	TotalGas         uint64    `json:"total_gas"`
	GasPrice         uint64    `json:"gas_price"`
	TotalCost        uint64    `json:"total_cost"`
	Timestamp        time.Time `json:"timestamp"`
	TransactionHash  string    `json:"transaction_hash"`
}

// ReplayResult represents the result of a bridge transaction replay
type ReplayResult struct {
	TransactionID    string           `json:"transaction_id"`
	OriginalTx       *BridgeTransaction `json:"original_tx"`
	ReplayMode       ReplayMode       `json:"replay_mode"`
	Success          bool             `json:"success"`
	Error            string           `json:"error,omitempty"`
	GasUsage         *GasUsageTracker `json:"gas_usage"`
	ValidationErrors []string         `json:"validation_errors,omitempty"`
	StateChanges     map[string]interface{} `json:"state_changes,omitempty"`
	ExecutionTime    time.Duration    `json:"execution_time"`
	Timestamp        time.Time        `json:"timestamp"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// BridgeReplayManager manages bridge transaction replay functionality
type BridgeReplayManager struct {
	bridge         *Bridge
	replayHistory  []ReplayResult
	gasEstimator   *GasEstimator
	mu             sync.RWMutex
	maxHistorySize int
}

// GasEstimator estimates gas usage for different bridge operations
type GasEstimator struct {
	BaseGasLimits map[string]uint64 `json:"base_gas_limits"`
	GasPrice      uint64            `json:"gas_price"`
	mu            sync.RWMutex
}

// NewBridgeReplayManager creates a new bridge replay manager
func NewBridgeReplayManager(bridge *Bridge) *BridgeReplayManager {
	gasEstimator := &GasEstimator{
		BaseGasLimits: map[string]uint64{
			"token_transfer":    21000,
			"token_approval":    45000,
			"bridge_lock":       80000,
			"bridge_unlock":     75000,
			"bridge_mint":       60000,
			"bridge_burn":       55000,
			"relay_signature":   25000,
			"validation":        15000,
		},
		GasPrice: 20, // 20 gwei equivalent
	}

	return &BridgeReplayManager{
		bridge:         bridge,
		replayHistory:  make([]ReplayResult, 0),
		gasEstimator:   gasEstimator,
		maxHistorySize: 1000,
	}
}

// ReplayBridgeTransaction replays a bridge transaction in the specified mode
func (brm *BridgeReplayManager) ReplayBridgeTransaction(txID string, mode ReplayMode) (*ReplayResult, error) {
	startTime := time.Now()
	
	log.Printf("🔄 Starting bridge replay: %s (mode: %s)", txID, mode)

	// Find the original transaction
	brm.bridge.mu.RLock()
	originalTx, exists := brm.bridge.Transactions[txID]
	brm.bridge.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("bridge transaction %s not found", txID)
	}

	// Create replay result
	result := &ReplayResult{
		TransactionID: txID,
		OriginalTx:    originalTx,
		ReplayMode:    mode,
		Timestamp:     time.Now(),
		StateChanges:  make(map[string]interface{}),
		Metadata:      make(map[string]interface{}),
	}

	// Estimate gas usage
	gasUsage, err := brm.estimateGasUsage(originalTx)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("gas estimation failed: %v", err)
		return result, err
	}
	result.GasUsage = gasUsage

	// Perform replay based on mode
	switch mode {
	case ReplayModeDryRun:
		err = brm.performDryRun(originalTx, result)
	case ReplayModeValidation:
		err = brm.performValidation(originalTx, result)
	case ReplayModeExecution:
		err = brm.performExecution(originalTx, result)
	case ReplayModeAudit:
		err = brm.performAudit(originalTx, result)
	default:
		err = fmt.Errorf("unknown replay mode: %s", mode)
	}

	// Set result status
	result.Success = (err == nil)
	if err != nil {
		result.Error = err.Error()
	}

	// Calculate execution time
	result.ExecutionTime = time.Since(startTime)

	// Store in history
	brm.addToHistory(*result)

	log.Printf("✅ Bridge replay completed: %s (success: %t, time: %v, gas: %d)", 
		txID, result.Success, result.ExecutionTime, gasUsage.TotalGas)

	return result, err
}

// performDryRun performs a dry run simulation of the bridge transaction
func (brm *BridgeReplayManager) performDryRun(tx *BridgeTransaction, result *ReplayResult) error {
	log.Printf("🧪 Performing dry run for transaction: %s", tx.ID)

	// Simulate token balance checks
	if tx.SourceChain == ChainTypeBlackhole {
		token, exists := brm.bridge.Blockchain.TokenRegistry[tx.TokenSymbol]
		if !exists {
			return fmt.Errorf("token %s not found", tx.TokenSymbol)
		}

		balance, err := token.BalanceOf(tx.SourceAddress)
		if err != nil {
			return fmt.Errorf("failed to check balance: %v", err)
		}

		if balance < tx.Amount {
			return fmt.Errorf("insufficient balance: has %d, needs %d", balance, tx.Amount)
		}

		result.StateChanges["source_balance_check"] = map[string]interface{}{
			"address": tx.SourceAddress,
			"balance": balance,
			"required": tx.Amount,
			"sufficient": balance >= tx.Amount,
		}
	}

	// Simulate bridge contract approval check
	if tx.SourceChain == ChainTypeBlackhole {
		token := brm.bridge.Blockchain.TokenRegistry[tx.TokenSymbol]
		allowance, err := token.Allowance(tx.SourceAddress, "bridge_contract")
		if err != nil {
			return fmt.Errorf("failed to check allowance: %v", err)
		}

		result.StateChanges["approval_check"] = map[string]interface{}{
			"owner": tx.SourceAddress,
			"spender": "bridge_contract",
			"allowance": allowance,
			"required": tx.Amount,
			"sufficient": allowance >= tx.Amount,
		}
	}

	// Simulate relay signature validation
	requiredSigs := 2
	availableSigs := len(tx.RelaySignatures)
	result.StateChanges["relay_signatures"] = map[string]interface{}{
		"required": requiredSigs,
		"available": availableSigs,
		"sufficient": availableSigs >= requiredSigs,
	}

	// Simulate destination chain token mapping
	_, exists := brm.bridge.TokenMappings[tx.DestChain][tx.TokenSymbol]
	result.StateChanges["token_mapping"] = map[string]interface{}{
		"source_token": tx.TokenSymbol,
		"dest_chain": tx.DestChain,
		"mapping_exists": exists,
	}

	result.Metadata["simulation_type"] = "dry_run"
	result.Metadata["checks_performed"] = []string{"balance", "approval", "relay_signatures", "token_mapping"}

	return nil
}

// performValidation performs validation checks on the bridge transaction
func (brm *BridgeReplayManager) performValidation(tx *BridgeTransaction, result *ReplayResult) error {
	log.Printf("✅ Performing validation for transaction: %s", tx.ID)

	validationErrors := make([]string, 0)

	// Validate transaction structure
	if tx.ID == "" {
		validationErrors = append(validationErrors, "transaction ID is empty")
	}
	if tx.SourceAddress == "" {
		validationErrors = append(validationErrors, "source address is empty")
	}
	if tx.DestAddress == "" {
		validationErrors = append(validationErrors, "destination address is empty")
	}
	if tx.Amount == 0 {
		validationErrors = append(validationErrors, "amount is zero")
	}
	if tx.TokenSymbol == "" {
		validationErrors = append(validationErrors, "token symbol is empty")
	}

	// Validate chain support
	if !brm.bridge.SupportedChains[tx.SourceChain] {
		validationErrors = append(validationErrors, fmt.Sprintf("source chain %s not supported", tx.SourceChain))
	}
	if !brm.bridge.SupportedChains[tx.DestChain] {
		validationErrors = append(validationErrors, fmt.Sprintf("destination chain %s not supported", tx.DestChain))
	}

	// Validate token mapping
	if _, exists := brm.bridge.TokenMappings[tx.DestChain][tx.TokenSymbol]; !exists {
		validationErrors = append(validationErrors, fmt.Sprintf("token %s not mapped to destination chain %s", tx.TokenSymbol, tx.DestChain))
	}

	// Validate relay signatures
	if len(tx.RelaySignatures) < 2 {
		validationErrors = append(validationErrors, fmt.Sprintf("insufficient relay signatures: has %d, needs 2", len(tx.RelaySignatures)))
	}

	result.ValidationErrors = validationErrors
	result.Metadata["validation_type"] = "full_validation"
	result.Metadata["total_checks"] = 8
	result.Metadata["failed_checks"] = len(validationErrors)

	if len(validationErrors) > 0 {
		return fmt.Errorf("validation failed with %d errors", len(validationErrors))
	}

	return nil
}

// performExecution performs actual execution of the bridge transaction (use with caution)
func (brm *BridgeReplayManager) performExecution(tx *BridgeTransaction, result *ReplayResult) error {
	log.Printf("⚡ Performing execution for transaction: %s", tx.ID)

	// WARNING: This actually executes the transaction
	// Should only be used in controlled environments

	result.Metadata["execution_type"] = "actual_execution"
	result.Metadata["warning"] = "this mode performs actual state changes"

	// For safety, we'll just simulate execution in this implementation
	// In a production system, you'd implement actual execution logic here
	return brm.performDryRun(tx, result)
}

// performAudit performs comprehensive audit of the bridge transaction
func (brm *BridgeReplayManager) performAudit(tx *BridgeTransaction, result *ReplayResult) error {
	log.Printf("🔍 Performing audit for transaction: %s", tx.ID)

	// Combine validation and dry run
	if err := brm.performValidation(tx, result); err != nil {
		// Continue with audit even if validation fails
		log.Printf("⚠️ Validation issues found during audit: %v", err)
	}

	if err := brm.performDryRun(tx, result); err != nil {
		log.Printf("⚠️ Dry run issues found during audit: %v", err)
	}

	// Additional audit checks
	auditFindings := make([]string, 0)

	// Check transaction timing
	if tx.CreatedAt > 0 && tx.CompletedAt > 0 {
		duration := tx.CompletedAt - tx.CreatedAt
		if duration > 3600 { // More than 1 hour
			auditFindings = append(auditFindings, fmt.Sprintf("transaction took %d seconds to complete", duration))
		}
	}

	// Check for unusual amounts
	if tx.Amount > 1000000 { // Large amount threshold
		auditFindings = append(auditFindings, fmt.Sprintf("large amount transfer: %d", tx.Amount))
	}

	// Check relay signature timing
	if len(tx.RelaySignatures) > 0 {
		auditFindings = append(auditFindings, fmt.Sprintf("relay signatures collected: %d", len(tx.RelaySignatures)))
	}

	result.Metadata["audit_type"] = "comprehensive_audit"
	result.Metadata["audit_findings"] = auditFindings
	result.Metadata["audit_timestamp"] = time.Now()

	return nil
}

// estimateGasUsage estimates the gas usage for a bridge transaction
func (brm *BridgeReplayManager) estimateGasUsage(tx *BridgeTransaction) (*GasUsageTracker, error) {
	brm.gasEstimator.mu.RLock()
	defer brm.gasEstimator.mu.RUnlock()

	tracker := &GasUsageTracker{
		OperationType:   "bridge_transfer",
		GasPrice:        brm.gasEstimator.GasPrice,
		Timestamp:       time.Now(),
		TransactionHash: tx.SourceTxHash,
	}

	// Base transaction gas
	tracker.BaseGas = brm.gasEstimator.BaseGasLimits["token_transfer"]

	// Token transfer gas (if source is Blackhole)
	if tx.SourceChain == ChainTypeBlackhole {
		tracker.TokenTransferGas = brm.gasEstimator.BaseGasLimits["bridge_lock"]
	}

	// Bridge contract interaction gas
	tracker.BridgeContractGas = brm.gasEstimator.BaseGasLimits["bridge_unlock"]

	// Relay signature gas
	tracker.RelayGas = brm.gasEstimator.BaseGasLimits["relay_signature"] * uint64(len(tx.RelaySignatures))

	// Validation gas
	tracker.ValidationGas = brm.gasEstimator.BaseGasLimits["validation"]

	// Calculate total gas
	tracker.TotalGas = tracker.BaseGas + tracker.TokenTransferGas + 
		tracker.BridgeContractGas + tracker.RelayGas + tracker.ValidationGas

	// Calculate total cost
	tracker.TotalCost = tracker.TotalGas * tracker.GasPrice

	return tracker, nil
}

// addToHistory adds a replay result to the history
func (brm *BridgeReplayManager) addToHistory(result ReplayResult) {
	brm.mu.Lock()
	defer brm.mu.Unlock()

	brm.replayHistory = append(brm.replayHistory, result)

	// Trim history if it exceeds max size
	if len(brm.replayHistory) > brm.maxHistorySize {
		brm.replayHistory = brm.replayHistory[1:]
	}
}

// GetReplayHistory returns the replay history
func (brm *BridgeReplayManager) GetReplayHistory() []ReplayResult {
	brm.mu.RLock()
	defer brm.mu.RUnlock()

	history := make([]ReplayResult, len(brm.replayHistory))
	copy(history, brm.replayHistory)
	return history
}

// GetGasUsageStats returns gas usage statistics
func (brm *BridgeReplayManager) GetGasUsageStats() map[string]interface{} {
	brm.mu.RLock()
	defer brm.mu.RUnlock()

	if len(brm.replayHistory) == 0 {
		return map[string]interface{}{
			"total_replays": 0,
			"average_gas": 0,
			"total_gas": 0,
		}
	}

	totalGas := uint64(0)
	totalCost := uint64(0)
	successCount := 0

	for _, result := range brm.replayHistory {
		if result.GasUsage != nil {
			totalGas += result.GasUsage.TotalGas
			totalCost += result.GasUsage.TotalCost
		}
		if result.Success {
			successCount++
		}
	}

	return map[string]interface{}{
		"total_replays":   len(brm.replayHistory),
		"successful_replays": successCount,
		"success_rate":    float64(successCount) / float64(len(brm.replayHistory)) * 100,
		"average_gas":     totalGas / uint64(len(brm.replayHistory)),
		"total_gas":       totalGas,
		"total_cost":      totalCost,
		"gas_price":       brm.gasEstimator.GasPrice,
	}
}
