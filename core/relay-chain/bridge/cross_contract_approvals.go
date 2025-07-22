package bridge

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// CrossContractApprovalManager handles complex approval scenarios between ERC20 tokens and bridge contracts
type CrossContractApprovalManager struct {
	bridge              *Bridge
	approvalCache       map[string]*CachedApproval
	pendingApprovals    map[string]*PendingApproval
	approvalCallbacks   map[string][]func(*ApprovalResult)
	mu                  sync.RWMutex
	cleanupTicker       *time.Ticker
	maxCacheAge         time.Duration
	maxPendingAge       time.Duration
}

// CachedApproval represents a cached approval state
type CachedApproval struct {
	Owner           string    `json:"owner"`
	Spender         string    `json:"spender"`
	TokenSymbol     string    `json:"token_symbol"`
	Amount          uint64    `json:"amount"`
	Timestamp       time.Time `json:"timestamp"`
	Valid           bool      `json:"valid"`
	LastValidated   time.Time `json:"last_validated"`
	ValidationCount int       `json:"validation_count"`
}

// PendingApproval represents an approval that's being processed
type PendingApproval struct {
	ID              string                 `json:"id"`
	Owner           string                 `json:"owner"`
	Spender         string                 `json:"spender"`
	TokenSymbol     string                 `json:"token_symbol"`
	RequestedAmount uint64                 `json:"requested_amount"`
	Status          string                 `json:"status"`
	CreatedAt       time.Time              `json:"created_at"`
	Callbacks       []func(*ApprovalResult) `json:"-"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ApprovalResult represents the result of an approval operation
type ApprovalResult struct {
	Success         bool                   `json:"success"`
	ApprovalID      string                 `json:"approval_id"`
	Owner           string                 `json:"owner"`
	Spender         string                 `json:"spender"`
	TokenSymbol     string                 `json:"token_symbol"`
	ApprovedAmount  uint64                 `json:"approved_amount"`
	PreviousAmount  uint64                 `json:"previous_amount"`
	TxHash          string                 `json:"tx_hash"`
	GasUsed         uint64                 `json:"gas_used"`
	Error           string                 `json:"error,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// NewCrossContractApprovalManager creates a new cross-contract approval manager
func NewCrossContractApprovalManager(bridge *Bridge) *CrossContractApprovalManager {
	ccam := &CrossContractApprovalManager{
		bridge:            bridge,
		approvalCache:     make(map[string]*CachedApproval),
		pendingApprovals:  make(map[string]*PendingApproval),
		approvalCallbacks: make(map[string][]func(*ApprovalResult)),
		maxCacheAge:       5 * time.Minute,
		maxPendingAge:     10 * time.Minute,
	}

	// Start cleanup routine
	ccam.cleanupTicker = time.NewTicker(1 * time.Minute)
	go ccam.cleanupRoutine()

	return ccam
}

// EnsureBridgeApproval ensures that the bridge contract has sufficient approval for a token transfer
func (ccam *CrossContractApprovalManager) EnsureBridgeApproval(owner, tokenSymbol string, amount uint64) (*ApprovalResult, error) {
	spender := "bridge_contract"
	
	log.Printf("Ensuring bridge approval: %s allows %s to spend %d %s", owner, spender, amount, tokenSymbol)

	// Always check current on-chain approval first to ensure accuracy

	// Check current on-chain approval
	token, exists := ccam.bridge.Blockchain.TokenRegistry[tokenSymbol]
	if !exists {
		return nil, fmt.Errorf("token %s not found", tokenSymbol)
	}

	currentAllowance, err := token.Allowance(owner, spender)
	if err != nil {
		return nil, fmt.Errorf("failed to check current allowance: %v", err)
	}

	// If current allowance is sufficient, return success
	if currentAllowance >= amount {
		return &ApprovalResult{
			Success:        true,
			Owner:          owner,
			Spender:        spender,
			TokenSymbol:    tokenSymbol,
			ApprovedAmount: currentAllowance,
			PreviousAmount: currentAllowance,
			Timestamp:      time.Now(),
			Metadata: map[string]interface{}{
				"source": "existing_approval",
				"sufficient": true,
			},
		}, nil
	}

	// Need to create or increase approval
	return ccam.requestApprovalIncrease(owner, spender, tokenSymbol, amount, currentAllowance)
}

// requestApprovalIncrease requests an increase in approval amount
func (ccam *CrossContractApprovalManager) requestApprovalIncrease(owner, spender, tokenSymbol string, requiredAmount, currentAmount uint64) (*ApprovalResult, error) {
	// Calculate the amount to approve (add some buffer for gas optimization)
	approvalAmount := requiredAmount
	if requiredAmount > currentAmount {
		// Add 20% buffer to reduce future approval transactions
		buffer := requiredAmount / 5
		approvalAmount = requiredAmount + buffer
	}

	log.Printf("Requesting approval increase: %s→%s for %d %s (current: %d, requested: %d)", 
		owner, spender, approvalAmount, tokenSymbol, currentAmount, requiredAmount)

	// Get token contract
	token, exists := ccam.bridge.Blockchain.TokenRegistry[tokenSymbol]
	if !exists {
		return nil, fmt.Errorf("token %s not found", tokenSymbol)
	}

	// Execute approval
	err := token.Approve(owner, spender, approvalAmount)
	if err != nil {
		return &ApprovalResult{
			Success:     false,
			Owner:       owner,
			Spender:     spender,
			TokenSymbol: tokenSymbol,
			Error:       err.Error(),
			Timestamp:   time.Now(),
		}, err
	}

	// Generate transaction hash for tracking
	txHash := fmt.Sprintf("0x%x", time.Now().UnixNano())

	// Cache the new approval
	cacheKey := fmt.Sprintf("%s:%s:%s", owner, spender, tokenSymbol)
	ccam.cacheApproval(cacheKey, &CachedApproval{
		Owner:           owner,
		Spender:         spender,
		TokenSymbol:     tokenSymbol,
		Amount:          approvalAmount,
		Timestamp:       time.Now(),
		Valid:           true,
		LastValidated:   time.Now(),
		ValidationCount: 1,
	})

	result := &ApprovalResult{
		Success:        true,
		Owner:          owner,
		Spender:        spender,
		TokenSymbol:    tokenSymbol,
		ApprovedAmount: approvalAmount,
		PreviousAmount: currentAmount,
		TxHash:         txHash,
		GasUsed:        45000, // Estimated gas for approval
		Timestamp:      time.Now(),
		Metadata: map[string]interface{}{
			"required_amount": requiredAmount,
			"buffer_added":    approvalAmount - requiredAmount,
			"approval_type":   "increase",
		},
	}

	log.Printf("Approval successful: %s→%s now has %d %s allowance", owner, spender, approvalAmount, tokenSymbol)
	return result, nil
}

// ValidateAndFixApprovals validates all approvals for a bridge transaction and fixes any issues
func (ccam *CrossContractApprovalManager) ValidateAndFixApprovals(bridgeTx *BridgeTransaction) error {
	if bridgeTx.SourceChain != ChainTypeBlackhole {
		// External chains handle their own approvals
		return nil
	}

	log.Printf("Validating and fixing approvals for bridge transaction: %s", bridgeTx.ID)

	// Ensure bridge contract approval
	result, err := ccam.EnsureBridgeApproval(bridgeTx.SourceAddress, bridgeTx.TokenSymbol, bridgeTx.Amount)
	if err != nil {
		return fmt.Errorf("failed to ensure bridge approval: %v", err)
	}

	if !result.Success {
		return fmt.Errorf("bridge approval failed: %s", result.Error)
	}

	// Validate that the approval is actually sufficient
	token := ccam.bridge.Blockchain.TokenRegistry[bridgeTx.TokenSymbol]
	currentAllowance, err := token.Allowance(bridgeTx.SourceAddress, "bridge_contract")
	if err != nil {
		return fmt.Errorf("failed to validate final allowance: %v", err)
	}

	if currentAllowance < bridgeTx.Amount {
		return fmt.Errorf("insufficient allowance after approval: has %d, needs %d", currentAllowance, bridgeTx.Amount)
	}

	log.Printf("Bridge approvals validated successfully for transaction: %s", bridgeTx.ID)
	return nil
}

// getCachedApproval retrieves a cached approval
func (ccam *CrossContractApprovalManager) getCachedApproval(key string) *CachedApproval {
	ccam.mu.RLock()
	defer ccam.mu.RUnlock()
	return ccam.approvalCache[key]
}

// cacheApproval stores an approval in cache
func (ccam *CrossContractApprovalManager) cacheApproval(key string, approval *CachedApproval) {
	ccam.mu.Lock()
	defer ccam.mu.Unlock()
	ccam.approvalCache[key] = approval
}

// InvalidateApprovalCache invalidates cached approvals for a specific owner/spender/token combination
func (ccam *CrossContractApprovalManager) InvalidateApprovalCache(owner, spender, tokenSymbol string) {
	ccam.mu.Lock()
	defer ccam.mu.Unlock()
	
	key := fmt.Sprintf("%s:%s:%s", owner, spender, tokenSymbol)
	delete(ccam.approvalCache, key)
	log.Printf("Invalidated approval cache for: %s", key)
}

// GetApprovalStatus returns the current approval status for a given combination
func (ccam *CrossContractApprovalManager) GetApprovalStatus(owner, spender, tokenSymbol string) (*ApprovalResult, error) {
	token, exists := ccam.bridge.Blockchain.TokenRegistry[tokenSymbol]
	if !exists {
		return nil, fmt.Errorf("token %s not found", tokenSymbol)
	}

	allowance, err := token.Allowance(owner, spender)
	if err != nil {
		return nil, fmt.Errorf("failed to check allowance: %v", err)
	}

	return &ApprovalResult{
		Success:        true,
		Owner:          owner,
		Spender:        spender,
		TokenSymbol:    tokenSymbol,
		ApprovedAmount: allowance,
		Timestamp:      time.Now(),
		Metadata: map[string]interface{}{
			"source": "live_query",
		},
	}, nil
}

// cleanupRoutine periodically cleans up expired cache entries and pending approvals
func (ccam *CrossContractApprovalManager) cleanupRoutine() {
	for range ccam.cleanupTicker.C {
		ccam.cleanup()
	}
}

// cleanup removes expired entries from cache and pending approvals
func (ccam *CrossContractApprovalManager) cleanup() {
	ccam.mu.Lock()
	defer ccam.mu.Unlock()

	now := time.Now()
	
	// Clean up expired cache entries
	for key, cached := range ccam.approvalCache {
		if now.Sub(cached.Timestamp) > ccam.maxCacheAge {
			delete(ccam.approvalCache, key)
		}
	}

	// Clean up expired pending approvals
	for id, pending := range ccam.pendingApprovals {
		if now.Sub(pending.CreatedAt) > ccam.maxPendingAge {
			delete(ccam.pendingApprovals, id)
		}
	}
}

// Stop stops the cleanup routine
func (ccam *CrossContractApprovalManager) Stop() {
	if ccam.cleanupTicker != nil {
		ccam.cleanupTicker.Stop()
	}
}
