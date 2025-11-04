package bridge

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// BridgeApprovalStatus represents the status of a bridge approval
type BridgeApprovalStatus string

const (
	ApprovalPending   BridgeApprovalStatus = "pending"
	ApprovalApproved  BridgeApprovalStatus = "approved"
	ApprovalRejected  BridgeApprovalStatus = "rejected"
	ApprovalExpired   BridgeApprovalStatus = "expired"
	ApprovalSimulated BridgeApprovalStatus = "simulated"
)

// BridgeApproval represents a bridge transfer approval request
type BridgeApproval struct {
	ID              string               `json:"id"`
	BridgeID        string               `json:"bridge_id"`
	UserAddress     string               `json:"user_address"`
	TokenSymbol     string               `json:"token_symbol"`
	Amount          uint64               `json:"amount"`
	SourceChain     ChainType            `json:"source_chain"`
	DestChain       ChainType            `json:"dest_chain"`
	Status          BridgeApprovalStatus `json:"status"`
	CreatedAt       int64                `json:"created_at"`
	ApprovedAt      int64                `json:"approved_at,omitempty"`
	ExpiresAt       int64                `json:"expires_at"`
	SimulationData  *SimulationResult    `json:"simulation_data,omitempty"`
	ApprovalHash    string               `json:"approval_hash"`
	RequiredSigs    int                  `json:"required_sigs"`
	CollectedSigs   []string             `json:"collected_sigs"`
	mu              sync.RWMutex
}

// SimulationResult contains the results of bridge transfer simulation
type SimulationResult struct {
	Success           bool                   `json:"success"`
	EstimatedGas      uint64                 `json:"estimated_gas"`
	EstimatedFee      uint64                 `json:"estimated_fee"`
	EstimatedTime     string                 `json:"estimated_time"`
	TokenBalance      uint64                 `json:"token_balance"`
	AllowanceRequired uint64                 `json:"allowance_required"`
	CurrentAllowance  uint64                 `json:"current_allowance"`
	Warnings          []string               `json:"warnings,omitempty"`
	Errors            []string               `json:"errors,omitempty"`
	SimulatedAt       int64                  `json:"simulated_at"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// BridgeApprovalManager manages bridge approval requests and simulations
type BridgeApprovalManager struct {
	approvals map[string]*BridgeApproval
	bridge    *Bridge
	mu        sync.RWMutex
}

// NewBridgeApprovalManager creates a new bridge approval manager
func NewBridgeApprovalManager(bridge *Bridge) *BridgeApprovalManager {
	return &BridgeApprovalManager{
		approvals: make(map[string]*BridgeApproval),
		bridge:    bridge,
	}
}

// RequestBridgeApproval creates a new bridge approval request with simulation
func (bam *BridgeApprovalManager) RequestBridgeApproval(userAddr, tokenSymbol string, amount uint64, sourceChain, destChain ChainType) (*BridgeApproval, error) {
	bam.mu.Lock()
	defer bam.mu.Unlock()

	// Generate approval ID
	approvalID := fmt.Sprintf("approval_%d_%s", time.Now().UnixNano(), userAddr[:8])

	// Create approval request
	approval := &BridgeApproval{
		ID:            approvalID,
		UserAddress:   userAddr,
		TokenSymbol:   tokenSymbol,
		Amount:        amount,
		SourceChain:   sourceChain,
		DestChain:     destChain,
		Status:        ApprovalPending,
		CreatedAt:     time.Now().Unix(),
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(), // 1 hour expiry
		ApprovalHash:  fmt.Sprintf("0x%x", []byte(approvalID)),
		RequiredSigs:  2, // Require 2 signatures
		CollectedSigs: make([]string, 0),
	}

	// Run simulation
	simulation, err := bam.simulateBridgeTransfer(approval)
	if err != nil {
		log.Printf("Bridge simulation failed: %v", err)
		approval.Status = ApprovalRejected
		approval.SimulationData = &SimulationResult{
			Success:     false,
			Errors:      []string{err.Error()},
			SimulatedAt: time.Now().Unix(),
		}
	} else {
		approval.SimulationData = simulation
		if simulation.Success {
			approval.Status = ApprovalSimulated
		} else {
			approval.Status = ApprovalRejected
		}
	}

	// Store approval
	bam.approvals[approvalID] = approval

	// Emit approval event
	approvalEvent := BridgeEvent{
		Type:          EventBridgeApproval,
		BridgeID:      approvalID,
		SourceChain:   sourceChain,
		DestChain:     destChain,
		SourceAddress: userAddr,
		TokenSymbol:   tokenSymbol,
		Amount:        amount,
		Status:        string(approval.Status),
		Metadata: map[string]interface{}{
			"approval_id":       approvalID,
			"simulation_result": simulation,
			"expires_at":        approval.ExpiresAt,
			"required_sigs":     approval.RequiredSigs,
		},
	}
	bam.bridge.EventEmitter.EmitEvent(approvalEvent)

	log.Printf("Bridge approval requested: %s (status: %s)", approvalID, approval.Status)
	return approval, nil
}

// simulateBridgeTransfer simulates a bridge transfer to validate feasibility
func (bam *BridgeApprovalManager) simulateBridgeTransfer(approval *BridgeApproval) (*SimulationResult, error) {
	simulation := &SimulationResult{
		SimulatedAt: time.Now().Unix(),
		Metadata:    make(map[string]interface{}),
	}

	// Check if source chain is supported
	if !bam.bridge.SupportedChains[approval.SourceChain] {
		simulation.Success = false
		simulation.Errors = append(simulation.Errors, fmt.Sprintf("Source chain %s not supported", approval.SourceChain))
		return simulation, nil
	}

	// Check if destination chain is supported
	if !bam.bridge.SupportedChains[approval.DestChain] {
		simulation.Success = false
		simulation.Errors = append(simulation.Errors, fmt.Sprintf("Destination chain %s not supported", approval.DestChain))
		return simulation, nil
	}

	// Check token mapping
	_, exists := bam.bridge.TokenMappings[approval.DestChain][approval.TokenSymbol]
	if !exists {
		simulation.Success = false
		simulation.Errors = append(simulation.Errors, fmt.Sprintf("Token %s not supported on destination chain %s", approval.TokenSymbol, approval.DestChain))
		return simulation, nil
	}

	// If source chain is Blackhole, check token balance and allowance
	if approval.SourceChain == ChainTypeBlackhole {
		token, exists := bam.bridge.Blockchain.TokenRegistry[approval.TokenSymbol]
		if !exists {
			simulation.Success = false
			simulation.Errors = append(simulation.Errors, fmt.Sprintf("Token %s not found", approval.TokenSymbol))
			return simulation, nil
		}

		// Check user balance
		balance, err := token.BalanceOf(approval.UserAddress)
		if err != nil {
			simulation.Success = false
			simulation.Errors = append(simulation.Errors, fmt.Sprintf("Failed to check balance: %v", err))
			return simulation, nil
		}
		simulation.TokenBalance = balance

		if balance < approval.Amount {
			simulation.Success = false
			simulation.Errors = append(simulation.Errors, fmt.Sprintf("Insufficient balance: has %d, needs %d", balance, approval.Amount))
			return simulation, nil
		}

		// Check bridge contract allowance
		allowance, err := token.Allowance(approval.UserAddress, "bridge_contract")
		if err != nil {
			simulation.Success = false
			simulation.Errors = append(simulation.Errors, fmt.Sprintf("Failed to check allowance: %v", err))
			return simulation, nil
		}
		simulation.CurrentAllowance = allowance
		simulation.AllowanceRequired = approval.Amount

		if allowance < approval.Amount {
			simulation.Warnings = append(simulation.Warnings, fmt.Sprintf("Insufficient bridge allowance: has %d, needs %d", allowance, approval.Amount))
			simulation.Metadata["allowance_needed"] = approval.Amount - allowance
		}
	}

	// Estimate gas and fees
	simulation.EstimatedGas = bam.estimateGas(approval)
	simulation.EstimatedFee = bam.estimateFee(approval)
	simulation.EstimatedTime = bam.estimateTime(approval)

	// Add metadata
	simulation.Metadata["source_chain"] = approval.SourceChain
	simulation.Metadata["dest_chain"] = approval.DestChain
	simulation.Metadata["bridge_route"] = fmt.Sprintf("%s->%s", approval.SourceChain, approval.DestChain)

	// Simulation successful if no errors
	simulation.Success = len(simulation.Errors) == 0

	return simulation, nil
}

// estimateGas estimates gas usage for the bridge transfer
func (bam *BridgeApprovalManager) estimateGas(approval *BridgeApproval) uint64 {
	baseGas := uint64(21000) // Base transaction gas
	
	// Add gas for token operations
	if approval.SourceChain == ChainTypeBlackhole {
		baseGas += 30000 // Token transfer gas
	}
	
	// Add gas for bridge operations
	baseGas += 50000 // Bridge contract interaction
	
	// Add gas for destination chain operations
	if approval.DestChain == ChainTypeBlackhole {
		baseGas += 40000 // Token minting gas
	}
	
	return baseGas
}

// estimateFee estimates the total fee for the bridge transfer
func (bam *BridgeApprovalManager) estimateFee(approval *BridgeApproval) uint64 {
	gasPrice := uint64(20) // 20 gwei equivalent
	gasUsed := bam.estimateGas(approval)
	
	baseFee := gasPrice * gasUsed
	
	// Add bridge service fee (0.1% of amount)
	bridgeFee := approval.Amount / 1000
	if bridgeFee < 1 {
		bridgeFee = 1 // Minimum fee
	}
	
	return baseFee + bridgeFee
}

// estimateTime estimates the time for bridge transfer completion
func (bam *BridgeApprovalManager) estimateTime(approval *BridgeApproval) string {
	// Base time for relay confirmation
	baseTime := 2 // 2 minutes
	
	// Add time based on chains
	if approval.SourceChain != ChainTypeBlackhole {
		baseTime += 3 // External chain confirmation time
	}
	if approval.DestChain != ChainTypeBlackhole {
		baseTime += 3 // External chain execution time
	}
	
	return fmt.Sprintf("%d-%.0f minutes", baseTime, float64(baseTime)*1.5)
}

// ApproveBridgeTransfer approves a bridge transfer request
func (bam *BridgeApprovalManager) ApproveBridgeTransfer(approvalID, signature string) error {
	bam.mu.Lock()
	defer bam.mu.Unlock()

	approval, exists := bam.approvals[approvalID]
	if !exists {
		return fmt.Errorf("approval %s not found", approvalID)
	}

	approval.mu.Lock()
	defer approval.mu.Unlock()

	// Check if approval is still valid
	if time.Now().Unix() > approval.ExpiresAt {
		approval.Status = ApprovalExpired
		return fmt.Errorf("approval %s has expired", approvalID)
	}

	if approval.Status != ApprovalSimulated {
		return fmt.Errorf("approval %s is not in simulated state", approvalID)
	}

	// Add signature
	approval.CollectedSigs = append(approval.CollectedSigs, signature)

	// Check if we have enough signatures
	if len(approval.CollectedSigs) >= approval.RequiredSigs {
		approval.Status = ApprovalApproved
		approval.ApprovedAt = time.Now().Unix()

		// Create bridge transaction ID for approved transfer
		bridgeID := fmt.Sprintf("bridge_%d_%s", time.Now().UnixNano(), approval.UserAddress[:8])
		approval.BridgeID = bridgeID

		log.Printf("Bridge approval %s approved with %d signatures", approvalID, len(approval.CollectedSigs))
	}

	return nil
}

// GetApproval returns a bridge approval by ID
func (bam *BridgeApprovalManager) GetApproval(approvalID string) (*BridgeApproval, error) {
	bam.mu.RLock()
	defer bam.mu.RUnlock()

	approval, exists := bam.approvals[approvalID]
	if !exists {
		return nil, fmt.Errorf("approval %s not found", approvalID)
	}

	return approval, nil
}

// GetUserApprovals returns all approvals for a user
func (bam *BridgeApprovalManager) GetUserApprovals(userAddr string) []*BridgeApproval {
	bam.mu.RLock()
	defer bam.mu.RUnlock()

	var userApprovals []*BridgeApproval
	for _, approval := range bam.approvals {
		if approval.UserAddress == userAddr {
			userApprovals = append(userApprovals, approval)
		}
	}

	return userApprovals
}

// CleanupExpiredApprovals removes expired approvals
func (bam *BridgeApprovalManager) CleanupExpiredApprovals() {
	bam.mu.Lock()
	defer bam.mu.Unlock()

	now := time.Now().Unix()
	for id, approval := range bam.approvals {
		if now > approval.ExpiresAt && approval.Status == ApprovalPending {
			approval.Status = ApprovalExpired
			log.Printf("Bridge approval %s expired", id)
		}
	}
}
