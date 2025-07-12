package bridge

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// ChainType represents different blockchain types
type ChainType string

const (
	ChainTypeBlackhole ChainType = "blackhole"
	ChainTypeEthereum  ChainType = "ethereum"
	ChainTypeSolana    ChainType = "solana"
	ChainTypePolkadot  ChainType = "polkadot"
)

// BridgeTransaction represents a cross-chain transaction
type BridgeTransaction struct {
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

// RelayNode represents a bridge relay node
type RelayNode struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	Active    bool   `json:"active"`
}

// Bridge manages cross-chain operations
type Bridge struct {
	SupportedChains map[ChainType]bool              `json:"supported_chains"`
	Transactions    map[string]*BridgeTransaction   `json:"transactions"`
	RelayNodes      map[string]*RelayNode           `json:"relay_nodes"`
	TokenMappings   map[ChainType]map[string]string `json:"token_mappings"` // chain -> original_token -> wrapped_token
	Blockchain      *chain.Blockchain               `json:"-"`
	mu              sync.RWMutex
}

// NewBridge creates a new bridge instance
func NewBridge(blockchain *chain.Blockchain) *Bridge {
	bridge := &Bridge{
		SupportedChains: make(map[ChainType]bool),
		Transactions:    make(map[string]*BridgeTransaction),
		RelayNodes:      make(map[string]*RelayNode),
		TokenMappings:   make(map[ChainType]map[string]string),
		Blockchain:      blockchain,
	}

	// Initialize supported chains
	bridge.SupportedChains[ChainTypeBlackhole] = true
	bridge.SupportedChains[ChainTypeEthereum] = true
	bridge.SupportedChains[ChainTypePolkadot] = true

	// Initialize token mappings
	bridge.TokenMappings[ChainTypeBlackhole] = make(map[string]string)
	bridge.TokenMappings[ChainTypeEthereum] = make(map[string]string)
	bridge.TokenMappings[ChainTypePolkadot] = make(map[string]string)

	// Mock token mappings
	bridge.TokenMappings[ChainTypeBlackhole]["BHX"] = "BHX"
	bridge.TokenMappings[ChainTypeEthereum]["BHX"] = "wBHX" // Wrapped BHX on Ethereum
	bridge.TokenMappings[ChainTypePolkadot]["BHX"] = "pBHX" // Polkadot BHX

	// Initialize mock relay nodes
	bridge.AddRelayNode("relay1", "relay1_address", "relay1_pubkey")
	bridge.AddRelayNode("relay2", "relay2_address", "relay2_pubkey")
	bridge.AddRelayNode("relay3", "relay3_address", "relay3_pubkey")

	return bridge
}

// AddRelayNode adds a new relay node
func (b *Bridge) AddRelayNode(id, address, publicKey string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.RelayNodes[id] = &RelayNode{
		ID:        id,
		Address:   address,
		PublicKey: publicKey,
		Active:    true,
	}
}

// InitiateBridgeTransfer initiates a cross-chain transfer
func (b *Bridge) InitiateBridgeTransfer(sourceChain, destChain ChainType, sourceAddr, destAddr, tokenSymbol string, amount uint64) (*BridgeTransaction, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Validate chains
	if !b.SupportedChains[sourceChain] || !b.SupportedChains[destChain] {
		return nil, fmt.Errorf("unsupported chain")
	}

	// Check token mapping
	_, exists := b.TokenMappings[destChain][tokenSymbol]
	if !exists {
		return nil, fmt.Errorf("token %s not supported on destination chain %s", tokenSymbol, destChain)
	}

	// Generate bridge transaction ID
	bridgeTxID := fmt.Sprintf("bridge_%d_%s", time.Now().UnixNano(), sourceAddr[:8])

	// Create bridge transaction
	bridgeTx := &BridgeTransaction{
		ID:              bridgeTxID,
		SourceChain:     sourceChain,
		DestChain:       destChain,
		SourceAddress:   sourceAddr,
		DestAddress:     destAddr,
		TokenSymbol:     tokenSymbol,
		Amount:          amount,
		Status:          "pending",
		CreatedAt:       time.Now().Unix(),
		RelaySignatures: make([]string, 0),
	}

	// If source chain is Blackhole, lock tokens
	if sourceChain == ChainTypeBlackhole {
		token, exists := b.Blockchain.TokenRegistry[tokenSymbol]
		if !exists {
			return nil, fmt.Errorf("token %s not found", tokenSymbol)
		}

		// Check balance
		balance, err := token.BalanceOf(sourceAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to check balance: %v", err)
		}

		if balance < amount {
			return nil, fmt.Errorf("insufficient balance: has %d, needs %d", balance, amount)
		}

		// Lock tokens in bridge contract
		err = token.Transfer(sourceAddr, "bridge_contract", amount)
		if err != nil {
			return nil, fmt.Errorf("failed to lock tokens: %v", err)
		}

		bridgeTx.SourceTxHash = fmt.Sprintf("blackhole_tx_%d", time.Now().UnixNano())
	}

	b.Transactions[bridgeTxID] = bridgeTx
	fmt.Printf("✅ Bridge transfer initiated: %s (%d %s from %s to %s)\n",
		bridgeTxID, amount, tokenSymbol, sourceChain, destChain)

	// Simulate relay processing
	go b.processRelayConfirmation(bridgeTxID)

	return bridgeTx, nil
}

// processRelayConfirmation simulates relay node confirmation
func (b *Bridge) processRelayConfirmation(bridgeTxID string) {
	// Simulate relay processing time
	time.Sleep(5 * time.Second)

	b.mu.Lock()
	defer b.mu.Unlock()

	bridgeTx, exists := b.Transactions[bridgeTxID]
	if !exists {
		return
	}

	bridgeTx.mu.Lock()
	defer bridgeTx.mu.Unlock()

	// Simulate relay signatures (need 2 out of 3)
	relayCount := 0
	for relayID := range b.RelayNodes {
		if relayCount >= 2 {
			break
		}
		bridgeTx.RelaySignatures = append(bridgeTx.RelaySignatures, fmt.Sprintf("sig_%s_%s", relayID, bridgeTxID))
		relayCount++
	}

	bridgeTx.Status = "confirmed"
	bridgeTx.ConfirmedAt = time.Now().Unix()

	fmt.Printf("✅ Bridge transaction %s confirmed by %d relays\n", bridgeTxID, len(bridgeTx.RelaySignatures))

	// Simulate destination chain processing
	go b.processDestinationTransfer(bridgeTxID)
}

// processDestinationTransfer simulates transfer on destination chain
func (b *Bridge) processDestinationTransfer(bridgeTxID string) {
	// Simulate destination processing time
	time.Sleep(3 * time.Second)

	b.mu.Lock()
	defer b.mu.Unlock()

	bridgeTx, exists := b.Transactions[bridgeTxID]
	if !exists {
		return
	}

	bridgeTx.mu.Lock()
	defer bridgeTx.mu.Unlock()

	// If destination is Blackhole, mint wrapped tokens
	if bridgeTx.DestChain == ChainTypeBlackhole {
		destToken := b.TokenMappings[bridgeTx.DestChain][bridgeTx.TokenSymbol]
		token, exists := b.Blockchain.TokenRegistry[destToken]
		if exists {
			// Mint wrapped tokens to destination address
			err := token.Mint(bridgeTx.DestAddress, bridgeTx.Amount)
			if err == nil {
				bridgeTx.DestTxHash = fmt.Sprintf("blackhole_mint_%d", time.Now().UnixNano())
			}
		}
	} else {
		// Simulate external chain transaction
		bridgeTx.DestTxHash = fmt.Sprintf("%s_tx_%d", bridgeTx.DestChain, time.Now().UnixNano())
	}

	bridgeTx.Status = "completed"
	bridgeTx.CompletedAt = time.Now().Unix()

	fmt.Printf("✅ Bridge transfer completed: %s (tx: %s)\n", bridgeTxID, bridgeTx.DestTxHash)
}

// GetBridgeTransaction returns a bridge transaction
func (b *Bridge) GetBridgeTransaction(bridgeTxID string) (*BridgeTransaction, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bridgeTx, exists := b.Transactions[bridgeTxID]
	if !exists {
		return nil, fmt.Errorf("bridge transaction %s not found", bridgeTxID)
	}

	// Return a copy
	bridgeTxCopy := *bridgeTx
	return &bridgeTxCopy, nil
}

// GetUserBridgeTransactions returns all bridge transactions for a user
func (b *Bridge) GetUserBridgeTransactions(userAddress string) []*BridgeTransaction {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var userTxs []*BridgeTransaction
	for _, bridgeTx := range b.Transactions {
		if bridgeTx.SourceAddress == userAddress || bridgeTx.DestAddress == userAddress {
			bridgeTxCopy := *bridgeTx
			userTxs = append(userTxs, &bridgeTxCopy)
		}
	}

	return userTxs
}

// GetSupportedChains returns list of supported chains
func (b *Bridge) GetSupportedChains() []ChainType {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var chains []ChainType
	for chain, supported := range b.SupportedChains {
		if supported {
			chains = append(chains, chain)
		}
	}

	return chains
}

// GetTokenMapping returns token mapping for a chain
func (b *Bridge) GetTokenMapping(chain ChainType) map[string]string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	mapping := make(map[string]string)
	if chainMapping, exists := b.TokenMappings[chain]; exists {
		for k, v := range chainMapping {
			mapping[k] = v
		}
	}

	return mapping
}

// GenerateTestBridgeTransaction creates a test bridge transaction JSON
func (b *Bridge) GenerateTestBridgeTransaction() string {
	testTx := map[string]interface{}{
		"id":               "bridge_test_12345",
		"source_chain":     "blackhole",
		"dest_chain":       "ethereum",
		"source_address":   "blackhole_addr_123",
		"dest_address":     "0x742d35Cc6634C0532925a3b8D4C9db96590b5",
		"token_symbol":     "BHX",
		"amount":           1000,
		"status":           "pending",
		"created_at":       time.Now().Unix(),
		"relay_signatures": []string{},
	}

	jsonData, _ := json.MarshalIndent(testTx, "", "  ")
	return string(jsonData)
}

// ApprovalSimulation represents the result of a bridge approval simulation
type ApprovalSimulation struct {
	Valid               bool     `json:"valid"`
	TokenSymbol         string   `json:"token_symbol"`
	Owner               string   `json:"owner"`
	Spender             string   `json:"spender"`
	RequestedAmount     uint64   `json:"requested_amount"`
	CurrentAllowance    uint64   `json:"current_allowance"`
	CurrentBalance      uint64   `json:"current_balance"`
	SufficientBalance   bool     `json:"sufficient_balance"`
	SufficientAllowance bool     `json:"sufficient_allowance"`
	Warnings            []string `json:"warnings"`
	EstimatedGasCost    uint64   `json:"estimated_gas_cost"`
	Timestamp           int64    `json:"timestamp"`
}

// SimulateApproval simulates a token approval for bridge operations
func (b *Bridge) SimulateApproval(sourceChain ChainType, tokenSymbol, owner, spender string, amount uint64) (*ApprovalSimulation, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	simulation := &ApprovalSimulation{
		TokenSymbol:      tokenSymbol,
		Owner:            owner,
		Spender:          spender,
		RequestedAmount:  amount,
		Warnings:         make([]string, 0),
		EstimatedGasCost: 45000, // Standard ERC-20 approval gas cost
		Timestamp:        time.Now().Unix(),
	}

	// Get token from blockchain registry
	token, exists := b.Blockchain.TokenRegistry[tokenSymbol]
	if !exists {
		simulation.Valid = false
		simulation.Warnings = append(simulation.Warnings, fmt.Sprintf("Token %s not found", tokenSymbol))
		return simulation, nil
	}

	// Check current balance
	balance, err := token.BalanceOf(owner)
	if err != nil {
		simulation.Valid = false
		simulation.Warnings = append(simulation.Warnings, fmt.Sprintf("Failed to check balance: %v", err))
		return simulation, nil
	}
	simulation.CurrentBalance = balance
	simulation.SufficientBalance = balance >= amount

	// Check current allowance
	allowance, err := token.Allowance(owner, spender)
	if err != nil {
		simulation.Valid = false
		simulation.Warnings = append(simulation.Warnings, fmt.Sprintf("Failed to check allowance: %v", err))
		return simulation, nil
	}
	simulation.CurrentAllowance = allowance
	simulation.SufficientAllowance = allowance >= amount

	// Validate approval requirements
	if !simulation.SufficientBalance {
		simulation.Warnings = append(simulation.Warnings,
			fmt.Sprintf("Insufficient balance: has %d, needs %d", balance, amount))
	}

	if !simulation.SufficientAllowance {
		simulation.Warnings = append(simulation.Warnings,
			fmt.Sprintf("Insufficient allowance: has %d, needs %d", allowance, amount))
	}

	// Check for common issues
	if amount > 1000000000 { // Very large amount
		simulation.Warnings = append(simulation.Warnings, "Large amount detected - please verify")
	}

	if owner == spender {
		simulation.Warnings = append(simulation.Warnings, "Owner and spender are the same address")
	}

	// Simulation is valid if balance and allowance are sufficient
	simulation.Valid = simulation.SufficientBalance && simulation.SufficientAllowance

	return simulation, nil
}

// ValidateApprovalForBridge validates that a bridge transaction has proper approvals
func (b *Bridge) ValidateApprovalForBridge(bridgeTx *BridgeTransaction) error {
	if bridgeTx.SourceChain != ChainTypeBlackhole {
		// For external chains, we assume approvals are handled externally
		return nil
	}

	// For Blackhole chain, validate token approval
	simulation, err := b.SimulateApproval(
		bridgeTx.SourceChain,
		bridgeTx.TokenSymbol,
		bridgeTx.SourceAddress,
		"bridge_contract", // Bridge contract as spender
		bridgeTx.Amount,
	)
	if err != nil {
		return fmt.Errorf("approval simulation failed: %v", err)
	}

	if !simulation.Valid {
		return fmt.Errorf("bridge approval validation failed: %v", simulation.Warnings)
	}

	if len(simulation.Warnings) > 0 {
		fmt.Printf("⚠️ Bridge approval warnings: %v\n", simulation.Warnings)
	}

	return nil
}

// PreValidateBridgeTransfer performs pre-flight validation of a bridge transfer
func (b *Bridge) PreValidateBridgeTransfer(sourceAddr, tokenSymbol string, amount uint64) error {
	// Check if token exists
	token, exists := b.Blockchain.TokenRegistry[tokenSymbol]
	if !exists {
		return fmt.Errorf("token %s not found", tokenSymbol)
	}

	// Check balance
	balance, err := token.BalanceOf(sourceAddr)
	if err != nil {
		return fmt.Errorf("failed to check balance: %v", err)
	}

	if balance < amount {
		return fmt.Errorf("insufficient balance: has %d, needs %d", balance, amount)
	}

	// Check allowance for bridge contract
	allowance, err := token.Allowance(sourceAddr, "bridge_contract")
	if err != nil {
		return fmt.Errorf("failed to check bridge allowance: %v", err)
	}

	if allowance < amount {
		return fmt.Errorf("insufficient bridge allowance: has %d, needs %d. Please approve bridge contract first", allowance, amount)
	}

	return nil
}
