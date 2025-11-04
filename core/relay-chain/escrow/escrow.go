package escrow

import (
	"fmt"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// EscrowStatus represents the status of an escrow
type EscrowStatus int

const (
	EscrowPending EscrowStatus = iota
	EscrowConfirmed
	EscrowReleased
	EscrowCancelled
	EscrowDisputed
)

func (s EscrowStatus) String() string {
	switch s {
	case EscrowPending:
		return "pending"
	case EscrowConfirmed:
		return "confirmed"
	case EscrowReleased:
		return "released"
	case EscrowCancelled:
		return "cancelled"
	case EscrowDisputed:
		return "disputed"
	default:
		return "unknown"
	}
}

// EscrowContract represents an escrow agreement
type EscrowContract struct {
	ID              string                 `json:"id"`
	Sender          string                 `json:"sender"`
	Receiver        string                 `json:"receiver"`
	Arbitrator      string                 `json:"arbitrator,omitempty"`
	TokenSymbol     string                 `json:"token_symbol"`
	Amount          uint64                 `json:"amount"`
	Status          EscrowStatus           `json:"status"`
	CreatedAt       int64                  `json:"created_at"`
	ConfirmedAt     int64                  `json:"confirmed_at,omitempty"`
	ReleasedAt      int64                  `json:"released_at,omitempty"`
	ExpiresAt       int64                  `json:"expires_at"`
	Conditions      map[string]interface{} `json:"conditions,omitempty"`
	Signatures      map[string]bool        `json:"signatures"` // address -> signed
	RequiredSigs    int                    `json:"required_sigs"`
	Description     string                 `json:"description,omitempty"`
	mu              sync.RWMutex
}

// EscrowManager manages all escrow contracts
type EscrowManager struct {
	Contracts  map[string]*EscrowContract `json:"contracts"`
	Blockchain *chain.Blockchain          `json:"-"`
	mu         sync.RWMutex
}

// NewEscrowManager creates a new escrow manager
func NewEscrowManager(blockchain *chain.Blockchain) *EscrowManager {
	return &EscrowManager{
		Contracts:  make(map[string]*EscrowContract),
		Blockchain: blockchain,
	}
}

// CreateEscrow creates a new escrow contract
func (em *EscrowManager) CreateEscrow(sender, receiver, arbitrator, tokenSymbol string, amount uint64, expirationHours int, description string) (*EscrowContract, error) {
	em.mu.Lock()
	defer em.mu.Unlock()

	// Validate addresses
	if sender == "" || receiver == "" {
		return nil, fmt.Errorf("invalid sender or receiver address")
	}

	// Generate unique ID
	escrowID := fmt.Sprintf("escrow_%d_%s", time.Now().UnixNano(), sender[:8])

	// Check if token exists
	token, exists := em.Blockchain.TokenRegistry[tokenSymbol]
	if !exists {
		return nil, fmt.Errorf("token %s not found", tokenSymbol)
	}

	// Check if sender has sufficient balance
	balance, err := token.BalanceOf(sender)
	if err != nil {
		return nil, fmt.Errorf("failed to check balance: %v", err)
	}

	if balance < amount {
		return nil, fmt.Errorf("insufficient balance: has %d, needs %d", balance, amount)
	}

	// Create escrow contract
	contract := &EscrowContract{
		ID:           escrowID,
		Sender:       sender,
		Receiver:     receiver,
		Arbitrator:   arbitrator,
		TokenSymbol:  tokenSymbol,
		Amount:       amount,
		Status:       EscrowPending,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Duration(expirationHours) * time.Hour).Unix(),
		Signatures:   make(map[string]bool),
		RequiredSigs: 2, // Sender and receiver by default
		Description:  description,
		Conditions:   make(map[string]interface{}),
	}

	if arbitrator != "" {
		contract.RequiredSigs = 2 // Any 2 of 3 (sender, receiver, arbitrator)
	}

	// Lock tokens in escrow
	err = token.Transfer(sender, "escrow_contract", amount)
	if err != nil {
		return nil, fmt.Errorf("failed to lock tokens in escrow: %v", err)
	}

	em.Contracts[escrowID] = contract
	fmt.Printf("✅ Escrow created: %s (%d %s from %s to %s)\n", escrowID, amount, tokenSymbol, sender, receiver)
	return contract, nil
}

// ConfirmEscrow allows a party to confirm the escrow
func (em *EscrowManager) ConfirmEscrow(escrowID, signer string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	contract, exists := em.Contracts[escrowID]
	if !exists {
		return fmt.Errorf("escrow %s not found", escrowID)
	}

	contract.mu.Lock()
	defer contract.mu.Unlock()

	if contract.Status != EscrowPending {
		return fmt.Errorf("escrow is not in pending status")
	}

	// Check if signer is authorized
	if signer != contract.Sender && signer != contract.Receiver && signer != contract.Arbitrator {
		return fmt.Errorf("unauthorized signer")
	}

	// Check expiration
	if time.Now().Unix() > contract.ExpiresAt {
		contract.Status = EscrowCancelled
		em.releaseTokensToSender(contract)
		return fmt.Errorf("escrow has expired")
	}

	// Add signature
	contract.Signatures[signer] = true

	// Check if we have enough signatures
	if len(contract.Signatures) >= contract.RequiredSigs {
		contract.Status = EscrowConfirmed
		contract.ConfirmedAt = time.Now().Unix()
		fmt.Printf("✅ Escrow %s confirmed with %d signatures\n", escrowID, len(contract.Signatures))
	}

	return nil
}

// ReleaseEscrow releases the escrowed tokens to the receiver
func (em *EscrowManager) ReleaseEscrow(escrowID, releaser string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	contract, exists := em.Contracts[escrowID]
	if !exists {
		return fmt.Errorf("escrow %s not found", escrowID)
	}

	contract.mu.Lock()
	defer contract.mu.Unlock()

	if contract.Status != EscrowConfirmed {
		return fmt.Errorf("escrow must be confirmed before release")
	}

	// Check if releaser is authorized (sender or arbitrator)
	if releaser != contract.Sender && releaser != contract.Arbitrator {
		return fmt.Errorf("only sender or arbitrator can release escrow")
	}

	// Release tokens to receiver
	token, exists := em.Blockchain.TokenRegistry[contract.TokenSymbol]
	if !exists {
		return fmt.Errorf("token %s not found", contract.TokenSymbol)
	}

	err := token.Transfer("escrow_contract", contract.Receiver, contract.Amount)
	if err != nil {
		return fmt.Errorf("failed to release tokens: %v", err)
	}

	contract.Status = EscrowReleased
	contract.ReleasedAt = time.Now().Unix()

	fmt.Printf("✅ Escrow %s released: %d %s to %s\n", escrowID, contract.Amount, contract.TokenSymbol, contract.Receiver)
	return nil
}

// CancelEscrow cancels an escrow and returns tokens to sender
func (em *EscrowManager) CancelEscrow(escrowID, canceller string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	contract, exists := em.Contracts[escrowID]
	if !exists {
		return fmt.Errorf("escrow %s not found", escrowID)
	}

	contract.mu.Lock()
	defer contract.mu.Unlock()

	if contract.Status != EscrowPending && contract.Status != EscrowConfirmed {
		return fmt.Errorf("escrow cannot be cancelled in current status")
	}

	// Check if canceller is authorized
	if canceller != contract.Sender && canceller != contract.Arbitrator {
		return fmt.Errorf("only sender or arbitrator can cancel escrow")
	}

	// Return tokens to sender
	em.releaseTokensToSender(contract)
	contract.Status = EscrowCancelled

	fmt.Printf("✅ Escrow %s cancelled, tokens returned to %s\n", escrowID, contract.Sender)
	return nil
}

// DisputeEscrow marks an escrow as disputed
func (em *EscrowManager) DisputeEscrow(escrowID, disputer string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	contract, exists := em.Contracts[escrowID]
	if !exists {
		return fmt.Errorf("escrow %s not found", escrowID)
	}

	contract.mu.Lock()
	defer contract.mu.Unlock()

	// Check if disputer is authorized
	if disputer != contract.Sender && disputer != contract.Receiver {
		return fmt.Errorf("only sender or receiver can dispute escrow")
	}

	contract.Status = EscrowDisputed
	fmt.Printf("⚠️ Escrow %s disputed by %s\n", escrowID, disputer)
	return nil
}

// GetEscrow returns an escrow contract
func (em *EscrowManager) GetEscrow(escrowID string) (*EscrowContract, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	contract, exists := em.Contracts[escrowID]
	if !exists {
		return nil, fmt.Errorf("escrow %s not found", escrowID)
	}

	// Return a copy to avoid race conditions
	contractCopy := *contract
	return &contractCopy, nil
}

// GetUserEscrows returns all escrows for a user
func (em *EscrowManager) GetUserEscrows(userAddress string) []*EscrowContract {
	em.mu.RLock()
	defer em.mu.RUnlock()

	var userEscrows []*EscrowContract
	for _, contract := range em.Contracts {
		if contract.Sender == userAddress || contract.Receiver == userAddress || contract.Arbitrator == userAddress {
			contractCopy := *contract
			userEscrows = append(userEscrows, &contractCopy)
		}
	}

	return userEscrows
}

// ProcessExpiredEscrows processes expired escrows and returns tokens to senders
func (em *EscrowManager) ProcessExpiredEscrows() {
	em.mu.Lock()
	defer em.mu.Unlock()

	currentTime := time.Now().Unix()
	for _, contract := range em.Contracts {
		contract.mu.Lock()
		if contract.Status == EscrowPending && currentTime > contract.ExpiresAt {
			em.releaseTokensToSender(contract)
			contract.Status = EscrowCancelled
			fmt.Printf("⏰ Expired escrow %s cancelled, tokens returned to %s\n", contract.ID, contract.Sender)
		}
		contract.mu.Unlock()
	}
}

// Helper function to release tokens back to sender
func (em *EscrowManager) releaseTokensToSender(contract *EscrowContract) error {
	token, exists := em.Blockchain.TokenRegistry[contract.TokenSymbol]
	if !exists {
		return fmt.Errorf("token %s not found", contract.TokenSymbol)
	}

	return token.Transfer("escrow_contract", contract.Sender, contract.Amount)
}

