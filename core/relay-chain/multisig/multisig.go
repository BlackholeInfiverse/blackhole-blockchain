package multisig

import (
	"fmt"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// MultiSigWallet represents a multi-signature wallet
type MultiSigWallet struct {
	ID              string            `json:"id"`
	Address         string            `json:"address"`
	Owners          []string          `json:"owners"`
	RequiredSigs    int               `json:"required_sigs"`
	Nonce           uint64            `json:"nonce"`
	CreatedAt       int64             `json:"created_at"`
	mu              sync.RWMutex
}

// PendingTransaction represents a transaction waiting for signatures
type PendingTransaction struct {
	ID              string            `json:"id"`
	WalletID        string            `json:"wallet_id"`
	To              string            `json:"to"`
	Amount          uint64            `json:"amount"`
	TokenSymbol     string            `json:"token_symbol"`
	Data            []byte            `json:"data,omitempty"`
	Signatures      map[string]bool   `json:"signatures"` // owner -> signed
	RequiredSigs    int               `json:"required_sigs"`
	CreatedAt       int64             `json:"created_at"`
	ExpiresAt       int64             `json:"expires_at"`
	Executed        bool              `json:"executed"`
	mu              sync.RWMutex
}

// MultiSigManager manages multi-signature wallets
type MultiSigManager struct {
	Wallets             map[string]*MultiSigWallet     `json:"wallets"`
	PendingTransactions map[string]*PendingTransaction `json:"pending_transactions"`
	Blockchain          *chain.Blockchain              `json:"-"`
	mu                  sync.RWMutex
}

// NewMultiSigManager creates a new multi-signature manager
func NewMultiSigManager(blockchain *chain.Blockchain) *MultiSigManager {
	return &MultiSigManager{
		Wallets:             make(map[string]*MultiSigWallet),
		PendingTransactions: make(map[string]*PendingTransaction),
		Blockchain:          blockchain,
	}
}

// CreateMultiSigWallet creates a new multi-signature wallet
func (msm *MultiSigManager) CreateMultiSigWallet(owners []string, requiredSigs int) (*MultiSigWallet, error) {
	msm.mu.Lock()
	defer msm.mu.Unlock()

	if len(owners) < 2 {
		return nil, fmt.Errorf("multi-sig wallet requires at least 2 owners")
	}

	if requiredSigs < 1 || requiredSigs > len(owners) {
		return nil, fmt.Errorf("required signatures must be between 1 and %d", len(owners))
	}

	// Generate unique wallet ID and address
	walletID := fmt.Sprintf("multisig_%d", time.Now().UnixNano())
	walletAddress := fmt.Sprintf("multisig_%s", walletID[8:16])

	wallet := &MultiSigWallet{
		ID:           walletID,
		Address:      walletAddress,
		Owners:       owners,
		RequiredSigs: requiredSigs,
		Nonce:        0,
		CreatedAt:    time.Now().Unix(),
	}

	msm.Wallets[walletID] = wallet
	fmt.Printf("✅ Multi-sig wallet created: %s with %d/%d signatures required\n", 
		walletAddress, requiredSigs, len(owners))
	return wallet, nil
}

// ProposeTransaction proposes a new transaction for the multi-sig wallet
func (msm *MultiSigManager) ProposeTransaction(walletID, proposer, to, tokenSymbol string, amount uint64, expirationHours int) (*PendingTransaction, error) {
	msm.mu.Lock()
	defer msm.mu.Unlock()

	wallet, exists := msm.Wallets[walletID]
	if !exists {
		return nil, fmt.Errorf("wallet %s not found", walletID)
	}

	// Check if proposer is an owner
	isOwner := false
	for _, owner := range wallet.Owners {
		if owner == proposer {
			isOwner = true
			break
		}
	}
	if !isOwner {
		return nil, fmt.Errorf("proposer %s is not an owner of wallet %s", proposer, walletID)
	}

	// Check wallet balance
	token, exists := msm.Blockchain.TokenRegistry[tokenSymbol]
	if !exists {
		return nil, fmt.Errorf("token %s not found", tokenSymbol)
	}

	balance, err := token.BalanceOf(wallet.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to check wallet balance: %v", err)
	}

	if balance < amount {
		return nil, fmt.Errorf("insufficient wallet balance: has %d, needs %d", balance, amount)
	}

	// Create pending transaction
	txID := fmt.Sprintf("tx_%d_%s", time.Now().UnixNano(), proposer[:8])
	pendingTx := &PendingTransaction{
		ID:           txID,
		WalletID:     walletID,
		To:           to,
		Amount:       amount,
		TokenSymbol:  tokenSymbol,
		Signatures:   make(map[string]bool),
		RequiredSigs: wallet.RequiredSigs,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Duration(expirationHours) * time.Hour).Unix(),
		Executed:     false,
	}

	// Proposer automatically signs
	pendingTx.Signatures[proposer] = true

	msm.PendingTransactions[txID] = pendingTx
	fmt.Printf("✅ Transaction proposed: %s (%d %s to %s) - 1/%d signatures\n", 
		txID, amount, tokenSymbol, to, wallet.RequiredSigs)
	return pendingTx, nil
}

// SignTransaction signs a pending transaction
func (msm *MultiSigManager) SignTransaction(txID, signer string) error {
	msm.mu.Lock()
	defer msm.mu.Unlock()

	pendingTx, exists := msm.PendingTransactions[txID]
	if !exists {
		return fmt.Errorf("transaction %s not found", txID)
	}

	pendingTx.mu.Lock()
	defer pendingTx.mu.Unlock()

	if pendingTx.Executed {
		return fmt.Errorf("transaction already executed")
	}

	// Check expiration
	if time.Now().Unix() > pendingTx.ExpiresAt {
		return fmt.Errorf("transaction has expired")
	}

	wallet := msm.Wallets[pendingTx.WalletID]
	
	// Check if signer is an owner
	isOwner := false
	for _, owner := range wallet.Owners {
		if owner == signer {
			isOwner = true
			break
		}
	}
	if !isOwner {
		return fmt.Errorf("signer %s is not an owner of wallet %s", signer, pendingTx.WalletID)
	}

	// Add signature
	pendingTx.Signatures[signer] = true

	fmt.Printf("✅ Transaction %s signed by %s - %d/%d signatures\n", 
		txID, signer, len(pendingTx.Signatures), pendingTx.RequiredSigs)

	// Check if we have enough signatures to execute
	if len(pendingTx.Signatures) >= pendingTx.RequiredSigs {
		return msm.executeTransaction(pendingTx)
	}

	return nil
}

// executeTransaction executes a transaction when enough signatures are collected
func (msm *MultiSigManager) executeTransaction(pendingTx *PendingTransaction) error {
	wallet := msm.Wallets[pendingTx.WalletID]
	
	// Get token
	token, exists := msm.Blockchain.TokenRegistry[pendingTx.TokenSymbol]
	if !exists {
		return fmt.Errorf("token %s not found", pendingTx.TokenSymbol)
	}

	// Execute transfer
	err := token.Transfer(wallet.Address, pendingTx.To, pendingTx.Amount)
	if err != nil {
		return fmt.Errorf("failed to execute transfer: %v", err)
	}

	// Mark as executed
	pendingTx.Executed = true
	wallet.Nonce++

	fmt.Printf("✅ Multi-sig transaction executed: %d %s from %s to %s\n", 
		pendingTx.Amount, pendingTx.TokenSymbol, wallet.Address, pendingTx.To)
	return nil
}

// GetWallet returns a multi-sig wallet
func (msm *MultiSigManager) GetWallet(walletID string) (*MultiSigWallet, error) {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	wallet, exists := msm.Wallets[walletID]
	if !exists {
		return nil, fmt.Errorf("wallet %s not found", walletID)
	}

	// Return a copy
	walletCopy := *wallet
	return &walletCopy, nil
}

// GetUserWallets returns all multi-sig wallets where user is an owner
func (msm *MultiSigManager) GetUserWallets(userAddress string) []*MultiSigWallet {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	var userWallets []*MultiSigWallet
	for _, wallet := range msm.Wallets {
		for _, owner := range wallet.Owners {
			if owner == userAddress {
				walletCopy := *wallet
				userWallets = append(userWallets, &walletCopy)
				break
			}
		}
	}

	return userWallets
}

// GetPendingTransactions returns all pending transactions for a wallet
func (msm *MultiSigManager) GetPendingTransactions(walletID string) []*PendingTransaction {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	var pending []*PendingTransaction
	for _, tx := range msm.PendingTransactions {
		if tx.WalletID == walletID && !tx.Executed && time.Now().Unix() <= tx.ExpiresAt {
			txCopy := *tx
			pending = append(pending, &txCopy)
		}
	}

	return pending
}

// GetUserPendingTransactions returns all pending transactions where user can sign
func (msm *MultiSigManager) GetUserPendingTransactions(userAddress string) []*PendingTransaction {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	var pending []*PendingTransaction
	for _, tx := range msm.PendingTransactions {
		if tx.Executed || time.Now().Unix() > tx.ExpiresAt {
			continue
		}

		wallet := msm.Wallets[tx.WalletID]
		for _, owner := range wallet.Owners {
			if owner == userAddress {
				txCopy := *tx
				pending = append(pending, &txCopy)
				break
			}
		}
	}

	return pending
}

// CleanupExpiredTransactions removes expired transactions
func (msm *MultiSigManager) CleanupExpiredTransactions() {
	msm.mu.Lock()
	defer msm.mu.Unlock()

	currentTime := time.Now().Unix()
	for txID, tx := range msm.PendingTransactions {
		if !tx.Executed && currentTime > tx.ExpiresAt {
			delete(msm.PendingTransactions, txID)
			fmt.Printf("🗑️ Expired transaction %s removed\n", txID)
		}
	}
}
