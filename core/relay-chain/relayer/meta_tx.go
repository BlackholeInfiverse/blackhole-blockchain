package relayer

import (
	"crypto/ecdsa"
	"fmt"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// MetaTxStatus represents the status of a meta transaction
type MetaTxStatus string

const (
	MetaTxPending   MetaTxStatus = "pending"
	MetaTxProcessed MetaTxStatus = "processed"
	MetaTxFailed    MetaTxStatus = "failed"
	MetaTxExpired   MetaTxStatus = "expired"
)

// MetaTransaction represents a gasless transaction
type MetaTransaction struct {
	ID           string       `json:"id"`
	UserAddress  string       `json:"user_address"`
	To           string       `json:"to"`
	Data         []byte       `json:"data"`
	Value        uint64       `json:"value"`
	GasLimit     uint64       `json:"gas_limit"`
	Nonce        uint64       `json:"nonce"`
	Signature    []byte       `json:"signature"`
	Status       MetaTxStatus `json:"status"`
	CreatedAt    int64        `json:"created_at"`
	ProcessedAt  int64        `json:"processed_at,omitempty"`
	RelayerFee   uint64       `json:"relayer_fee"`
	mu           sync.RWMutex
}

// RelayerConfig holds configuration for the relayer
type RelayerConfig struct {
	MaxGasPrice      uint64 `json:"max_gas_price"`
	MinRelayerFee    uint64 `json:"min_relayer_fee"`
	SubsidyTreasury  string `json:"subsidy_treasury"`
	MaxQueueSize     int    `json:"max_queue_size"`
	ProcessInterval  int    `json:"process_interval"` // seconds
}

// MetaTxRelayer manages gasless transaction processing
type MetaTxRelayer struct {
	Config          RelayerConfig              `json:"config"`
	PendingTxs      map[string]*MetaTransaction `json:"pending_txs"`
	ProcessedTxs    map[string]*MetaTransaction `json:"processed_txs"`
	Blockchain      *chain.Blockchain          `json:"-"`
	RelayerKey      *ecdsa.PrivateKey          `json:"-"`
	SubsidyBalance  uint64                     `json:"subsidy_balance"`
	mu              sync.RWMutex
}

// NewMetaTxRelayer creates a new meta-transaction relayer
func NewMetaTxRelayer(blockchain *chain.Blockchain, config RelayerConfig) *MetaTxRelayer {
	relayer := &MetaTxRelayer{
		Config:       config,
		PendingTxs:   make(map[string]*MetaTransaction),
		ProcessedTxs: make(map[string]*MetaTransaction),
		Blockchain:   blockchain,
	}

	// Start background processing
	go relayer.startProcessor()
	go relayer.startCleanup()

	return relayer
}

// SubmitMetaTx submits a meta transaction for gasless execution
func (r *MetaTxRelayer) SubmitMetaTx(userAddr, to string, data []byte, value, gasLimit uint64, signature []byte) (*MetaTransaction, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check queue size limit
	if len(r.PendingTxs) >= r.Config.MaxQueueSize {
		return nil, fmt.Errorf("relayer queue is full")
	}

	// Calculate relayer fee
	relayerFee := r.calculateRelayerFee(gasLimit)
	if relayerFee < r.Config.MinRelayerFee {
		relayerFee = r.Config.MinRelayerFee
	}

	// Generate meta transaction ID
	userSuffix := userAddr
	if len(userAddr) > 8 {
		userSuffix = userAddr[:8]
	}
	metaTxID := fmt.Sprintf("meta_%d_%s", time.Now().UnixNano(), userSuffix)

	metaTx := &MetaTransaction{
		ID:          metaTxID,
		UserAddress: userAddr,
		To:          to,
		Data:        data,
		Value:       value,
		GasLimit:    gasLimit,
		Signature:   signature,
		Status:      MetaTxPending,
		CreatedAt:   time.Now().Unix(),
		RelayerFee:  relayerFee,
	}

	r.PendingTxs[metaTxID] = metaTx
	fmt.Printf("✅ Meta transaction submitted: %s (fee: %d)\n", metaTxID, relayerFee)
	return metaTx, nil
}

// ProcessMetaTx processes a pending meta transaction
func (r *MetaTxRelayer) ProcessMetaTx(metaTxID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	metaTx, exists := r.PendingTxs[metaTxID]
	if !exists {
		return fmt.Errorf("meta transaction %s not found", metaTxID)
	}

	metaTx.mu.Lock()
	defer metaTx.mu.Unlock()

	// Check if already processed
	if metaTx.Status != MetaTxPending {
		return fmt.Errorf("meta transaction already processed")
	}

	// Check subsidy balance
	totalCost := metaTx.Value + metaTx.RelayerFee
	if r.SubsidyBalance < totalCost {
		metaTx.Status = MetaTxFailed
		return fmt.Errorf("insufficient subsidy balance: has %d, needs %d", r.SubsidyBalance, totalCost)
	}

	// Execute the transaction using subsidy treasury
	err := r.executeTransaction(metaTx)
	if err != nil {
		metaTx.Status = MetaTxFailed
		fmt.Printf("❌ Meta transaction failed: %s - %v\n", metaTxID, err)
		return err
	}

	// Update status and move to processed
	metaTx.Status = MetaTxProcessed
	metaTx.ProcessedAt = time.Now().Unix()
	r.SubsidyBalance -= totalCost

	r.ProcessedTxs[metaTxID] = metaTx
	delete(r.PendingTxs, metaTxID)

	fmt.Printf("✅ Meta transaction processed: %s\n", metaTxID)
	return nil
}

// executeTransaction executes the meta transaction on-chain
func (r *MetaTxRelayer) executeTransaction(metaTx *MetaTransaction) error {
	// Start atomic transaction
	tx := r.Blockchain.BeginTransaction()

	// Get treasury token
	treasuryToken, exists := r.Blockchain.TokenRegistry["BHX"]
	if !exists {
		tx.Rollback()
		return fmt.Errorf("treasury token BHX not found")
	}

	// Transfer value from treasury to destination if needed
	if metaTx.Value > 0 {
		err := tx.Transfer(treasuryToken, r.Config.SubsidyTreasury, metaTx.To, metaTx.Value)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to transfer value: %v", err)
		}
	}

	// Process any additional data/contract calls here
	// This would involve decoding metaTx.Data and executing appropriate operations

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}

// calculateRelayerFee calculates the fee for processing the meta transaction
func (r *MetaTxRelayer) calculateRelayerFee(gasLimit uint64) uint64 {
	baseFee := uint64(1000) // Base fee in smallest unit
	gasFee := gasLimit * 10 // Fee per gas unit
	return baseFee + gasFee
}

// GetMetaTx retrieves a meta transaction by ID
func (r *MetaTxRelayer) GetMetaTx(metaTxID string) (*MetaTransaction, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check pending first
	if metaTx, exists := r.PendingTxs[metaTxID]; exists {
		metaTxCopy := *metaTx
		return &metaTxCopy, nil
	}

	// Check processed
	if metaTx, exists := r.ProcessedTxs[metaTxID]; exists {
		metaTxCopy := *metaTx
		return &metaTxCopy, nil
	}

	return nil, fmt.Errorf("meta transaction %s not found", metaTxID)
}

// GetPendingTxs returns all pending meta transactions
func (r *MetaTxRelayer) GetPendingTxs() []*MetaTransaction {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var pending []*MetaTransaction
	for _, metaTx := range r.PendingTxs {
		metaTxCopy := *metaTx
		pending = append(pending, &metaTxCopy)
	}
	return pending
}

// GetUserTxs returns all transactions for a specific user
func (r *MetaTxRelayer) GetUserTxs(userAddr string) []*MetaTransaction {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var userTxs []*MetaTransaction

	// Check pending
	for _, metaTx := range r.PendingTxs {
		if metaTx.UserAddress == userAddr {
			metaTxCopy := *metaTx
			userTxs = append(userTxs, &metaTxCopy)
		}
	}

	// Check processed
	for _, metaTx := range r.ProcessedTxs {
		if metaTx.UserAddress == userAddr {
			metaTxCopy := *metaTx
			userTxs = append(userTxs, &metaTxCopy)
		}
	}

	return userTxs
}

// FundSubsidy adds funds to the subsidy treasury
func (r *MetaTxRelayer) FundSubsidy(amount uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.SubsidyBalance += amount
	fmt.Printf("💰 Subsidy treasury funded: %d (new balance: %d)\n", amount, r.SubsidyBalance)
	return nil
}

// startProcessor starts the background processor for pending transactions
func (r *MetaTxRelayer) startProcessor() {
	ticker := time.NewTicker(time.Duration(r.Config.ProcessInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.processPendingTxs()
		}
	}
}

// processPendingTxs processes all pending meta transactions
func (r *MetaTxRelayer) processPendingTxs() {
	r.mu.RLock()
	pendingIDs := make([]string, 0, len(r.PendingTxs))
	for id := range r.PendingTxs {
		pendingIDs = append(pendingIDs, id)
	}
	r.mu.RUnlock()

	for _, id := range pendingIDs {
		if err := r.ProcessMetaTx(id); err != nil {
			fmt.Printf("⚠️ Failed to process meta tx %s: %v\n", id, err)
		}
	}
}

// startCleanup starts the cleanup process for expired transactions
func (r *MetaTxRelayer) startCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.cleanupExpiredTxs()
		}
	}
}

// cleanupExpiredTxs removes expired transactions from the system
func (r *MetaTxRelayer) cleanupExpiredTxs() {
	r.mu.Lock()
	defer r.mu.Unlock()

	currentTime := time.Now().Unix()
	expirationTime := int64(3600) // 1 hour expiration

	// Cleanup pending transactions
	for id, metaTx := range r.PendingTxs {
		if currentTime-metaTx.CreatedAt > expirationTime {
			metaTx.Status = MetaTxExpired
			delete(r.PendingTxs, id)
			fmt.Printf("🗑️ Expired meta transaction removed: %s\n", id)
		}
	}

	// Cleanup old processed transactions (keep for 24 hours)
	cleanupTime := int64(86400) // 24 hours
	for id, metaTx := range r.ProcessedTxs {
		if currentTime-metaTx.ProcessedAt > cleanupTime {
			delete(r.ProcessedTxs, id)
		}
	}
}

// RelayerStats represents statistics for the relayer
type RelayerStats struct {
	PendingTxs      int    `json:"pending_txs"`
	ProcessedTxs    int    `json:"processed_txs"`
	FailedTxs       int    `json:"failed_txs"`
	SubsidyBalance  uint64 `json:"subsidy_balance"`
	TotalFeesEarned uint64 `json:"total_fees_earned"`
	Uptime          int64  `json:"uptime"`
}

// GetStats returns statistics about the relayer
func (r *MetaTxRelayer) GetStats() RelayerStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := RelayerStats{
		PendingTxs:     len(r.PendingTxs),
		SubsidyBalance: r.SubsidyBalance,
		Uptime:         time.Now().Unix(),
	}

	// Count processed and failed transactions
	for _, metaTx := range r.ProcessedTxs {
		if metaTx.Status == MetaTxProcessed {
			stats.ProcessedTxs++
			stats.TotalFeesEarned += metaTx.RelayerFee
		} else if metaTx.Status == MetaTxFailed {
			stats.FailedTxs++
		}
	}

	return stats
}