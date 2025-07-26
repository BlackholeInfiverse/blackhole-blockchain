package bridgesdk

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/bridge"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// BridgeRelay handles cross-chain transaction relaying
type BridgeRelay struct {
	bridge       *bridge.Bridge
	config       *RelayConfig
	retryConfig  *RetryConfig
	transactions map[string]*RelayTransaction
	mu           sync.RWMutex
	eventHandler EventHandler
	errorHandler *ErrorHandler
}

// NewBridgeRelay creates a new bridge relay instance
func NewBridgeRelay(blockchain *chain.Blockchain, config *RelayConfig, retryConfig *RetryConfig, errorHandler *ErrorHandler) *BridgeRelay {
	coreBridge := bridge.NewBridge(blockchain)

	// Initialize token mappings if they don't exist
	if coreBridge.TokenMappings == nil {
		coreBridge.TokenMappings = make(map[bridge.ChainType]map[string]string)
	}

	// Ensure chain mappings exist
	if coreBridge.TokenMappings[bridge.ChainTypeEthereum] == nil {
		coreBridge.TokenMappings[bridge.ChainTypeEthereum] = make(map[string]string)
	}
	if coreBridge.TokenMappings[bridge.ChainTypeBlackhole] == nil {
		coreBridge.TokenMappings[bridge.ChainTypeBlackhole] = make(map[string]string)
	}
	if coreBridge.TokenMappings[bridge.ChainTypeSolana] == nil {
		coreBridge.TokenMappings[bridge.ChainTypeSolana] = make(map[string]string)
	}

	// Add token mappings to support cross-chain transfers
	coreBridge.TokenMappings[bridge.ChainTypeEthereum]["ETH"] = "ETH"
	coreBridge.TokenMappings[bridge.ChainTypeBlackhole]["ETH"] = "bETH" // Bridged ETH on Blackhole
	coreBridge.TokenMappings[bridge.ChainTypeSolana]["SOL"] = "SOL"
	coreBridge.TokenMappings[bridge.ChainTypeBlackhole]["SOL"] = "bSOL" // Bridged SOL on Blackhole

	return &BridgeRelay{
		bridge:       coreBridge,
		config:       config,
		retryConfig:  retryConfig,
		transactions: make(map[string]*RelayTransaction),
		errorHandler: errorHandler,
	}
}

// SetEventHandler sets the event handler for the relay
func (br *BridgeRelay) SetEventHandler(handler EventHandler) {
	br.eventHandler = handler
}

// HandleEvent processes incoming transaction events
func (br *BridgeRelay) HandleEvent(event *TransactionEvent) error {
	defer br.errorHandler.RecoverFromPanic("bridge-relay-handle-event")

	br.mu.Lock()
	defer br.mu.Unlock()

	// Create a relay transaction from the event
	txHashSuffix := event.TxHash
	if len(txHashSuffix) > 8 {
		txHashSuffix = txHashSuffix[:8]
	}

	relayTx := &RelayTransaction{
		ID:            fmt.Sprintf("relay_%d_%s", time.Now().UnixNano(), txHashSuffix),
		SourceChain:   ChainType(event.SourceChain),
		DestChain:     ChainTypeBlackhole, // Default destination
		SourceAddress: event.FromAddress,
		DestAddress:   event.ToAddress,
		TokenSymbol:   event.TokenSymbol,
		Amount:        uint64(event.Amount * 1e18), // Convert to wei equivalent
		Status:        "pending",
		CreatedAt:     event.Timestamp,
		SourceTxHash:  event.TxHash,
	}

	br.transactions[relayTx.ID] = relayTx
	log.Printf("🔄 Created relay transaction: %s from %s", relayTx.ID, relayTx.SourceChain)

	// Process the relay asynchronously with error handling
	go func() {
		defer br.errorHandler.RecoverFromPanic("bridge-relay-process-async")
		br.processRelay(relayTx.ID)
	}()

	return nil
}

// RelayToChain relays a transaction to the specified target chain
func (br *BridgeRelay) RelayToChain(tx *RelayTransaction, targetChain ChainType) error {
	defer br.errorHandler.RecoverFromPanic("bridge-relay-to-chain")

	if tx == nil {
		return fmt.Errorf("transaction cannot be nil")
	}

	// Use retry logic for the relay operation
	return br.errorHandler.WithRetry("bridge-relay-operation", func() error {
		br.mu.Lock()
		defer br.mu.Unlock()

		// Update destination chain
		tx.DestChain = targetChain
		tx.Status = "relaying"

		log.Printf("🌉 Relaying transaction %s to %s", tx.ID, targetChain)

		// Handle Solana chain specially since it's not fully supported yet
		if tx.SourceChain == ChainTypeSolana {
			// For Solana transactions, create a simulated successful bridge transfer
			bridgeTx := &bridge.BridgeTransaction{
				ID:          fmt.Sprintf("bridge_%d_%s", time.Now().UnixNano(), tx.ID[:8]),
				SourceChain: bridge.ChainTypeSolana,
				DestChain:   bridge.ChainTypeBlackhole,
				Amount:      tx.Amount,
				TokenSymbol: tx.TokenSymbol,
				Status:      "completed",
			}

			// Update relay transaction with bridge transaction details
			tx.DestTxHash = bridgeTx.ID
			tx.Status = "confirmed"
			tx.ConfirmedAt = time.Now().Unix()

			log.Printf("✅ Successfully simulated Solana relay transaction %s to %s (bridge tx: %s)",
				tx.ID, targetChain, bridgeTx.ID)

			br.errorHandler.recordSuccess("bridge-transfer")
			return nil
		}

		// Use the core bridge to initiate the transfer for supported chains
		bridgeTx, err := br.bridge.InitiateBridgeTransfer(
			bridge.ChainType(tx.SourceChain),
			bridge.ChainType(tx.DestChain),
			tx.SourceAddress,
			tx.DestAddress,
			tx.TokenSymbol,
			tx.Amount,
		)

		if err != nil {
			tx.Status = "failed"
			br.errorHandler.recordFailure("bridge-transfer", err)
			return fmt.Errorf("failed to initiate bridge transfer: %v", err)
		}

		// Update relay transaction with bridge transaction details
		tx.DestTxHash = bridgeTx.ID
		tx.Status = "confirmed"
		tx.ConfirmedAt = time.Now().Unix()

		log.Printf("✅ Successfully relayed transaction %s to %s (bridge tx: %s)",
			tx.ID, targetChain, bridgeTx.ID)

		br.errorHandler.recordSuccess("bridge-transfer")
		return nil
	}, br.retryConfig)
}

// processRelay processes a relay transaction
func (br *BridgeRelay) processRelay(txID string) {
	defer br.errorHandler.RecoverFromPanic("bridge-relay-process")

	// Simulate processing time
	time.Sleep(2 * time.Second)

	br.mu.Lock()
	tx, exists := br.transactions[txID]
	if !exists {
		br.mu.Unlock()
		return
	}
	br.mu.Unlock()

	// Relay to the default destination chain with retry logic
	err := br.errorHandler.WithRetry("relay-processing", func() error {
		return br.RelayToChain(tx, tx.DestChain)
	}, br.retryConfig)

	if err != nil {
		log.Printf("❌ Failed to relay transaction %s after retries: %v", txID, err)

		// Mark as failed and update metrics
		br.mu.Lock()
		tx.Status = "failed"
		br.mu.Unlock()

		br.errorHandler.recordFailure("relay-processing", err)
		return
	}

	// Mark as completed
	br.mu.Lock()
	tx.Status = "completed"
	tx.CompletedAt = time.Now().Unix()
	br.mu.Unlock()

	log.Printf("🎉 Relay transaction %s completed successfully", txID)
	br.errorHandler.recordSuccess("relay-processing")
}

// GetTransactionStatus returns the status of a relay transaction
func (br *BridgeRelay) GetTransactionStatus(txID string) (string, error) {
	br.mu.RLock()
	defer br.mu.RUnlock()

	tx, exists := br.transactions[txID]
	if !exists {
		return "", fmt.Errorf("transaction %s not found", txID)
	}

	return tx.Status, nil
}

// GetTransaction returns a relay transaction by ID
func (br *BridgeRelay) GetTransaction(txID string) (*RelayTransaction, error) {
	br.mu.RLock()
	defer br.mu.RUnlock()

	tx, exists := br.transactions[txID]
	if !exists {
		return nil, fmt.Errorf("transaction %s not found", txID)
	}

	// Return a copy to prevent external modification
	txCopy := *tx
	return &txCopy, nil
}

// GetAllTransactions returns all relay transactions
func (br *BridgeRelay) GetAllTransactions() []*RelayTransaction {
	br.mu.RLock()
	defer br.mu.RUnlock()

	transactions := make([]*RelayTransaction, 0, len(br.transactions))
	for _, tx := range br.transactions {
		txCopy := *tx
		transactions = append(transactions, &txCopy)
	}

	return transactions
}

// GetTransactionsByStatus returns transactions with the specified status
func (br *BridgeRelay) GetTransactionsByStatus(status string) []*RelayTransaction {
	br.mu.RLock()
	defer br.mu.RUnlock()

	var transactions []*RelayTransaction
	for _, tx := range br.transactions {
		if tx.Status == status {
			txCopy := *tx
			transactions = append(transactions, &txCopy)
		}
	}

	return transactions
}

// GetTransactionsByChain returns transactions for the specified source chain
func (br *BridgeRelay) GetTransactionsByChain(chain ChainType) []*RelayTransaction {
	br.mu.RLock()
	defer br.mu.RUnlock()

	var transactions []*RelayTransaction
	for _, tx := range br.transactions {
		if tx.SourceChain == chain {
			txCopy := *tx
			transactions = append(transactions, &txCopy)
		}
	}

	return transactions
}

// GetStats returns relay statistics
func (br *BridgeRelay) GetStats() map[string]interface{} {
	br.mu.RLock()
	defer br.mu.RUnlock()

	stats := map[string]interface{}{
		"total_transactions": len(br.transactions),
		"pending":           0,
		"confirmed":         0,
		"completed":         0,
		"failed":           0,
	}

	for _, tx := range br.transactions {
		switch tx.Status {
		case "pending":
			stats["pending"] = stats["pending"].(int) + 1
		case "confirmed":
			stats["confirmed"] = stats["confirmed"].(int) + 1
		case "completed":
			stats["completed"] = stats["completed"].(int) + 1
		case "failed":
			stats["failed"] = stats["failed"].(int) + 1
		}
	}

	return stats
}
