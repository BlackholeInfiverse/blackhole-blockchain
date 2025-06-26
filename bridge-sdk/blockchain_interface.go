package main

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/bridge"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// BlackHoleBlockchainInterface provides bridge-sdk access to core blockchain
type BlackHoleBlockchainInterface struct {
	blockchain    *chain.Blockchain
	bridge        *bridge.Bridge
	logger        *logrus.Logger
	eventChan     chan BlockchainEvent
	subscribers   []chan BlockchainEvent
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
}

// BlockchainEvent represents events from the core blockchain
type BlockchainEvent struct {
	Type        string                 `json:"type"`
	TxHash      string                 `json:"tx_hash"`
	BlockNumber uint64                 `json:"block_number"`
	Data        map[string]interface{} `json:"data"`
	Timestamp   time.Time              `json:"timestamp"`
}

// TransactionStatus represents the status of a blockchain transaction
type TransactionStatus struct {
	Hash          string    `json:"hash"`
	Status        string    `json:"status"`
	BlockNumber   uint64    `json:"block_number"`
	Confirmations int       `json:"confirmations"`
	Timestamp     time.Time `json:"timestamp"`
}

// NewBlackHoleBlockchainInterface creates a new blockchain interface
func NewBlackHoleBlockchainInterface(blockchain *chain.Blockchain, logger *logrus.Logger) *BlackHoleBlockchainInterface {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Initialize bridge if not already present
	var bridgeInstance *bridge.Bridge
	if blockchain != nil {
		bridgeInstance = bridge.NewBridge(blockchain)
	}

	bhi := &BlackHoleBlockchainInterface{
		blockchain:  blockchain,
		bridge:      bridgeInstance,
		logger:      logger,
		eventChan:   make(chan BlockchainEvent, 100),
		subscribers: make([]chan BlockchainEvent, 0),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Start event monitoring if blockchain is available
	if blockchain != nil {
		go bhi.monitorBlockchainEvents()
	}

	return bhi
}

// ProcessBridgeTransaction processes a bridge transaction on the BlackHole blockchain
func (bhi *BlackHoleBlockchainInterface) ProcessBridgeTransaction(bridgeTx *Transaction) error {
	if bhi.blockchain == nil {
		return fmt.Errorf("blockchain not available - running in simulation mode")
	}

	bhi.logger.Infof("🔗 Processing bridge transaction on BlackHole blockchain: %s", bridgeTx.ID)

	// Convert bridge transaction to core blockchain transaction
	coreTx, err := bhi.convertBridgeToCoreTx(bridgeTx)
	if err != nil {
		return fmt.Errorf("failed to convert bridge transaction: %v", err)
	}

	// Process transaction through core blockchain
	err = bhi.blockchain.ProcessTransaction(coreTx)
	if err != nil {
		return fmt.Errorf("failed to process transaction on blockchain: %v", err)
	}

	// Update bridge transaction status
	bridgeTx.Status = "confirmed"
	bridgeTx.BlockNumber = uint64(len(bhi.blockchain.Blocks))
	now := time.Now()
	bridgeTx.CompletedAt = &now
	bridgeTx.ProcessingTime = fmt.Sprintf("%.2fs", time.Since(bridgeTx.CreatedAt).Seconds())

	// Emit blockchain event
	bhi.emitEvent("transaction_processed", coreTx.ID, map[string]interface{}{
		"bridge_tx_id": bridgeTx.ID,
		"amount":       bridgeTx.Amount,
		"token":        bridgeTx.TokenSymbol,
		"from":         bridgeTx.SourceAddress,
		"to":           bridgeTx.DestAddress,
	})

	bhi.logger.Infof("✅ Bridge transaction processed successfully: %s", bridgeTx.ID)
	return nil
}

// GetTokenBalance retrieves token balance from the blockchain
func (bhi *BlackHoleBlockchainInterface) GetTokenBalance(address, tokenSymbol string) (uint64, error) {
	if bhi.blockchain == nil {
		// Return mock balance for simulation mode
		return 1000000, nil
	}

	token, exists := bhi.blockchain.TokenRegistry[tokenSymbol]
	if !exists {
		return 0, fmt.Errorf("token %s not found in registry", tokenSymbol)
	}

	balance, err := token.BalanceOf(address)
	if err != nil {
		return 0, fmt.Errorf("failed to get balance: %v", err)
	}

	return balance, nil
}

// GetTransactionStatus retrieves transaction status from blockchain
func (bhi *BlackHoleBlockchainInterface) GetTransactionStatus(txHash string) (*TransactionStatus, error) {
	if bhi.blockchain == nil {
		// Return mock status for simulation mode
		return &TransactionStatus{
			Hash:          txHash,
			Status:        "confirmed",
			BlockNumber:   uint64(time.Now().Unix() % 1000),
			Confirmations: 12,
			Timestamp:     time.Now(),
		}, nil
	}

	// Search for transaction in blockchain
	for i, block := range bhi.blockchain.Blocks {
		for _, tx := range block.Transactions {
			if tx.ID == txHash {
				return &TransactionStatus{
					Hash:          txHash,
					Status:        "confirmed",
					BlockNumber:   uint64(i),
					Confirmations: len(bhi.blockchain.Blocks) - i,
					Timestamp:     time.Unix(tx.Timestamp, 0),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("transaction not found: %s", txHash)
}

// SubscribeToEvents subscribes to blockchain events
func (bhi *BlackHoleBlockchainInterface) SubscribeToEvents() <-chan BlockchainEvent {
	bhi.mu.Lock()
	defer bhi.mu.Unlock()

	eventChan := make(chan BlockchainEvent, 50)
	bhi.subscribers = append(bhi.subscribers, eventChan)
	return eventChan
}

// GetBlockchainStats returns current blockchain statistics
func (bhi *BlackHoleBlockchainInterface) GetBlockchainStats() map[string]interface{} {
	if bhi.blockchain == nil {
		return map[string]interface{}{
			"mode":         "simulation",
			"blocks":       0,
			"transactions": 0,
			"tokens":       0,
		}
	}

	bhi.blockchain.mu.RLock()
	defer bhi.blockchain.mu.RUnlock()

	totalTxs := 0
	for _, block := range bhi.blockchain.Blocks {
		totalTxs += len(block.Transactions)
	}

	return map[string]interface{}{
		"mode":         "live",
		"blocks":       len(bhi.blockchain.Blocks),
		"transactions": totalTxs,
		"tokens":       len(bhi.blockchain.TokenRegistry),
		"total_supply": bhi.blockchain.TotalSupply,
		"validators":   bhi.blockchain.StakeLedger.GetValidatorCount(),
	}
}

// convertBridgeToCoreTx converts bridge transaction to core blockchain transaction
func (bhi *BlackHoleBlockchainInterface) convertBridgeToCoreTx(bridgeTx *Transaction) (*chain.Transaction, error) {
	// Parse amount from string to uint64
	amount, err := strconv.ParseUint(bridgeTx.Amount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %s", bridgeTx.Amount)
	}

	// Create core blockchain transaction
	coreTx := &chain.Transaction{
		ID:        bridgeTx.Hash,
		Type:      chain.TokenTransfer,
		From:      bridgeTx.SourceAddress,
		To:        bridgeTx.DestAddress,
		Amount:    amount,
		TokenID:   bridgeTx.TokenSymbol,
		Timestamp: bridgeTx.CreatedAt.Unix(),
		Nonce:     0, // Will be set by blockchain
	}

	return coreTx, nil
}

// monitorBlockchainEvents monitors blockchain for events
func (bhi *BlackHoleBlockchainInterface) monitorBlockchainEvents() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	lastBlockCount := 0

	for {
		select {
		case <-bhi.ctx.Done():
			return
		case <-ticker.C:
			if bhi.blockchain == nil {
				continue
			}

			bhi.blockchain.mu.RLock()
			currentBlockCount := len(bhi.blockchain.Blocks)
			bhi.blockchain.mu.RUnlock()

			// Check for new blocks
			if currentBlockCount > lastBlockCount {
				bhi.emitEvent("new_block", "", map[string]interface{}{
					"block_number": currentBlockCount,
					"timestamp":    time.Now(),
				})
				lastBlockCount = currentBlockCount
			}
		}
	}
}

// emitEvent emits an event to all subscribers
func (bhi *BlackHoleBlockchainInterface) emitEvent(eventType, txHash string, data map[string]interface{}) {
	event := BlockchainEvent{
		Type:        eventType,
		TxHash:      txHash,
		BlockNumber: uint64(len(bhi.blockchain.Blocks)),
		Data:        data,
		Timestamp:   time.Now(),
	}

	bhi.mu.RLock()
	defer bhi.mu.RUnlock()

	for _, subscriber := range bhi.subscribers {
		select {
		case subscriber <- event:
		default:
			// Skip if channel is full
		}
	}
}

// Close closes the blockchain interface
func (bhi *BlackHoleBlockchainInterface) Close() {
	bhi.cancel()
	close(bhi.eventChan)
}

// IsLive returns true if connected to real blockchain
func (bhi *BlackHoleBlockchainInterface) IsLive() bool {
	return bhi.blockchain != nil
}
