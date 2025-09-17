package bridgesdk

import (
	"context"
	"github.com/sirupsen/logrus"
	"time"
	
	"fmt"
	"strconv"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk"
)

// RealBlockchainListener represents a listener for real blockchain events
type RealBlockchainListener struct {
	sdk    *BridgeSDK
	logger *logrus.Logger
}

// NewRealBlockchainListener creates a new real blockchain listener
func NewRealBlockchainListener(sdk *BridgeSDK) *RealBlockchainListener {
	return &RealBlockchainListener{
		sdk:    sdk,
		logger: sdk.logger,
	}
}

// StartEthereumListener starts the Ethereum blockchain listener
func (rbl *RealBlockchainListener) StartEthereumListener(ctx context.Context) error {
	rbl.logger.Info("🔗 Starting real Ethereum blockchain listener...")

	// Connect to Ethereum node
	ethereumNode, err := chain.ConnectToEthereumNode(rbl.sdk.blockchainInterface.config)
	if err != nil {
		rbl.logger.Errorf("❌ Failed to connect to Ethereum node: %v", err)
		return err
	}

	// Subscribe to Ethereum events
	subscription, err := ethereumNode.SubscribeToEvents(ctx, "transfer")
	if err != nil {
		rbl.logger.Errorf("❌ Failed to subscribe to Ethereum events: %v", err)
		return err
	}

	// Process events
	go func() {
		for {
			select {
			case <-ctx.Done():
				rbl.logger.Info("🛑 Ethereum listener stopped")
				return
			case event := <-subscription.Events:
				// Convert Ethereum event to bridge transaction
				tx, err := rbl.convertEthereumEventToBridgeTx(event)
				if err != nil {
					rbl.logger.Errorf("❌ Failed to convert Ethereum event: %v", err)
					continue
				}

				// Process bridge transaction
				rbl.processBridgeTransaction(tx)
			}
		}
	return nil
}

// StartSolanaListener starts the Solana blockchain listener
func (rbl *RealBlockchainListener) StartSolanaListener(ctx context.Context) error {
	rbl.logger.Info("🔗 Starting real Solana blockchain listener...")

	// Connect to Solana node
	solanaNode, err := chain.ConnectToSolanaNode(rbl.sdk.blockchainInterface.config)
	if err != nil {
		rbl.logger.Errorf("❌ Failed to connect to Solana node: %v", err)
		return err
	}

	// Subscribe to Solana events
	subscription, err := solanaNode.SubscribeToEvents(ctx, "transfer")
	if err != nil {
		rbl.logger.Errorf("❌ Failed to subscribe to Solana events: %v", err)
		return err
	}

	// Process events
	go func() {
		for {
			select {
			case <-ctx.Done():
				rbl.logger.Info("🛑 Solana listener stopped")
				return
			case event := <-subscription.Events:
				// Convert Solana event to bridge transaction
				tx, err := rbl.convertSolanaEventToBridgeTx(event)
				if err != nil {
					rbl.logger.Errorf("❌ Failed to convert Solana event: %v", err)
					continue
				}

				// Process bridge transaction
				rbl.processBridgeTransaction(tx)
			}
		}
	}() // ✅ properly closed the goroutine

	return nil
}

// convertEthereumEventToBridgeTx converts an Ethereum event to a bridge transaction
func (rbl *RealBlockchainListener) convertEthereumEventToBridgeTx(event chain.BlockchainEvent) (*Transaction, error) {
	// Implementation details for Ethereum event conversion
	return &Transaction{
		ID:            fmt.Sprintf("eth_%d", time.Now().Unix()),
		Hash:          event.Hash,
		SourceChain:   "ethereum",
		DestChain:     "blackhole", // Default destination chain
		SourceAddress: event.From,
		DestAddress:   event.To,
		TokenSymbol:   event.Token,
		Amount:        strconv.FormatUint(event.Amount, 10),
		Status:        "pending",
		CreatedAt:     time.Now(),
	}, nil
}

// convertSolanaEventToBridgeTx converts a Solana event to a bridge transaction
func (rbl *RealBlockchainListener) convertSolanaEventToBridgeTx(event chain.BlockchainEvent) (*Transaction, error) {
	// Implementation details for Solana event conversion
	// This would parse the specific Solana event format
	// and create a corresponding bridge transaction
	return &Transaction{
		ID:            fmt.Sprintf("sol_%d", time.Now().Unix()),
		Hash:          event.Hash,
		SourceChain:   "solana",
		DestChain:     "blackhole", // Default destination chain
		SourceAddress: event.From,
		DestAddress:   event.To,
		TokenSymbol:   event.Token,
		Amount:        strconv.FormatUint(event.Amount, 10),
		Status:        "pending",
		CreatedAt:     time.Now(),
	}, nil
}

// processBridgeTransaction processes a bridge transaction through the system
func (rbl *RealBlockchainListener) processBridgeTransaction(tx *Transaction) {
	// Add to retry queue in case of failure
	addedID := rbl.sdk.addToRetryQueue("real_blockchain_event", map[string]interface{}{
		"transaction_id": tx.ID,
		"amount":         tx.Amount,
		"token":          tx.TokenSymbol,
		"from":           tx.SourceAddress,
		"to":             tx.DestAddress,
		"hash":           tx.Hash,
	}, nil)

	// Check if added to retry queue
	if addedID == "" {
		rbl.logger.Warnf("⚠️ Failed to add transaction %s to retry queue", tx.ID)
		return
	}

	// Process transaction through bridge
	if err := rbl.sdk.blockchainInterface.ProcessBridgeTransaction(tx); err != nil {
		rbl.logger.Errorf("❌ Failed to process bridge transaction %s: %v", tx.ID, err)
		return
	}

	// Transaction processed successfully, remove from retry queue
	if err := rbl.sdk.removeFromRetryQueue(addedID); err != nil {
		rbl.logger.Warnf("❌ Failed to remove transaction %s from retry queue: %v", tx.ID, err)
	}

	// Add event to monitoring
	rbl.sdk.addEvent("transfer", tx.SourceChain, tx.Hash, map[string]interface{}{
		"amount": tx.Amount,
		"token":  tx.TokenSymbol,
		"from":   tx.SourceAddress,
		"to":     tx.DestAddress,
	})

	// Log transaction
	rbl.logger.Infof("💰 Real %s transaction detected: %s (%s %s)", tx.SourceChain, tx.ID, tx.Amount, tx.TokenSymbol)
}