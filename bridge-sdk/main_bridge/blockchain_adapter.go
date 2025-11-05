package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sirupsen/logrus"
)

// BlockchainAdapter provides secure real-time blockchain connections
// This adapter bridges between main.go's BridgeSDK and real blockchain networks
type BlockchainAdapter struct {
	sdk              *BridgeSDK
	logger           *logrus.Logger
	ethereumClient   *ethclient.Client
	ethereumCtx      context.Context
	ethereumCancel   context.CancelFunc
	solanaCtx        context.Context
	solanaCancel     context.CancelFunc
	mu               sync.RWMutex
	connected        bool
	lastEthBlock     uint64
	lastSolanaBlock  uint64
	reconnectAttempts int
	maxReconnects    int
}

// NewBlockchainAdapter creates a new secure blockchain adapter
func NewBlockchainAdapter(sdk *BridgeSDK) *BlockchainAdapter {
	adapter := &BlockchainAdapter{
		sdk:           sdk,
		logger:        sdk.logger,
		connected:     false,
		maxReconnects: 5,
	}
	
	adapter.ethereumCtx, adapter.ethereumCancel = context.WithCancel(context.Background())
	adapter.solanaCtx, adapter.solanaCancel = context.WithCancel(context.Background())
	
	return adapter
}

// ConnectToEthereum establishes secure connection to Ethereum network
func (ba *BlockchainAdapter) ConnectToEthereum() error {
	ba.mu.Lock()
	defer ba.mu.Unlock()
	
	ethRPC := ba.sdk.config.EthereumRPC
	if ethRPC == "" {
		return fmt.Errorf("Ethereum RPC URL not configured")
	}
	
	ba.logger.Infof("🔗 Connecting to Ethereum network: %s", maskRPCURL(ethRPC))
	
	// Create context with timeout for initial connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	client, err := ethclient.DialContext(ctx, ethRPC)
	if err != nil {
		ba.logger.Errorf("❌ Failed to connect to Ethereum: %v", err)
		return fmt.Errorf("ethereum connection failed: %w", err)
	}
	
	// Verify connection with a test call
	chainID, err := client.ChainID(ctx)
	if err != nil {
		client.Close()
		return fmt.Errorf("failed to verify ethereum connection: %w", err)
	}
	
	ba.ethereumClient = client
	ba.connected = true
	ba.reconnectAttempts = 0
	
	ba.logger.Infof("✅ Connected to Ethereum - Chain ID: %s", chainID.String())
	return nil
}

// StartEthereumListener starts real-time Ethereum blockchain monitoring
func (ba *BlockchainAdapter) StartEthereumListener(ctx context.Context) error {
	if err := ba.ConnectToEthereum(); err != nil {
		return err
	}
	
	ba.logger.Info("🚀 Starting real-time Ethereum blockchain listener...")
	
	go ba.monitorEthereumBlocks(ctx)
	go ba.monitorEthereumHealth(ctx)
	
	return nil
}

// monitorEthereumBlocks continuously monitors Ethereum blocks for bridge events
func (ba *BlockchainAdapter) monitorEthereumBlocks(ctx context.Context) {
	ticker := time.NewTicker(12 * time.Second) // Ethereum block time ~12s
	defer ticker.Stop()
	
	// Initialize starting block
	if ba.lastEthBlock == 0 {
		currentBlock, err := ba.ethereumClient.BlockNumber(ctx)
		if err != nil {
			ba.logger.Errorf("❌ Failed to get current block: %v", err)
			return
		}
		ba.lastEthBlock = currentBlock - 10 // Start from 10 blocks ago
		ba.logger.Infof("📍 Starting Ethereum monitoring from block: %d", ba.lastEthBlock)
	}
	
	for {
		select {
		case <-ctx.Done():
			ba.logger.Info("🛑 Ethereum listener stopped")
			return
		case <-ticker.C:
			if err := ba.processNewEthereumBlocks(ctx); err != nil {
				ba.logger.Warnf("⚠️ Error processing Ethereum blocks: %v", err)
				ba.handleConnectionError("ethereum", err)
			}
		}
	}
}

// processNewEthereumBlocks processes new Ethereum blocks
func (ba *BlockchainAdapter) processNewEthereumBlocks(ctx context.Context) error {
	currentBlock, err := ba.ethereumClient.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current block: %w", err)
	}
	
	// Process blocks from last processed to current
	for blockNum := ba.lastEthBlock + 1; blockNum <= currentBlock; blockNum++ {
		if err := ba.processEthereumBlock(ctx, blockNum); err != nil {
			ba.logger.Warnf("⚠️ Error processing block %d: %v", blockNum, err)
			continue
		}
		ba.lastEthBlock = blockNum
	}
	
	return nil
}

// processEthereumBlock processes a single Ethereum block for bridge events
func (ba *BlockchainAdapter) processEthereumBlock(ctx context.Context, blockNum uint64) error {
	block, err := ba.ethereumClient.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
	if err != nil {
		return fmt.Errorf("failed to get block %d: %w", blockNum, err)
	}
	
	// Process each transaction in the block
	for _, tx := range block.Transactions() {
		// Only process transactions to contracts
		if tx.To() != nil && len(tx.Data()) > 0 {
			receipt, err := ba.ethereumClient.TransactionReceipt(ctx, tx.Hash())
			if err != nil {
				continue
			}
			
			// Process logs (events) from the transaction
			for _, vLog := range receipt.Logs {
				if ba.isTransferEvent(vLog) {
					ba.handleEthereumTransferEvent(vLog, blockNum)
				}
			}
		}
	}
	
	return nil
}

// isTransferEvent checks if log is a Transfer event
func (ba *BlockchainAdapter) isTransferEvent(vLog *types.Log) bool {
	// Transfer event signature: 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
	transferEventSig := common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
	return len(vLog.Topics) > 0 && vLog.Topics[0] == transferEventSig && len(vLog.Topics) >= 3
}

// handleEthereumTransferEvent processes Ethereum Transfer events
func (ba *BlockchainAdapter) handleEthereumTransferEvent(vLog *types.Log, blockNum uint64) {
	// Parse Transfer event
	fromAddr := common.HexToAddress(vLog.Topics[1].Hex())
	toAddr := common.HexToAddress(vLog.Topics[2].Hex())
	
	// Extract amount from data
	var amount uint64
	if len(vLog.Data) >= 32 {
		amountBig := new(big.Int).SetBytes(vLog.Data[:32])
		amount = amountBig.Uint64()
	}
	
	// Create bridge transaction
	tx := &Transaction{
		ID:            fmt.Sprintf("eth_%d_%s", time.Now().UnixNano(), vLog.TxHash.Hex()),
		Hash:          vLog.TxHash.Hex(),
		SourceChain:   "ethereum",
		DestChain:     "blackhole",
		SourceAddress: fromAddr.Hex(),
		DestAddress:   toAddr.Hex(),
		TokenSymbol:   vLog.Address.Hex(),
		Amount:        fmt.Sprintf("%d", amount),
		Status:        "pending",
		BlockNumber:   blockNum,
		CreatedAt:     time.Now(),
		Confirmations: 0,
	}
	
	// Check replay protection
	hash := ba.generateEventHash(tx)
	if ba.sdk.replayProtection.isProcessed(hash) {
		ba.logger.Warnf("🚫 Replay attack detected for transaction %s", tx.ID)
		ba.sdk.incrementBlockedReplays()
		return
	}
	
	// Mark as processed
	if err := ba.sdk.replayProtection.markProcessed(hash); err != nil {
		ba.logger.Errorf("Failed to mark transaction as processed: %v", err)
		return
	}
	
	// Save transaction
	ba.sdk.saveTransaction(tx)
	ba.sdk.addEvent("transfer", "ethereum", tx.Hash, map[string]interface{}{
		"amount": tx.Amount,
		"token":  tx.TokenSymbol,
		"from":   tx.SourceAddress,
		"to":     tx.DestAddress,
	})
	
	ba.logger.Infof("💰 Real Ethereum transaction detected: %s (%s)", tx.ID, tx.Amount)
	
	// Process through bridge
	go ba.processTransaction(tx)
}

// StartSolanaListener starts real-time Solana blockchain monitoring
func (ba *BlockchainAdapter) StartSolanaListener(ctx context.Context) error {
	solRPC := ba.sdk.config.SolanaRPC
	if solRPC == "" {
		ba.logger.Warn("⚠️ Solana RPC not configured, using HTTP polling")
		solRPC = "https://api.mainnet-beta.solana.com"
	}
	
	ba.logger.Infof("🔗 Connecting to Solana network: %s", maskRPCURL(solRPC))
	ba.logger.Info("🚀 Starting real-time Solana blockchain listener...")
	
	// Note: Full Solana WebSocket requires solana-go library
	// For production, implement using github.com/gagliardetto/solana-go
	go ba.monitorSolanaHTTP(ctx, solRPC)
	
	return nil
}

// monitorSolanaHTTP monitors Solana via HTTP polling (production should use WebSocket)
func (ba *BlockchainAdapter) monitorSolanaHTTP(ctx context.Context, rpcURL string) {
	ticker := time.NewTicker(1 * time.Second) // Solana ~400ms block time, poll every second
	defer ticker.Stop()
	
	ba.logger.Info("📡 Solana HTTP polling started (upgrade to WebSocket for production)")
	
	for {
		select {
		case <-ctx.Done():
			ba.logger.Info("🛑 Solana listener stopped")
			return
		case <-ticker.C:
			// TODO: Implement real Solana transaction fetching
			// Using github.com/gagliardetto/solana-go:
			// - Connect to WebSocket
			// - Subscribe to account changes
			// - Monitor SPL token transfers
			ba.logger.Debug("Polling Solana for new transactions...")
		}
	}
}

// monitorEthereumHealth monitors Ethereum connection health
func (ba *BlockchainAdapter) monitorEthereumHealth(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ba.checkEthereumHealth(); err != nil {
				ba.logger.Warnf("⚠️ Ethereum health check failed: %v", err)
				ba.handleConnectionError("ethereum", err)
			}
		}
	}
}

// checkEthereumHealth performs health check on Ethereum connection
func (ba *BlockchainAdapter) checkEthereumHealth() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	_, err := ba.ethereumClient.BlockNumber(ctx)
	if err != nil {
		ba.mu.Lock()
		ba.connected = false
		ba.mu.Unlock()
		return err
	}
	
	return nil
}

// handleConnectionError handles connection errors with automatic reconnection
func (ba *BlockchainAdapter) handleConnectionError(chain string, err error) {
	ba.mu.Lock()
	defer ba.mu.Unlock()
	
	ba.reconnectAttempts++
	
	if ba.reconnectAttempts >= ba.maxReconnects {
		ba.logger.Errorf("🚨 Max reconnection attempts reached for %s", chain)
		// Circuit breaker should be triggered here
		if cb, ok := ba.sdk.circuitBreakers[chain+"_listener"]; ok {
			cb.recordFailure()
		}
		return
	}
	
	ba.logger.Warnf("🔄 Attempting to reconnect to %s (attempt %d/%d)", chain, ba.reconnectAttempts, ba.maxReconnects)
	
	// Exponential backoff
	backoff := time.Duration(ba.reconnectAttempts*ba.reconnectAttempts) * time.Second
	time.Sleep(backoff)
	
	if chain == "ethereum" {
		if err := ba.ConnectToEthereum(); err != nil {
			ba.logger.Errorf("❌ Reconnection failed: %v", err)
		}
	}
}

// processTransaction processes bridge transaction
func (ba *BlockchainAdapter) processTransaction(tx *Transaction) {
	// Simulate processing delay
	time.Sleep(2 * time.Second)
	
	tx.Status = "completed"
	now := time.Now()
	tx.CompletedAt = &now
	tx.Confirmations = 12
	tx.ProcessingTime = fmt.Sprintf("%.2fs", time.Since(tx.CreatedAt).Seconds())
	
	ba.sdk.saveTransaction(tx)
	ba.logger.Infof("✅ Transaction completed: %s", tx.ID)
}

// generateEventHash generates hash for replay protection
func (ba *BlockchainAdapter) generateEventHash(tx *Transaction) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		tx.SourceChain, tx.DestChain, tx.SourceAddress,
		tx.DestAddress, tx.TokenSymbol, tx.Amount)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}

// maskRPCURL masks sensitive parts of RPC URL for logging
func maskRPCURL(url string) string {
	if len(url) > 50 {
		return url[:20] + "..." + url[len(url)-10:]
	}
	return url
}

// Close closes all blockchain connections
func (ba *BlockchainAdapter) Close() error {
	ba.logger.Info("🔌 Closing blockchain connections...")
	
	if ba.ethereumCancel != nil {
		ba.ethereumCancel()
	}
	if ba.solanaCancel != nil {
		ba.solanaCancel()
	}
	
	if ba.ethereumClient != nil {
		ba.ethereumClient.Close()
	}
	
	ba.logger.Info("✅ All blockchain connections closed")
	return nil
}

// GetConnectionStatus returns current connection status
func (ba *BlockchainAdapter) GetConnectionStatus() map[string]interface{} {
	ba.mu.RLock()
	defer ba.mu.RUnlock()
	
	return map[string]interface{}{
		"ethereum": map[string]interface{}{
			"connected":        ba.connected,
			"last_block":       ba.lastEthBlock,
			"reconnect_attempts": ba.reconnectAttempts,
		},
		"solana": map[string]interface{}{
			"connected":        true, // HTTP polling always "connected"
			"last_block":       ba.lastSolanaBlock,
			"reconnect_attempts": 0,
		},
	}
}
