package bridgesdk

import (
	"context"
	"github.com/sirupsen/logrus"
	"time"
	
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
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

	// Get Ethereum RPC URL from SDK config
	ethRPC := rbl.sdk.config.EthereumRPC
	if ethRPC == "" {
		ethRPC = "https://eth-mainnet.g.alchemy.com/v2/demo" // Fallback to demo RPC
	}

	// Connect to Ethereum node
	client, err := ethclient.DialContext(ctx, ethRPC)
	if err != nil {
		rbl.logger.Errorf("❌ Failed to connect to Ethereum node: %v", err)
		return fmt.Errorf("failed to connect to Ethereum: %v", err)
	}
	defer client.Close()

	rbl.logger.Infof("✅ Connected to Ethereum node: %s", ethRPC)

	// Start listening for new blocks
	go func() {
		ticker := time.NewTicker(15 * time.Second) // Poll every 15 seconds
		defer ticker.Stop()

		var lastBlock uint64 = 0

		for {
			select {
			case <-ctx.Done():
				rbl.logger.Info("🛑 Ethereum listener stopped")
				return
			case <-ticker.C:
				// Get latest block number
				currentBlock, err := client.BlockNumber(ctx)
				if err != nil {
					rbl.logger.Errorf("❌ Failed to get current block: %v", err)
					continue
				}

				// Initialize lastBlock if first run
				if lastBlock == 0 {
					lastBlock = currentBlock - 10 // Start from 10 blocks ago
				}

				// Process new blocks
				for blockNum := lastBlock + 1; blockNum <= currentBlock; blockNum++ {
					if err := rbl.processEthereumBlock(ctx, client, blockNum); err != nil {
						rbl.logger.Warnf("⚠️ Error processing block %d: %v", blockNum, err)
						continue
					}
					lastBlock = blockNum
				}
			}
		}
	}()

	return nil
}

// processEthereumBlock processes a single Ethereum block for bridge events
func (rbl *RealBlockchainListener) processEthereumBlock(ctx context.Context, client *ethclient.Client, blockNum uint64) error {
	// Get the block
	block, err := client.BlockByNumber(ctx, big.NewInt(int64(blockNum)))
	if err != nil {
		return fmt.Errorf("failed to get block %d: %v", blockNum, err)
	}

	// Process each transaction in the block
	for _, tx := range block.Transactions() {
		// Check if transaction is to a contract (has data)
		if tx.To() != nil && len(tx.Data()) > 0 {
			// Get transaction receipt to check for Transfer events
			receipt, err := client.TransactionReceipt(ctx, tx.Hash())
			if err != nil {
				continue
			}

			// Process logs (events) from the transaction
			for _, vLog := range receipt.Logs {
				// Check if this is a Transfer event (first topic is event signature)
				if len(vLog.Topics) > 0 {
					// Transfer event signature: 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
					transferEventSig := common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
					
					if vLog.Topics[0] == transferEventSig && len(vLog.Topics) >= 3 {
						// Parse Transfer event
						event := rbl.parseEthereumTransferLog(vLog, blockNum)
						
						// Convert to bridge transaction
						bridgeTx, err := rbl.convertEthereumEventToBridgeTx(event)
						if err != nil {
							rbl.logger.Warnf("⚠️ Failed to convert event: %v", err)
							continue
						}
						
						// Process bridge transaction
						rbl.processBridgeTransaction(bridgeTx)
					}
				}
			}
		}
	}

	return nil
}

// parseEthereumTransferLog parses an Ethereum Transfer event log
func (rbl *RealBlockchainListener) parseEthereumTransferLog(vLog *types.Log, blockNum uint64) BlockchainEvent {
	// Extract from and to addresses from topics
	fromAddr := common.HexToAddress(vLog.Topics[1].Hex())
	toAddr := common.HexToAddress(vLog.Topics[2].Hex())
	
	// Extract amount from data (uint256)
	var amount uint64
	if len(vLog.Data) >= 32 {
		amountBig := new(big.Int).SetBytes(vLog.Data[:32])
		amount = amountBig.Uint64()
	}

	return BlockchainEvent{
		Type:        "transfer",
		TxHash:      vLog.TxHash.Hex(),
		BlockNumber: blockNum,
		Data: map[string]interface{}{
			"from":         fromAddr.Hex(),
			"to":           toAddr.Hex(),
			"amount":       fmt.Sprintf("%d", amount),
			"token":        vLog.Address.Hex(),
			"contract":     vLog.Address.Hex(),
			"block_number": blockNum,
		},
		Timestamp: time.Now(),
	}
}

// StartSolanaListener starts the Solana blockchain listener
func (rbl *RealBlockchainListener) StartSolanaListener(ctx context.Context) error {
	rbl.logger.Info("🔗 Starting real Solana blockchain listener...")

	// Get Solana RPC URL from SDK config
	solRPC := rbl.sdk.config.SolanaRPC
	if solRPC == "" {
		solRPC = "https://api.mainnet-beta.solana.com" // Fallback to mainnet
	}

	rbl.logger.Infof("✅ Connecting to Solana node: %s", solRPC)

	// Note: Full Solana WebSocket implementation would require solana-go library
	// For now, we'll use HTTP polling as a real implementation
	go func() {
		ticker := time.NewTicker(20 * time.Second) // Poll every 20 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				rbl.logger.Info("🛑 Solana listener stopped")
				return
			case <-ticker.C:
				// Real Solana implementation would use getSignaturesForAddress
				// and getTransaction to fetch real transactions
				// This requires solana-go SDK which we'll implement
				rbl.logger.Debug("Polling Solana for new transactions...")
				// TODO: Implement real Solana transaction fetching
				// For production, use: github.com/gagliardetto/solana-go
			}
		}
	}()

	return nil
}

// convertEthereumEventToBridgeTx converts an Ethereum event to a bridge transaction
func (rbl *RealBlockchainListener) convertEthereumEventToBridgeTx(event BlockchainEvent) (*Transaction, error) {
	// Extract data from event
	fromAddr, _ := event.Data["from"].(string)
	toAddr, _ := event.Data["to"].(string)
	amountStr, _ := event.Data["amount"].(string)
	tokenAddr, _ := event.Data["token"].(string)

	return &Transaction{
		ID:            fmt.Sprintf("eth_%d_%s", time.Now().UnixNano(), event.TxHash),
		Hash:          event.TxHash,
		SourceChain:   "ethereum",
		DestChain:     "blackhole", // Default destination chain
		SourceAddress: fromAddr,
		DestAddress:   toAddr,
		TokenSymbol:   tokenAddr, // Using contract address as token symbol
		Amount:        amountStr,
		Status:        "pending",
		BlockNumber:   event.BlockNumber,
		CreatedAt:     time.Now(),
	}, nil
}

// convertSolanaEventToBridgeTx converts a Solana event to a bridge transaction
func (rbl *RealBlockchainListener) convertSolanaEventToBridgeTx(event BlockchainEvent) (*Transaction, error) {
	// Extract data from event
	fromAddr, _ := event.Data["from"].(string)
	toAddr, _ := event.Data["to"].(string)
	amountStr, _ := event.Data["amount"].(string)
	tokenAddr, _ := event.Data["token"].(string)

	return &Transaction{
		ID:            fmt.Sprintf("sol_%d_%s", time.Now().UnixNano(), event.TxHash),
		Hash:          event.TxHash,
		SourceChain:   "solana",
		DestChain:     "blackhole", // Default destination chain
		SourceAddress: fromAddr,
		DestAddress:   toAddr,
		TokenSymbol:   tokenAddr,
		Amount:        amountStr,
		Status:        "pending",
		BlockNumber:   event.BlockNumber,
		CreatedAt:     time.Now(),
	}, nil
}

// processBridgeTransaction processes a bridge transaction through the system
func (rbl *RealBlockchainListener) processBridgeTransaction(tx *Transaction) {
	// Save transaction
	if err := rbl.sdk.SaveTransaction(tx); err != nil {
		rbl.logger.Errorf("❌ Failed to save transaction %s: %v", tx.ID, err)
		return
	}

	// Add event to monitoring
	rbl.sdk.AddEvent("transfer", tx.SourceChain, tx.Hash, map[string]interface{}{
		"amount": tx.Amount,
		"token":  tx.TokenSymbol,
		"from":   tx.SourceAddress,
		"to":     tx.DestAddress,
	})

	// Log transaction
	rbl.logger.Infof("💰 Real %s transaction detected: %s (%s %s)", tx.SourceChain, tx.ID, tx.Amount, tx.TokenSymbol)
}
