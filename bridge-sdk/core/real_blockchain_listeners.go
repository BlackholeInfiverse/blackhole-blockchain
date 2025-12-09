package bridgesdk

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// RealBlockchainListener represents a listener for real blockchain events
type RealBlockchainListener struct {
	sdk             BridgeSDKInterface
	logger          *logrus.Logger
	ethClient       *ethclient.Client
	wsClients       []*websocket.Conn
	mu              sync.Mutex
	stopCh          chan struct{}
	contracts       map[string]common.Address // token contract addresses to watch
	lastBlockNumber uint64
}

// NewRealBlockchainListener creates a new real blockchain listener
func NewRealBlockchainListener(sdk BridgeSDKInterface) *RealBlockchainListener {
	return &RealBlockchainListener{
		sdk:       sdk,
		logger:    sdk.GetLogger(),
		contracts: make(map[string]common.Address),
		stopCh:    make(chan struct{}),
	}
}

// AddTokenContract adds a token contract to watch
func (rbl *RealBlockchainListener) AddTokenContract(symbol string, address common.Address) {
	rbl.mu.Lock()
	defer rbl.mu.Unlock()
	rbl.contracts[symbol] = address
}

// Start starts all blockchain listeners
func (rbl *RealBlockchainListener) Start(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	// Start Ethereum listener
	g.Go(func() error {
		return rbl.StartEthereumListener(ctx)
	})

	// Start Solana listener
	// TODO: Fix Solana API usage
	// g.Go(func() error {
	// 	return rbl.StartSolanaListener(ctx)
	// })

	return g.Wait()
}

// Stop stops all listeners
func (rbl *RealBlockchainListener) Stop() {
	close(rbl.stopCh)
	if rbl.ethClient != nil {
		rbl.ethClient.Close()
	}
	// Close all WebSocket connections
	rbl.mu.Lock()
	defer rbl.mu.Unlock()
	for _, conn := range rbl.wsClients {
		conn.Close()
	}
}

// StartEthereumListener starts the Ethereum blockchain listener with WebSocket subscription
func (rbl *RealBlockchainListener) StartEthereumListener(ctx context.Context) error {
	rbl.logger.Info("🔗 Starting real Ethereum blockchain listener...")

	// Get Ethereum WebSocket URL (replace http/https with ws/wss)
	ethRPC := rbl.sdk.GetConfig().EthereumRPC
	if ethRPC == "" {
		ethRPC = "wss://eth-mainnet.g.alchemy.com/v2/demo" // Fallback to demo WebSocket
	} else {
		ethRPC = strings.Replace(ethRPC, "http://", "ws://", 1)
		ethRPC = strings.Replace(ethRPC, "https://", "wss://", 1)
	}

	// Connect to Ethereum node with WebSocket
	client, err := ethclient.Dial(ethRPC)
	if err != nil {
		rbl.logger.Errorf("❌ Failed to connect to Ethereum WebSocket: %v", err)
		return fmt.Errorf("failed to connect to Ethereum WebSocket: %v", err)
	}
	rbl.ethClient = client

	rbl.logger.Infof("✅ Connected to Ethereum WebSocket: %s", ethRPC)

	// Get current block number to start from
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %v", err)
	}
	rbl.lastBlockNumber = header.Number.Uint64()

	// Start block subscription
	headers := make(chan *types.Header)
	sub, err := client.SubscribeNewHead(ctx, headers)
	if err != nil {
		return fmt.Errorf("failed to subscribe to new headers: %v", err)
	}

	// Start processing blocks
	go func() {
		defer sub.Unsubscribe()

		for {
			select {
			case err := <-sub.Err():
				rbl.logger.Errorf("❌ Ethereum subscription error: %v", err)
				// Attempt to resubscribe
				time.Sleep(5 * time.Second)
				if err := rbl.StartEthereumListener(ctx); err != nil {
					rbl.logger.Errorf("❌ Failed to resubscribe to Ethereum: %v", err)
				}
				return

			case header := <-headers:
				blockNum := header.Number.Uint64()
				if blockNum > rbl.lastBlockNumber+1 {
					// We missed some blocks, process them all
					for i := rbl.lastBlockNumber + 1; i < blockNum; i++ {
						rbl.processEthereumBlock(ctx, client, i)
					}
				}
				rbl.processEthereumBlock(ctx, client, blockNum)
				rbl.lastBlockNumber = blockNum

			case <-rbl.stopCh:
				rbl.logger.Info("🛑 Ethereum listener stopped by request")
				return

			case <-ctx.Done():
				rbl.logger.Info("🛑 Ethereum listener context cancelled")
				return
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

// StartSolanaListener starts the Solana blockchain listener with WebSocket subscription
// TODO: Implement Solana listener with correct API usage
func (rbl *RealBlockchainListener) StartSolanaListener(ctx context.Context) error {
	rbl.logger.Info("🔗 Solana listener not implemented yet")
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
