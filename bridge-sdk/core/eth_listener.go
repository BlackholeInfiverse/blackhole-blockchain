package bridgesdk

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// EthereumListener handles Ethereum blockchain events
type EthereumListener struct {
	client       *ethclient.Client
	bridgeAddr   common.Address
	tokenAddr    common.Address
	eventHandler EventHandler
	logger       interface{} // Will be *logrus.Logger
	running      bool
	stopChan     chan bool
}

// NewEthereumListener creates a new Ethereum listener
func NewEthereumListener(rpcURL string, bridgeAddr, tokenAddr string, eventHandler EventHandler) (*EthereumListener, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum: %v", err)
	}

	return &EthereumListener{
		client:       client,
		bridgeAddr:   common.HexToAddress(bridgeAddr),
		tokenAddr:    common.HexToAddress(tokenAddr),
		eventHandler: eventHandler,
		stopChan:     make(chan bool),
	}, nil
}

// Start starts the Ethereum listener
func (el *EthereumListener) Start() error {
	if el.running {
		return fmt.Errorf("listener is already running")
	}

	el.running = true
	go el.listenForEvents()
	
	log.Printf("🔗 Ethereum listener started, monitoring bridge: %s", el.bridgeAddr.Hex())
	return nil
}

// Stop stops the Ethereum listener
func (el *EthereumListener) Stop() error {
	if !el.running {
		return nil
	}

	el.running = false
	el.stopChan <- true
	
	log.Printf("🛑 Ethereum listener stopped")
	return nil
}

// listenForEvents listens for bridge events on Ethereum
func (el *EthereumListener) listenForEvents() {
	ticker := time.NewTicker(15 * time.Second) // Check every 15 seconds
	defer ticker.Stop()

	var lastBlock uint64 = 0

	for {
		select {
		case <-el.stopChan:
			return
		case <-ticker.C:
			if err := el.processNewBlocks(&lastBlock); err != nil {
				log.Printf("❌ Error processing Ethereum blocks: %v", err)
			}
		}
	}
}

// processNewBlocks processes new blocks for bridge events
func (el *EthereumListener) processNewBlocks(lastBlock *uint64) error {
	ctx := context.Background()
	
	// Get current block number
	currentBlock, err := el.client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current block: %v", err)
	}

	// If this is the first run, start from recent blocks
	if *lastBlock == 0 {
		*lastBlock = currentBlock - 10 // Start from 10 blocks ago
	}

	// Process blocks from lastBlock to currentBlock
	for blockNum := *lastBlock + 1; blockNum <= currentBlock; blockNum++ {
		if err := el.processBlock(ctx, blockNum); err != nil {
			log.Printf("⚠️ Error processing block %d: %v", blockNum, err)
			continue
		}
		*lastBlock = blockNum
	}

	return nil
}

// processBlock processes a single block for bridge events
func (el *EthereumListener) processBlock(ctx context.Context, blockNum uint64) error {
	// Create filter query for bridge contract events
	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(int64(blockNum)),
		ToBlock:   big.NewInt(int64(blockNum)),
		Addresses: []common.Address{el.bridgeAddr},
	}

	// Get logs
	logs, err := el.client.FilterLogs(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to filter logs: %v", err)
	}

	// Process each log
	for _, vLog := range logs {
		if err := el.processLog(vLog); err != nil {
			log.Printf("⚠️ Error processing log: %v", err)
		}
	}

	return nil
}

// processLog processes a single log entry
func (el *EthereumListener) processLog(vLog types.Log) error {
	// Create event from log
	event := Event{
		ID:          fmt.Sprintf("eth_%s_%d", vLog.TxHash.Hex(), vLog.Index),
		Type:        "bridge_deposit",
		Chain:       "ethereum",
		TxHash:      vLog.TxHash.Hex(),
		Timestamp:   time.Now(),
		BlockNumber: vLog.BlockNumber,
		Data: map[string]interface{}{
			"address":     vLog.Address.Hex(),
			"topics":      vLog.Topics,
			"data":        vLog.Data,
			"block_hash":  vLog.BlockHash.Hex(),
			"tx_index":    vLog.TxIndex,
			"log_index":   vLog.Index,
		},
		Processed: false,
	}

	// Handle the event
	if err := el.eventHandler.HandleEvent(event); err != nil {
		return fmt.Errorf("failed to handle event: %v", err)
	}

	log.Printf("✅ Processed Ethereum event: %s (block: %d)", event.ID, vLog.BlockNumber)
	return nil
}

// GetLatestBlock returns the latest block number
func (el *EthereumListener) GetLatestBlock() (uint64, error) {
	ctx := context.Background()
	return el.client.BlockNumber(ctx)
}

// GetTransactionReceipt gets a transaction receipt
func (el *EthereumListener) GetTransactionReceipt(txHash string) (*types.Receipt, error) {
	ctx := context.Background()
	hash := common.HexToHash(txHash)
	return el.client.TransactionReceipt(ctx, hash)
}

// IsConnected checks if the client is connected
func (el *EthereumListener) IsConnected() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	_, err := el.client.BlockNumber(ctx)
	return err == nil
}
