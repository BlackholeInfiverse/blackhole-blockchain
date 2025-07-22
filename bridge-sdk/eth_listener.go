package bridgesdk

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// EventHandler is a function that handles blockchain events
type EventHandler func(event *types.Log)

// ChainListener listens for events on a blockchain
type ChainListener struct {
	client       *ethclient.Client
	bridgeAddr   common.Address
	handlers     map[string][]EventHandler
	subscription ethereum.Subscription
	blockDelay   uint64
	lastBlock    uint64
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewChainListener creates a new chain listener
func NewChainListener(client *ethclient.Client, bridgeAddr string, blockDelay uint64) (*ChainListener, error) {
	ctx, cancel := context.WithCancel(context.Background())

	listener := &ChainListener{
		client:     client,
		bridgeAddr: common.HexToAddress(bridgeAddr),
		handlers:   make(map[string][]EventHandler),
		blockDelay: blockDelay,
		ctx:        ctx,
		cancel:     cancel,
	}

	return listener, nil
}

// RegisterEventHandler registers a handler for a specific event
func (l *ChainListener) RegisterEventHandler(eventName string, handler EventHandler) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.handlers[eventName] == nil {
		l.handlers[eventName] = make([]EventHandler, 0)
	}
	l.handlers[eventName] = append(l.handlers[eventName], handler)
}

// Start starts listening for events
func (l *ChainListener) Start() error {
	// Get current block number
	currentBlock, err := l.client.BlockNumber(l.ctx)
	if err != nil {
		return fmt.Errorf("failed to get current block: %v", err)
	}
	l.lastBlock = currentBlock - l.blockDelay

	// Create filter query
	query := ethereum.FilterQuery{
		Addresses: []common.Address{l.bridgeAddr},
		FromBlock: big.NewInt(int64(l.lastBlock)),
	}

	// Subscribe to logs
	logs := make(chan types.Log)
	sub, err := l.client.SubscribeFilterLogs(l.ctx, query, logs)
	if err != nil {
		return fmt.Errorf("failed to subscribe to logs: %v", err)
	}
	l.subscription = sub

	// Start processing events
	go l.processEvents(logs)

	// Start block monitoring
	go l.monitorBlocks()

	return nil
}

// Stop stops listening for events
func (l *ChainListener) Stop() {
	if l.subscription != nil {
		l.subscription.Unsubscribe()
	}
	l.cancel()
}

// processEvents processes incoming events
func (l *ChainListener) processEvents(logs chan types.Log) {
	for {
		select {
		case err := <-l.subscription.Err():
			fmt.Printf("Error in event subscription: %v\n", err)
			return
		case vLog := <-logs:
			l.handleEvent(&vLog)
		case <-l.ctx.Done():
			return
		}
	}
}

// handleEvent handles a single event
func (l *ChainListener) handleEvent(vLog *types.Log) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Get event signature (first topic)
	if len(vLog.Topics) == 0 {
		return
	}
	eventSig := vLog.Topics[0].Hex()

	// Call handlers for this event
	if handlers, ok := l.handlers[eventSig]; ok {
		for _, handler := range handlers {
			go handler(vLog)
		}
	}
}

// monitorBlocks monitors new blocks
func (l *ChainListener) monitorBlocks() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			currentBlock, err := l.client.BlockNumber(l.ctx)
			if err != nil {
				fmt.Printf("Error getting current block: %v\n", err)
				continue
			}

			if currentBlock > l.lastBlock+l.blockDelay {
				l.mu.Lock()
				l.lastBlock = currentBlock - l.blockDelay
				l.mu.Unlock()

				// Update filter
				query := ethereum.FilterQuery{
					Addresses: []common.Address{l.bridgeAddr},
					FromBlock: big.NewInt(int64(l.lastBlock)),
				}

				if l.subscription != nil {
					l.subscription.Unsubscribe()
				}

				logs := make(chan types.Log)
				sub, err := l.client.SubscribeFilterLogs(l.ctx, query, logs)
				if err != nil {
					fmt.Printf("Error updating subscription: %v\n", err)
					continue
				}

				l.subscription = sub
				go l.processEvents(logs)
			}
		case <-l.ctx.Done():
			return
		}
	}
}
