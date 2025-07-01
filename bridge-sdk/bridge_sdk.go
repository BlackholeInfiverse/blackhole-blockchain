package bridgesdk

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// ChainConfig represents configuration for a blockchain
type ChainConfig struct {
	ChainType    string `json:"chain_type"`
	RPC          string `json:"rpc"`
	BridgeAddr   string `json:"bridge_addr"`
	TokenAddr    string `json:"token_addr"`
	ConfirmBlock uint64 `json:"confirm_block"`
}

// BridgeSDK manages cross-chain operations
type BridgeSDK struct {
	configs map[string]*ChainConfig
	clients map[string]*ethclient.Client
	mu      sync.RWMutex
}

// NewBridgeSDK creates a new bridge SDK instance
func NewBridgeSDK() *BridgeSDK {
	return &BridgeSDK{
		configs: make(map[string]*ChainConfig),
		clients: make(map[string]*ethclient.Client),
	}
}

// AddChain adds a new chain configuration
func (sdk *BridgeSDK) AddChain(chainType string, config *ChainConfig) error {
	sdk.mu.Lock()
	defer sdk.mu.Unlock()

	// Validate config
	if config.RPC == "" {
		return fmt.Errorf("RPC URL is required")
	}
	if config.BridgeAddr == "" {
		return fmt.Errorf("bridge contract address is required")
	}
	if config.TokenAddr == "" {
		return fmt.Errorf("token contract address is required")
	}

	// Initialize client
	client, err := ethclient.Dial(config.RPC)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", chainType, err)
	}

	sdk.configs[chainType] = config
	sdk.clients[chainType] = client

	return nil
}

// BridgeParams represents parameters for a bridge transfer
type BridgeParams struct {
	SourceChain string         `json:"source_chain"`
	DestChain   string         `json:"dest_chain"`
	Token       common.Address `json:"token"`
	Amount      string         `json:"amount"`
	Recipient   common.Address `json:"recipient"`
	RelayerFee  string         `json:"relayer_fee"`
	Nonce       uint64         `json:"nonce"`
	Deadline    uint64         `json:"deadline"`
	SignatureV  uint8          `json:"signature_v"`
	SignatureR  [32]byte       `json:"signature_r"`
	SignatureS  [32]byte       `json:"signature_s"`
}

// BridgeResult represents the result of a bridge transfer
type BridgeResult struct {
	TxHash         string    `json:"tx_hash"`
	SourceChain    string    `json:"source_chain"`
	DestChain      string    `json:"dest_chain"`
	Amount         string    `json:"amount"`
	Status         string    `json:"status"`
	Timestamp      time.Time `json:"timestamp"`
	BlockNumber    uint64    `json:"block_number"`
	Confirmations  uint64    `json:"confirmations"`
	EstimatedTime  string    `json:"estimated_time"`
	RelayerAddress string    `json:"relayer_address"`
	RelayerFee     string    `json:"relayer_fee"`
	Error          string    `json:"error,omitempty"`
}

// InitiateBridgeTransfer initiates a cross-chain transfer
func (sdk *BridgeSDK) InitiateBridgeTransfer(ctx context.Context, params *BridgeParams) (*BridgeResult, error) {
	sdk.mu.RLock()
	sourceConfig, exists := sdk.configs[params.SourceChain]
	if !exists {
		sdk.mu.RUnlock()
		return nil, fmt.Errorf("source chain %s not configured", params.SourceChain)
	}
	_, exists = sdk.configs[params.DestChain]
	if !exists {
		sdk.mu.RUnlock()
		return nil, fmt.Errorf("destination chain %s not configured", params.DestChain)
	}
	sourceClient := sdk.clients[params.SourceChain]
	sdk.mu.RUnlock()

	// Validate parameters
	if err := sdk.validateBridgeParams(params); err != nil {
		return nil, err
	}

	// Get current block for confirmation tracking
	currentBlock, err := sourceClient.BlockNumber(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current block: %v", err)
	}

	// Create bridge result
	result := &BridgeResult{
		SourceChain:   params.SourceChain,
		DestChain:     params.DestChain,
		Amount:        params.Amount,
		Status:        "pending",
		Timestamp:     time.Now(),
		BlockNumber:   currentBlock,
		RelayerFee:    params.RelayerFee,
		EstimatedTime: fmt.Sprintf("%d minutes", sourceConfig.ConfirmBlock/4), // Assuming 15s block time
	}

	// Start monitoring in background
	go sdk.monitorBridgeTransfer(params, result)

	return result, nil
}

// validateBridgeParams validates bridge transfer parameters
func (sdk *BridgeSDK) validateBridgeParams(params *BridgeParams) error {
	if params.Amount == "0" {
		return fmt.Errorf("amount must be greater than 0")
	}
	if params.Deadline < uint64(time.Now().Unix()) {
		return fmt.Errorf("deadline must be in the future")
	}
	return nil
}

// monitorBridgeTransfer monitors the status of a bridge transfer
func (sdk *BridgeSDK) monitorBridgeTransfer(params *BridgeParams, result *BridgeResult) {
	ctx := context.Background()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	sourceClient := sdk.clients[params.SourceChain]
	sourceConfig := sdk.configs[params.SourceChain]

	for {
		select {
		case <-ticker.C:
			currentBlock, err := sourceClient.BlockNumber(ctx)
			if err != nil {
				continue
			}

			confirmations := currentBlock - result.BlockNumber
			result.Confirmations = confirmations

			if confirmations >= sourceConfig.ConfirmBlock {
				result.Status = "confirmed"
				return
			}
		}
	}
}

// GetBridgeStatus gets the status of a bridge transfer
func (sdk *BridgeSDK) GetBridgeStatus(txHash string) (*BridgeResult, error) {
	// Implementation would query the bridge contract on both chains
	// and return the current status
	return nil, fmt.Errorf("not implemented")
}

// GetSupportedChains returns the list of supported chains
func (sdk *BridgeSDK) GetSupportedChains() []string {
	sdk.mu.RLock()
	defer sdk.mu.RUnlock()

	chains := make([]string, 0, len(sdk.configs))
	for chain := range sdk.configs {
		chains = append(chains, chain)
	}
	return chains
}

// Close closes all client connections
func (sdk *BridgeSDK) Close() {
	sdk.mu.Lock()
	defer sdk.mu.Unlock()

	for _, client := range sdk.clients {
		client.Close()
	}
}
