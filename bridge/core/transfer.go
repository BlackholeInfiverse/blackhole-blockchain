package core

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// TokenStandard represents different token standards across chains
type TokenStandard string

const (
	TokenStandardERC20   TokenStandard = "ERC20"
	TokenStandardSPL     TokenStandard = "SPL"
	TokenStandardNative  TokenStandard = "NATIVE"
	TokenStandardBHX     TokenStandard = "BHX"
)

// ChainType represents supported blockchain networks
type ChainType string

const (
	ChainTypeEthereum  ChainType = "ethereum"
	ChainTypeSolana    ChainType = "solana"
	ChainTypeBlackHole ChainType = "blackhole"
)

// TransferState represents the current state of a cross-chain transfer
type TransferState string

const (
	TransferStatePending    TransferState = "pending"
	TransferStateConfirmed  TransferState = "confirmed"
	TransferStateCompleted  TransferState = "completed"
	TransferStateFailed     TransferState = "failed"
	TransferStateRolledBack TransferState = "rolled_back"
	TransferStateExpired    TransferState = "expired"
)

// TokenInfo represents token metadata for cross-chain transfers
type TokenInfo struct {
	Symbol       string        `json:"symbol"`
	Name         string        `json:"name"`
	Decimals     uint8         `json:"decimals"`
	Standard     TokenStandard `json:"standard"`
	ContractAddr string        `json:"contract_address,omitempty"`
	ChainID      string        `json:"chain_id"`
	IsNative     bool          `json:"is_native"`
}

// TransferRequest represents a cross-chain token transfer request
type TransferRequest struct {
	ID              string     `json:"id"`
	FromChain       ChainType  `json:"from_chain"`
	ToChain         ChainType  `json:"to_chain"`
	FromAddress     string     `json:"from_address"`
	ToAddress       string     `json:"to_address"`
	Token           TokenInfo  `json:"token"`
	Amount          *big.Int   `json:"amount"`
	Fee             *big.Int   `json:"fee,omitempty"`
	Nonce           uint64     `json:"nonce"`
	Deadline        time.Time  `json:"deadline"`
	Signature       string     `json:"signature,omitempty"`
	Metadata        string     `json:"metadata,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// TransferResponse represents the response to a transfer request
type TransferResponse struct {
	RequestID       string        `json:"request_id"`
	State           TransferState `json:"state"`
	SourceTxHash    string        `json:"source_tx_hash,omitempty"`
	DestTxHash      string        `json:"dest_tx_hash,omitempty"`
	BridgeTxHash    string        `json:"bridge_tx_hash,omitempty"`
	Confirmations   uint64        `json:"confirmations"`
	RequiredConf    uint64        `json:"required_confirmations"`
	EstimatedTime   time.Duration `json:"estimated_time,omitempty"`
	ActualTime      time.Duration `json:"actual_time,omitempty"`
	ErrorMessage    string        `json:"error_message,omitempty"`
	ProcessedAt     time.Time     `json:"processed_at,omitempty"`
	CompletedAt     time.Time     `json:"completed_at,omitempty"`
	UpdatedAt       time.Time     `json:"updated_at,omitempty"`
}

// SwapPair represents a supported token swap pair
type SwapPair struct {
	ID          string    `json:"id"`
	FromToken   TokenInfo `json:"from_token"`
	ToToken     TokenInfo `json:"to_token"`
	ExchangeRate *big.Int `json:"exchange_rate"` // Rate in smallest units
	MinAmount   *big.Int  `json:"min_amount"`
	MaxAmount   *big.Int  `json:"max_amount"`
	Fee         *big.Int  `json:"fee"`
	IsActive    bool      `json:"is_active"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TransferValidationResult represents validation results
type TransferValidationResult struct {
	IsValid      bool     `json:"is_valid"`
	Errors       []string `json:"errors,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
	EstimatedFee *big.Int `json:"estimated_fee,omitempty"`
	EstimatedTime time.Duration `json:"estimated_time,omitempty"`
}

// TokenTransferManager manages cross-chain token transfers
type TokenTransferManager struct {
	mu                sync.RWMutex
	transfers         map[string]*TransferRequest
	responses         map[string]*TransferResponse
	supportedPairs    map[string]*SwapPair
	chainConfigs      map[ChainType]*ChainConfig
	validators        map[ChainType]AddressValidator
	feeCalculators    map[ChainType]FeeCalculator
	transferHandlers  map[ChainType]TransferHandler
	eventListeners    []TransferEventListener
	isRunning         bool
	ctx               context.Context
	cancel            context.CancelFunc
}

// ChainConfig represents configuration for a specific blockchain
type ChainConfig struct {
	ChainID           string        `json:"chain_id"`
	Name              string        `json:"name"`
	RPC               string        `json:"rpc_url"`
	WSS               string        `json:"wss_url,omitempty"`
	RequiredConf      uint64        `json:"required_confirmations"`
	BlockTime         time.Duration `json:"block_time"`
	MaxGasPrice       *big.Int      `json:"max_gas_price,omitempty"`
	NativeToken       TokenInfo     `json:"native_token"`
	SupportedTokens   []TokenInfo   `json:"supported_tokens"`
	BridgeContract    string        `json:"bridge_contract,omitempty"`
	IsTestnet         bool          `json:"is_testnet"`
}

// AddressValidator validates addresses for specific chains
type AddressValidator interface {
	ValidateAddress(address string) error
	NormalizeAddress(address string) (string, error)
	IsContractAddress(address string) (bool, error)
}

// FeeCalculator calculates transfer fees for specific chains
type FeeCalculator interface {
	CalculateTransferFee(req *TransferRequest) (*big.Int, error)
	EstimateGasPrice() (*big.Int, error)
	GetMinimumFee() *big.Int
}

// TransferHandler handles actual token transfers on specific chains
type TransferHandler interface {
	InitiateTransfer(req *TransferRequest) (*TransferResponse, error)
	ConfirmTransfer(txHash string) (*TransferResponse, error)
	RollbackTransfer(req *TransferRequest) error
	GetTransferStatus(txHash string) (TransferState, error)
}

// TransferEventListener listens for transfer events
type TransferEventListener interface {
	OnTransferInitiated(req *TransferRequest)
	OnTransferConfirmed(resp *TransferResponse)
	OnTransferCompleted(resp *TransferResponse)
	OnTransferFailed(resp *TransferResponse, err error)
	OnTransferRolledBack(req *TransferRequest)
}

// NewTokenTransferManager creates a new token transfer manager
func NewTokenTransferManager() *TokenTransferManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &TokenTransferManager{
		transfers:        make(map[string]*TransferRequest),
		responses:        make(map[string]*TransferResponse),
		supportedPairs:   make(map[string]*SwapPair),
		chainConfigs:     make(map[ChainType]*ChainConfig),
		validators:       make(map[ChainType]AddressValidator),
		feeCalculators:   make(map[ChainType]FeeCalculator),
		transferHandlers: make(map[ChainType]TransferHandler),
		eventListeners:   make([]TransferEventListener, 0),
		ctx:              ctx,
		cancel:           cancel,
	}
}

// RegisterChain registers a blockchain configuration
func (ttm *TokenTransferManager) RegisterChain(chainType ChainType, config *ChainConfig) error {
	ttm.mu.Lock()
	defer ttm.mu.Unlock()
	
	if config == nil {
		return fmt.Errorf("chain config cannot be nil")
	}
	
	ttm.chainConfigs[chainType] = config
	return nil
}

// RegisterValidator registers an address validator for a chain
func (ttm *TokenTransferManager) RegisterValidator(chainType ChainType, validator AddressValidator) {
	ttm.mu.Lock()
	defer ttm.mu.Unlock()
	ttm.validators[chainType] = validator
}

// RegisterFeeCalculator registers a fee calculator for a chain
func (ttm *TokenTransferManager) RegisterFeeCalculator(chainType ChainType, calculator FeeCalculator) {
	ttm.mu.Lock()
	defer ttm.mu.Unlock()
	ttm.feeCalculators[chainType] = calculator
}

// RegisterTransferHandler registers a transfer handler for a chain
func (ttm *TokenTransferManager) RegisterTransferHandler(chainType ChainType, handler TransferHandler) {
	ttm.mu.Lock()
	defer ttm.mu.Unlock()
	ttm.transferHandlers[chainType] = handler
}

// AddEventListener adds a transfer event listener
func (ttm *TokenTransferManager) AddEventListener(listener TransferEventListener) {
	ttm.mu.Lock()
	defer ttm.mu.Unlock()
	ttm.eventListeners = append(ttm.eventListeners, listener)
}

// AddSwapPair adds a supported token swap pair
func (ttm *TokenTransferManager) AddSwapPair(pair *SwapPair) error {
	ttm.mu.Lock()
	defer ttm.mu.Unlock()
	
	if pair == nil {
		return fmt.Errorf("swap pair cannot be nil")
	}
	
	pairID := fmt.Sprintf("%s_%s_%s_%s", 
		pair.FromToken.Symbol, pair.FromToken.ChainID,
		pair.ToToken.Symbol, pair.ToToken.ChainID)
	
	ttm.supportedPairs[pairID] = pair
	return nil
}

// ValidateTransferRequest validates a transfer request
func (ttm *TokenTransferManager) ValidateTransferRequest(req *TransferRequest) *TransferValidationResult {
	result := &TransferValidationResult{
		IsValid:  true,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}
	
	// Basic validation
	if req == nil {
		result.IsValid = false
		result.Errors = append(result.Errors, "transfer request cannot be nil")
		return result
	}
	
	// Validate chains
	if req.FromChain == req.ToChain {
		result.IsValid = false
		result.Errors = append(result.Errors, "source and destination chains cannot be the same")
	}
	
	// Validate amount
	if req.Amount == nil || req.Amount.Sign() <= 0 {
		result.IsValid = false
		result.Errors = append(result.Errors, "transfer amount must be positive")
	}
	
	// Validate deadline
	if req.Deadline.Before(time.Now()) {
		result.IsValid = false
		result.Errors = append(result.Errors, "transfer deadline has passed")
	}
	
	// Validate addresses using registered validators
	ttm.mu.RLock()
	defer ttm.mu.RUnlock()
	
	if validator, exists := ttm.validators[req.FromChain]; exists {
		if err := validator.ValidateAddress(req.FromAddress); err != nil {
			result.IsValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("invalid from address: %v", err))
		}
	}
	
	if validator, exists := ttm.validators[req.ToChain]; exists {
		if err := validator.ValidateAddress(req.ToAddress); err != nil {
			result.IsValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("invalid to address: %v", err))
		}
	}
	
	// Calculate estimated fee
	if calculator, exists := ttm.feeCalculators[req.FromChain]; exists {
		if fee, err := calculator.CalculateTransferFee(req); err == nil {
			result.EstimatedFee = fee
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("could not calculate fee: %v", err))
		}
	}
	
	// Estimate transfer time
	if config, exists := ttm.chainConfigs[req.FromChain]; exists {
		result.EstimatedTime = time.Duration(config.RequiredConf) * config.BlockTime
	}
	
	return result
}

// InitiateTransfer initiates a cross-chain token transfer
func (ttm *TokenTransferManager) InitiateTransfer(req *TransferRequest) (*TransferResponse, error) {
	// Validate request
	validation := ttm.ValidateTransferRequest(req)
	if !validation.IsValid {
		return nil, fmt.Errorf("validation failed: %v", validation.Errors)
	}
	
	// Store transfer request
	ttm.mu.Lock()
	ttm.transfers[req.ID] = req
	ttm.mu.Unlock()
	
	// Create initial response
	response := &TransferResponse{
		RequestID:     req.ID,
		State:         TransferStatePending,
		Confirmations: 0,
		ProcessedAt:   time.Now(),
	}
	
	// Get required confirmations
	if config, exists := ttm.chainConfigs[req.FromChain]; exists {
		response.RequiredConf = config.RequiredConf
		response.EstimatedTime = time.Duration(config.RequiredConf) * config.BlockTime
	}
	
	// Store response
	ttm.mu.Lock()
	ttm.responses[req.ID] = response
	ttm.mu.Unlock()
	
	// Notify listeners
	for _, listener := range ttm.eventListeners {
		go listener.OnTransferInitiated(req)
	}
	
	// Initiate transfer using appropriate handler
	ttm.mu.RLock()
	handler, exists := ttm.transferHandlers[req.FromChain]
	ttm.mu.RUnlock()
	
	if !exists {
		response.State = TransferStateFailed
		response.ErrorMessage = fmt.Sprintf("no transfer handler for chain %s", req.FromChain)
		return response, fmt.Errorf("no transfer handler for chain %s", req.FromChain)
	}
	
	// Execute transfer in background
	go ttm.executeTransfer(req, handler)
	
	return response, nil
}

// executeTransfer executes the actual transfer
func (ttm *TokenTransferManager) executeTransfer(req *TransferRequest, handler TransferHandler) {
	response, err := handler.InitiateTransfer(req)
	if err != nil {
		ttm.mu.Lock()
		if resp, exists := ttm.responses[req.ID]; exists {
			resp.State = TransferStateFailed
			resp.ErrorMessage = err.Error()
		}
		ttm.mu.Unlock()
		
		for _, listener := range ttm.eventListeners {
			go listener.OnTransferFailed(response, err)
		}
		return
	}
	
	// Update stored response
	ttm.mu.Lock()
	ttm.responses[req.ID] = response
	ttm.mu.Unlock()
	
	// Notify listeners based on state
	switch response.State {
	case TransferStateConfirmed:
		for _, listener := range ttm.eventListeners {
			go listener.OnTransferConfirmed(response)
		}
	case TransferStateCompleted:
		for _, listener := range ttm.eventListeners {
			go listener.OnTransferCompleted(response)
		}
	case TransferStateFailed:
		for _, listener := range ttm.eventListeners {
			go listener.OnTransferFailed(response, fmt.Errorf(response.ErrorMessage))
		}
	}
}

// GetTransferStatus returns the current status of a transfer
func (ttm *TokenTransferManager) GetTransferStatus(requestID string) (*TransferResponse, error) {
	ttm.mu.RLock()
	defer ttm.mu.RUnlock()
	
	response, exists := ttm.responses[requestID]
	if !exists {
		return nil, fmt.Errorf("transfer not found: %s", requestID)
	}
	
	return response, nil
}

// GetSupportedPairs returns all supported swap pairs
func (ttm *TokenTransferManager) GetSupportedPairs() map[string]*SwapPair {
	ttm.mu.RLock()
	defer ttm.mu.RUnlock()
	
	pairs := make(map[string]*SwapPair)
	for k, v := range ttm.supportedPairs {
		pairs[k] = v
	}
	
	return pairs
}

// GetChainConfig returns configuration for a specific chain
func (ttm *TokenTransferManager) GetChainConfig(chainType ChainType) (*ChainConfig, error) {
	ttm.mu.RLock()
	defer ttm.mu.RUnlock()
	
	config, exists := ttm.chainConfigs[chainType]
	if !exists {
		return nil, fmt.Errorf("chain config not found: %s", chainType)
	}
	
	return config, nil
}

// Start starts the token transfer manager
func (ttm *TokenTransferManager) Start() error {
	ttm.mu.Lock()
	defer ttm.mu.Unlock()
	
	if ttm.isRunning {
		return fmt.Errorf("token transfer manager is already running")
	}
	
	ttm.isRunning = true
	
	// Start background processes for monitoring transfers
	go ttm.monitorTransfers()
	
	return nil
}

// Stop stops the token transfer manager
func (ttm *TokenTransferManager) Stop() error {
	ttm.mu.Lock()
	defer ttm.mu.Unlock()
	
	if !ttm.isRunning {
		return nil
	}
	
	ttm.isRunning = false
	ttm.cancel()
	
	return nil
}

// monitorTransfers monitors ongoing transfers for updates
func (ttm *TokenTransferManager) monitorTransfers() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ttm.ctx.Done():
			return
		case <-ticker.C:
			ttm.checkPendingTransfers()
		}
	}
}

// checkPendingTransfers checks status of pending transfers
func (ttm *TokenTransferManager) checkPendingTransfers() {
	ttm.mu.RLock()
	pendingTransfers := make([]*TransferResponse, 0)
	for _, resp := range ttm.responses {
		if resp.State == TransferStatePending || resp.State == TransferStateConfirmed {
			pendingTransfers = append(pendingTransfers, resp)
		}
	}
	ttm.mu.RUnlock()
	
	for _, resp := range pendingTransfers {
		ttm.updateTransferStatus(resp)
	}
}

// updateTransferStatus updates the status of a transfer
func (ttm *TokenTransferManager) updateTransferStatus(resp *TransferResponse) {
	if resp.SourceTxHash == "" {
		return
	}
	
	// Get the request to determine source chain
	ttm.mu.RLock()
	req, exists := ttm.transfers[resp.RequestID]
	ttm.mu.RUnlock()
	
	if !exists {
		return
	}
	
	// Get handler for source chain
	ttm.mu.RLock()
	handler, exists := ttm.transferHandlers[req.FromChain]
	ttm.mu.RUnlock()
	
	if !exists {
		return
	}
	
	// Check current status
	currentState, err := handler.GetTransferStatus(resp.SourceTxHash)
	if err != nil {
		return
	}
	
	// Update if state changed
	if currentState != resp.State {
		ttm.mu.Lock()
		resp.State = currentState
		resp.UpdatedAt = time.Now()
		if currentState == TransferStateCompleted {
			resp.CompletedAt = time.Now()
			resp.ActualTime = resp.CompletedAt.Sub(resp.ProcessedAt)
		}
		ttm.mu.Unlock()
		
		// Notify listeners
		switch currentState {
		case TransferStateConfirmed:
			for _, listener := range ttm.eventListeners {
				go listener.OnTransferConfirmed(resp)
			}
		case TransferStateCompleted:
			for _, listener := range ttm.eventListeners {
				go listener.OnTransferCompleted(resp)
			}
		case TransferStateFailed:
			for _, listener := range ttm.eventListeners {
				go listener.OnTransferFailed(resp, fmt.Errorf(resp.ErrorMessage))
			}
		}
	}
}
