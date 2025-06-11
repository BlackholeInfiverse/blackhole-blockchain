package dex

import (
	"fmt"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/bridge"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// CrossChainSwapOrder represents a cross-chain swap order
type CrossChainSwapOrder struct {
	ID              string                `json:"id"`
	User            string                `json:"user"`
	SourceChain     bridge.ChainType      `json:"source_chain"`
	DestChain       bridge.ChainType      `json:"dest_chain"`
	TokenIn         string                `json:"token_in"`
	TokenOut        string                `json:"token_out"`
	AmountIn        uint64                `json:"amount_in"`
	MinAmountOut    uint64                `json:"min_amount_out"`
	EstimatedOut    uint64                `json:"estimated_out"`
	Status          string                `json:"status"` // "pending", "bridging", "swapping", "completed", "failed"
	BridgeTxID      string                `json:"bridge_tx_id,omitempty"`
	SwapTxID        string                `json:"swap_tx_id,omitempty"`
	CreatedAt       int64                 `json:"created_at"`
	CompletedAt     int64                 `json:"completed_at,omitempty"`
	ExpiresAt       int64                 `json:"expires_at"`
	PriceImpact     float64               `json:"price_impact"`
	BridgeFee       uint64                `json:"bridge_fee"`
	SwapFee         uint64                `json:"swap_fee"`
	mu              sync.RWMutex
}

// CrossChainDEX manages cross-chain swaps
type CrossChainDEX struct {
	LocalDEX        *DEX                              `json:"-"`
	Bridge          *bridge.Bridge                    `json:"-"`
	Blockchain      *chain.Blockchain                 `json:"-"`
	SwapOrders      map[string]*CrossChainSwapOrder   `json:"swap_orders"`
	ChainDEXes      map[bridge.ChainType]*DEX         `json:"-"` // DEX instances for each chain
	SupportedPairs  map[string][]bridge.ChainType     `json:"supported_pairs"` // token -> supported chains
	BridgeFees      map[bridge.ChainType]uint64       `json:"bridge_fees"` // chain -> fee amount
	mu              sync.RWMutex
}

// NewCrossChainDEX creates a new cross-chain DEX
func NewCrossChainDEX(localDEX *DEX, bridgeInstance *bridge.Bridge, blockchain *chain.Blockchain) *CrossChainDEX {
	ccDEX := &CrossChainDEX{
		LocalDEX:       localDEX,
		Bridge:         bridgeInstance,
		Blockchain:     blockchain,
		SwapOrders:     make(map[string]*CrossChainSwapOrder),
		ChainDEXes:     make(map[bridge.ChainType]*DEX),
		SupportedPairs: make(map[string][]bridge.ChainType),
		BridgeFees:     make(map[bridge.ChainType]uint64),
	}

	// Initialize supported chains and fees
	ccDEX.initializeSupportedChains()
	
	return ccDEX
}

// initializeSupportedChains sets up supported tokens and chains
func (ccDEX *CrossChainDEX) initializeSupportedChains() {
	// Set up supported token pairs across chains
	ccDEX.SupportedPairs["BHX"] = []bridge.ChainType{
		bridge.ChainTypeBlackhole,
		bridge.ChainTypeEthereum,
		bridge.ChainTypeSolana,
	}
	ccDEX.SupportedPairs["USDT"] = []bridge.ChainType{
		bridge.ChainTypeBlackhole,
		bridge.ChainTypeEthereum,
		bridge.ChainTypeSolana,
	}
	ccDEX.SupportedPairs["ETH"] = []bridge.ChainType{
		bridge.ChainTypeEthereum,
		bridge.ChainTypeBlackhole,
	}
	ccDEX.SupportedPairs["SOL"] = []bridge.ChainType{
		bridge.ChainTypeSolana,
		bridge.ChainTypeBlackhole,
	}

	// Set bridge fees (in base units)
	ccDEX.BridgeFees[bridge.ChainTypeEthereum] = 10  // 10 units
	ccDEX.BridgeFees[bridge.ChainTypeSolana] = 5     // 5 units
	ccDEX.BridgeFees[bridge.ChainTypeBlackhole] = 1  // 1 unit

	fmt.Printf("✅ Cross-chain DEX initialized with %d supported tokens\n", len(ccDEX.SupportedPairs))
}

// GetCrossChainQuote calculates quote for cross-chain swap
func (ccDEX *CrossChainDEX) GetCrossChainQuote(sourceChain, destChain bridge.ChainType, tokenIn, tokenOut string, amountIn uint64) (*CrossChainSwapOrder, error) {
	ccDEX.mu.RLock()
	defer ccDEX.mu.RUnlock()

	// Validate chains support the tokens
	if !ccDEX.isTokenSupportedOnChain(tokenIn, sourceChain) {
		return nil, fmt.Errorf("token %s not supported on source chain %s", tokenIn, sourceChain)
	}
	if !ccDEX.isTokenSupportedOnChain(tokenOut, destChain) {
		return nil, fmt.Errorf("token %s not supported on destination chain %s", tokenOut, destChain)
	}

	// Calculate bridge fee
	bridgeFee := ccDEX.BridgeFees[destChain]
	if amountIn <= bridgeFee {
		return nil, fmt.Errorf("amount too small to cover bridge fee")
	}

	// Calculate swap quote on destination chain
	amountAfterBridge := amountIn - bridgeFee
	
	// Get swap quote (simulate destination DEX)
	estimatedOut, err := ccDEX.getDestinationSwapQuote(destChain, tokenIn, tokenOut, amountAfterBridge)
	if err != nil {
		return nil, fmt.Errorf("failed to get destination swap quote: %v", err)
	}

	// Calculate price impact
	priceImpact, _ := ccDEX.calculateCrossChainPriceImpact(sourceChain, destChain, tokenIn, tokenOut, amountIn)

	// Calculate swap fee (0.3% of output)
	swapFee := uint64(float64(estimatedOut) * 0.003)
	finalOutput := estimatedOut - swapFee

	quote := &CrossChainSwapOrder{
		SourceChain:  sourceChain,
		DestChain:    destChain,
		TokenIn:      tokenIn,
		TokenOut:     tokenOut,
		AmountIn:     amountIn,
		EstimatedOut: finalOutput,
		PriceImpact:  priceImpact,
		BridgeFee:    bridgeFee,
		SwapFee:      swapFee,
		ExpiresAt:    time.Now().Add(10 * time.Minute).Unix(), // 10 minute quote validity
	}

	return quote, nil
}

// InitiateCrossChainSwap starts a cross-chain swap
func (ccDEX *CrossChainDEX) InitiateCrossChainSwap(user string, sourceChain, destChain bridge.ChainType, tokenIn, tokenOut string, amountIn, minAmountOut uint64) (*CrossChainSwapOrder, error) {
	ccDEX.mu.Lock()
	defer ccDEX.mu.Unlock()

	// Generate swap order ID
	orderID := fmt.Sprintf("ccswap_%d_%s", time.Now().UnixNano(), user[:8])

	// Get fresh quote
	quote, err := ccDEX.GetCrossChainQuote(sourceChain, destChain, tokenIn, tokenOut, amountIn)
	if err != nil {
		return nil, err
	}

	// Check slippage protection
	if quote.EstimatedOut < minAmountOut {
		return nil, fmt.Errorf("insufficient output amount: estimated %d, minimum %d", quote.EstimatedOut, minAmountOut)
	}

	// Create swap order
	order := &CrossChainSwapOrder{
		ID:           orderID,
		User:         user,
		SourceChain:  sourceChain,
		DestChain:    destChain,
		TokenIn:      tokenIn,
		TokenOut:     tokenOut,
		AmountIn:     amountIn,
		MinAmountOut: minAmountOut,
		EstimatedOut: quote.EstimatedOut,
		Status:       "pending",
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(30 * time.Minute).Unix(), // 30 minute execution window
		PriceImpact:  quote.PriceImpact,
		BridgeFee:    quote.BridgeFee,
		SwapFee:      quote.SwapFee,
	}

	ccDEX.SwapOrders[orderID] = order

	// Start the cross-chain swap process
	go ccDEX.executeCrossChainSwap(orderID)

	fmt.Printf("✅ Cross-chain swap initiated: %s (%d %s on %s → %s on %s)\n", 
		orderID, amountIn, tokenIn, sourceChain, tokenOut, destChain)

	return order, nil
}

// executeCrossChainSwap executes the multi-step cross-chain swap
func (ccDEX *CrossChainDEX) executeCrossChainSwap(orderID string) {
	order, exists := ccDEX.SwapOrders[orderID]
	if !exists {
		return
	}

	// Step 1: Initiate bridge transfer
	order.mu.Lock()
	order.Status = "bridging"
	order.mu.Unlock()

	bridgeTx, err := ccDEX.Bridge.InitiateBridgeTransfer(
		order.SourceChain,
		order.DestChain,
		order.User,
		order.User, // Same user on destination
		order.TokenIn,
		order.AmountIn,
	)

	if err != nil {
		order.mu.Lock()
		order.Status = "failed"
		order.mu.Unlock()
		fmt.Printf("❌ Bridge transfer failed for order %s: %v\n", orderID, err)
		return
	}

	order.mu.Lock()
	order.BridgeTxID = bridgeTx.ID
	order.mu.Unlock()

	// Step 2: Wait for bridge confirmation and execute swap
	go ccDEX.waitForBridgeAndSwap(orderID)
}

// waitForBridgeAndSwap waits for bridge completion and executes the swap
func (ccDEX *CrossChainDEX) waitForBridgeAndSwap(orderID string) {
	order, exists := ccDEX.SwapOrders[orderID]
	if !exists {
		return
	}

	// Wait for bridge transaction to complete (simulate)
	time.Sleep(5 * time.Second) // Simulate bridge confirmation time

	// Step 3: Execute swap on destination chain
	order.mu.Lock()
	order.Status = "swapping"
	order.mu.Unlock()

	// Calculate amount after bridge fees
	amountForSwap := order.AmountIn - order.BridgeFee

	// Execute the swap (simulate destination chain swap)
	swapResult, err := ccDEX.executeDestinationSwap(order.DestChain, order.TokenIn, order.TokenOut, amountForSwap, order.MinAmountOut, order.User)
	if err != nil {
		order.mu.Lock()
		order.Status = "failed"
		order.mu.Unlock()
		fmt.Printf("❌ Destination swap failed for order %s: %v\n", orderID, err)
		return
	}

	// Step 4: Complete the order
	order.mu.Lock()
	order.Status = "completed"
	order.SwapTxID = swapResult.TxID
	order.EstimatedOut = swapResult.AmountOut // Update with actual amount
	order.CompletedAt = time.Now().Unix()
	order.mu.Unlock()

	fmt.Printf("✅ Cross-chain swap completed: %s (Final output: %d %s)\n", 
		orderID, swapResult.AmountOut, order.TokenOut)
}

// Helper functions
func (ccDEX *CrossChainDEX) isTokenSupportedOnChain(token string, chainType bridge.ChainType) bool {
	supportedChains, exists := ccDEX.SupportedPairs[token]
	if !exists {
		return false
	}
	
	for _, chain := range supportedChains {
		if chain == chainType {
			return true
		}
	}
	return false
}

func (ccDEX *CrossChainDEX) getDestinationSwapQuote(destChain bridge.ChainType, tokenIn, tokenOut string, amountIn uint64) (uint64, error) {
	// If destination is local chain, use local DEX
	if destChain == bridge.ChainTypeBlackhole {
		return ccDEX.LocalDEX.GetSwapQuote(tokenIn, tokenOut, amountIn)
	}
	
	// Simulate external chain DEX quote
	// In production, this would call external chain APIs
	simulatedRate := 1.0
	if tokenIn == "BHX" && tokenOut == "USDT" {
		simulatedRate = 5.0 // 1 BHX = 5 USDT
	} else if tokenIn == "USDT" && tokenOut == "BHX" {
		simulatedRate = 0.2 // 1 USDT = 0.2 BHX
	}
	
	return uint64(float64(amountIn) * simulatedRate), nil
}

func (ccDEX *CrossChainDEX) calculateCrossChainPriceImpact(sourceChain, destChain bridge.ChainType, tokenIn, tokenOut string, amountIn uint64) (float64, error) {
	// Simplified price impact calculation for cross-chain
	// In production, this would consider liquidity on both chains
	if destChain == bridge.ChainTypeBlackhole {
		return ccDEX.LocalDEX.CalculatePriceImpact(tokenIn, tokenOut, amountIn)
	}
	
	// Simulate external chain price impact
	return 0.5, nil // 0.5% impact
}

// SwapResult represents the result of a destination swap
type SwapResult struct {
	TxID      string
	AmountOut uint64
}

func (ccDEX *CrossChainDEX) executeDestinationSwap(destChain bridge.ChainType, tokenIn, tokenOut string, amountIn, minAmountOut uint64, user string) (*SwapResult, error) {
	// If destination is local chain, use local DEX
	if destChain == bridge.ChainTypeBlackhole {
		amountOut, err := ccDEX.LocalDEX.ExecuteSwap(tokenIn, tokenOut, amountIn, minAmountOut, user)
		if err != nil {
			return nil, err
		}
		
		return &SwapResult{
			TxID:      fmt.Sprintf("local_swap_%d", time.Now().UnixNano()),
			AmountOut: amountOut,
		}, nil
	}
	
	// Simulate external chain swap
	quote, err := ccDEX.getDestinationSwapQuote(destChain, tokenIn, tokenOut, amountIn)
	if err != nil {
		return nil, err
	}
	
	if quote < minAmountOut {
		return nil, fmt.Errorf("insufficient output amount")
	}
	
	return &SwapResult{
		TxID:      fmt.Sprintf("%s_swap_%d", destChain, time.Now().UnixNano()),
		AmountOut: quote,
	}, nil
}

// GetSwapOrder returns a swap order by ID
func (ccDEX *CrossChainDEX) GetSwapOrder(orderID string) (*CrossChainSwapOrder, error) {
	ccDEX.mu.RLock()
	defer ccDEX.mu.RUnlock()
	
	order, exists := ccDEX.SwapOrders[orderID]
	if !exists {
		return nil, fmt.Errorf("swap order %s not found", orderID)
	}
	
	// Return a copy to avoid race conditions
	orderCopy := *order
	return &orderCopy, nil
}

// GetUserSwapOrders returns all swap orders for a user
func (ccDEX *CrossChainDEX) GetUserSwapOrders(user string) []*CrossChainSwapOrder {
	ccDEX.mu.RLock()
	defer ccDEX.mu.RUnlock()
	
	var userOrders []*CrossChainSwapOrder
	for _, order := range ccDEX.SwapOrders {
		if order.User == user {
			orderCopy := *order
			userOrders = append(userOrders, &orderCopy)
		}
	}
	
	return userOrders
}

// GetSupportedChains returns supported chains for a token
func (ccDEX *CrossChainDEX) GetSupportedChains(token string) []bridge.ChainType {
	ccDEX.mu.RLock()
	defer ccDEX.mu.RUnlock()
	
	return ccDEX.SupportedPairs[token]
}
