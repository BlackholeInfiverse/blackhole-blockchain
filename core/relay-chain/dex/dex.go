package dex

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	
)

// LiquidityPool represents a trading pair pool
type LiquidityPool struct {
	TokenA       string  `json:"token_a"`
	TokenB       string  `json:"token_b"`
	ReserveA     uint64  `json:"reserve_a"`
	ReserveB     uint64  `json:"reserve_b"`
	TotalShares  uint64  `json:"total_shares"`
	FeeRate      float64 `json:"fee_rate"` // 0.003 = 0.3%
	LastUpdated  int64   `json:"last_updated"`
	mu           sync.RWMutex
}

// DEX represents the decentralized exchange
type DEX struct {
	Pools       map[string]*LiquidityPool `json:"pools"` // key: "TokenA-TokenB"
	Blockchain  *chain.Blockchain         `json:"-"`
	mu          sync.RWMutex
}

// NewDEX creates a new DEX instance
func NewDEX(blockchain *chain.Blockchain) *DEX {
	return &DEX{
		Pools:      make(map[string]*LiquidityPool),
		Blockchain: blockchain,
	}
}

// CreatePair creates a new trading pair
func (dex *DEX) CreatePair(tokenA, tokenB string, initialReserveA, initialReserveB uint64) error {
	dex.mu.Lock()
	defer dex.mu.Unlock()

	pairKey := dex.getPairKey(tokenA, tokenB)
	if _, exists := dex.Pools[pairKey]; exists {
		return fmt.Errorf("pair %s already exists", pairKey)
	}

	pool := &LiquidityPool{
		TokenA:      tokenA,
		TokenB:      tokenB,
		ReserveA:    initialReserveA,
		ReserveB:    initialReserveB,
		TotalShares: uint64(math.Sqrt(float64(initialReserveA * initialReserveB))),
		FeeRate:     0.003, // 0.3% fee
		LastUpdated: time.Now().Unix(),
	}

	dex.Pools[pairKey] = pool
	fmt.Printf("✅ Created trading pair: %s with reserves %d:%d\n", pairKey, initialReserveA, initialReserveB)
	return nil
}

// AddLiquidity adds liquidity to a pool
func (dex *DEX) AddLiquidity(tokenA, tokenB string, amountA, amountB uint64, provider string) (uint64, error) {
	dex.mu.Lock()
	defer dex.mu.Unlock()

	pairKey := dex.getPairKey(tokenA, tokenB)
	pool, exists := dex.Pools[pairKey]
	if !exists {
		return 0, fmt.Errorf("pair %s does not exist", pairKey)
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Calculate optimal amounts and shares
	var shares uint64
	if pool.TotalShares == 0 {
		shares = uint64(math.Sqrt(float64(amountA * amountB)))
	} else {
		sharesA := (amountA * pool.TotalShares) / pool.ReserveA
		sharesB := (amountB * pool.TotalShares) / pool.ReserveB
		shares = min(sharesA, sharesB)
	}

	// Update pool reserves
	pool.ReserveA += amountA
	pool.ReserveB += amountB
	pool.TotalShares += shares
	pool.LastUpdated = time.Now().Unix()

	fmt.Printf("✅ Added liquidity: %d %s + %d %s, received %d shares\n", 
		amountA, tokenA, amountB, tokenB, shares)
	return shares, nil
}

// GetSwapQuote calculates the output amount for a swap
func (dex *DEX) GetSwapQuote(tokenIn, tokenOut string, amountIn uint64) (uint64, error) {
	dex.mu.RLock()
	defer dex.mu.RUnlock()

	pairKey := dex.getPairKey(tokenIn, tokenOut)
	pool, exists := dex.Pools[pairKey]
	if !exists {
		return 0, fmt.Errorf("pair %s does not exist", pairKey)
	}

	pool.mu.RLock()
	defer pool.mu.RUnlock()

	var reserveIn, reserveOut uint64
	if tokenIn == pool.TokenA {
		reserveIn, reserveOut = pool.ReserveA, pool.ReserveB
	} else {
		reserveIn, reserveOut = pool.ReserveB, pool.ReserveA
	}

	// Apply fee
	amountInWithFee := uint64(float64(amountIn) * (1.0 - pool.FeeRate))
	
	// Calculate output using constant product formula: x * y = k
	amountOut := (amountInWithFee * reserveOut) / (reserveIn + amountInWithFee)
	
	return amountOut, nil
}

// CalculatePriceImpact calculates the price impact of a swap
func (dex *DEX) CalculatePriceImpact(tokenIn, tokenOut string, amountIn uint64) (float64, error) {
	dex.mu.RLock()
	defer dex.mu.RUnlock()

	pairKey := dex.getPairKey(tokenIn, tokenOut)
	pool, exists := dex.Pools[pairKey]
	if !exists {
		return 0, fmt.Errorf("pair %s does not exist", pairKey)
	}

	pool.mu.RLock()
	defer pool.mu.RUnlock()

	var reserveIn, reserveOut uint64
	if tokenIn == pool.TokenA {
		reserveIn, reserveOut = pool.ReserveA, pool.ReserveB
	} else {
		reserveIn, reserveOut = pool.ReserveB, pool.ReserveA
	}

	// Current price
	currentPrice := float64(reserveOut) / float64(reserveIn)
	
	// Price after swap
	amountOut, _ := dex.GetSwapQuote(tokenIn, tokenOut, amountIn)
	newReserveIn := reserveIn + amountIn
	newReserveOut := reserveOut - amountOut
	newPrice := float64(newReserveOut) / float64(newReserveIn)
	
	// Price impact percentage
	priceImpact := math.Abs((newPrice - currentPrice) / currentPrice) * 100
	
	return priceImpact, nil
}

// GetSwapRate returns the current exchange rate
func (dex *DEX) GetSwapRate(tokenA, tokenB string) (float64, error) {
	dex.mu.RLock()
	defer dex.mu.RUnlock()

	pairKey := dex.getPairKey(tokenA, tokenB)
	pool, exists := dex.Pools[pairKey]
	if !exists {
		return 0, fmt.Errorf("pair %s does not exist", pairKey)
	}

	pool.mu.RLock()
	defer pool.mu.RUnlock()

	if tokenA == pool.TokenA {
		return float64(pool.ReserveB) / float64(pool.ReserveA), nil
	}
	return float64(pool.ReserveA) / float64(pool.ReserveB), nil
}

// ExecuteSwap performs a token swap
func (dex *DEX) ExecuteSwap(tokenIn, tokenOut string, amountIn uint64, minAmountOut uint64, trader string) (uint64, error) {
	dex.mu.Lock()
	defer dex.mu.Unlock()

	pairKey := dex.getPairKey(tokenIn, tokenOut)
	pool, exists := dex.Pools[pairKey]
	if !exists {
		return 0, fmt.Errorf("pair %s does not exist", pairKey)
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Calculate output amount
	amountOut, err := dex.GetSwapQuote(tokenIn, tokenOut, amountIn)
	if err != nil {
		return 0, err
	}

	if amountOut < minAmountOut {
		return 0, fmt.Errorf("insufficient output amount: got %d, minimum %d", amountOut, minAmountOut)
	}

	// Update pool reserves
	if tokenIn == pool.TokenA {
		pool.ReserveA += amountIn
		pool.ReserveB -= amountOut
	} else {
		pool.ReserveB += amountIn
		pool.ReserveA -= amountOut
	}
	pool.LastUpdated = time.Now().Unix()

	fmt.Printf("✅ Swap executed: %d %s → %d %s\n", amountIn, tokenIn, amountOut, tokenOut)
	return amountOut, nil
}

// GetPoolStatus returns the current status of a pool
func (dex *DEX) GetPoolStatus(tokenA, tokenB string) (*LiquidityPool, error) {
	dex.mu.RLock()
	defer dex.mu.RUnlock()

	pairKey := dex.getPairKey(tokenA, tokenB)
	pool, exists := dex.Pools[pairKey]
	if !exists {
		return nil, fmt.Errorf("pair %s does not exist", pairKey)
	}

	// Return a copy to avoid race conditions
	poolCopy := *pool
	return &poolCopy, nil
}

// GetAllPools returns all trading pairs
func (dex *DEX) GetAllPools() map[string]*LiquidityPool {
	dex.mu.RLock()
	defer dex.mu.RUnlock()

	pools := make(map[string]*LiquidityPool)
	for key, pool := range dex.Pools {
		poolCopy := *pool
		pools[key] = &poolCopy
	}
	return pools
}

// Helper function to create consistent pair keys
func (dex *DEX) getPairKey(tokenA, tokenB string) string {
	if tokenA < tokenB {
		return fmt.Sprintf("%s-%s", tokenA, tokenB)
	}
	return fmt.Sprintf("%s-%s", tokenB, tokenA)
}

// Helper function to get minimum of two uint64 values
func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
