package integration

import (
	"fmt"
	"strconv"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// BridgeTransaction represents a bridge transaction (from bridge-sdk)
type BridgeTransaction struct {
	ID             string     `json:"id"`
	Hash           string     `json:"hash"`
	SourceChain    string     `json:"source_chain"`
	DestChain      string     `json:"dest_chain"`
	SourceAddress  string     `json:"source_address"`
	DestAddress    string     `json:"dest_address"`
	TokenSymbol    string     `json:"token_symbol"`
	Amount         string     `json:"amount"`
	Fee            string     `json:"fee"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	ProcessingTime string     `json:"processing_time,omitempty"`
	Confirmations  int        `json:"confirmations"`
	BlockNumber    uint64     `json:"block_number"`
}

// TransactionConverter handles conversion between bridge and core blockchain transactions
type TransactionConverter struct{}

// NewTransactionConverter creates a new transaction converter
func NewTransactionConverter() *TransactionConverter {
	return &TransactionConverter{}
}

// BridgeToCore converts a bridge transaction to core blockchain transaction
func (tc *TransactionConverter) BridgeToCore(bridgeTx *BridgeTransaction) (*chain.Transaction, error) {
	// Parse amount from string to uint64
	amount, err := strconv.ParseUint(bridgeTx.Amount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount format: %s", bridgeTx.Amount)
	}

	// Parse fee if provided
	var fee uint64
	if bridgeTx.Fee != "" {
		feeFloat, err := strconv.ParseFloat(bridgeTx.Fee, 64)
		if err == nil {
			fee = uint64(feeFloat * 1000000) // Convert to micro units
		}
	}

	// Determine transaction type based on operation
	txType := chain.TokenTransfer
	if bridgeTx.DestChain == "blackhole" && bridgeTx.SourceChain != "blackhole" {
		// Incoming bridge transaction - might need minting
		txType = chain.TokenTransfer // Use transfer for now, bridge module handles minting
	}

	// Create core blockchain transaction
	coreTx := &chain.Transaction{
		ID:        bridgeTx.Hash,
		Type:      txType,
		From:      bridgeTx.SourceAddress,
		To:        bridgeTx.DestAddress,
		Amount:    amount,
		TokenID:   tc.mapTokenSymbol(bridgeTx.TokenSymbol, bridgeTx.DestChain),
		Timestamp: bridgeTx.CreatedAt.Unix(),
		Fee:       fee,
		Nonce:     0, // Will be set by blockchain
		Data:      tc.createTransactionData(bridgeTx),
	}

	return coreTx, nil
}

// CoreToBridge converts a core blockchain transaction to bridge transaction
func (tc *TransactionConverter) CoreToBridge(coreTx *chain.Transaction, sourceChain, destChain string) *BridgeTransaction {
	bridgeTx := &BridgeTransaction{
		ID:            coreTx.ID,
		Hash:          coreTx.ID,
		SourceChain:   sourceChain,
		DestChain:     destChain,
		SourceAddress: coreTx.From,
		DestAddress:   coreTx.To,
		TokenSymbol:   tc.unmapTokenSymbol(coreTx.TokenID),
		Amount:        fmt.Sprintf("%d", coreTx.Amount),
		Fee:           fmt.Sprintf("%.6f", float64(coreTx.Fee)/1000000),
		Status:        "pending",
		CreatedAt:     time.Unix(coreTx.Timestamp, 0),
		Confirmations: 0,
		BlockNumber:   0,
	}

	return bridgeTx
}

// mapTokenSymbol maps bridge token symbols to blockchain token IDs
func (tc *TransactionConverter) mapTokenSymbol(symbol, destChain string) string {
	// Token mapping for different chains
	tokenMappings := map[string]map[string]string{
		"blackhole": {
			"BHX":  "BHX",
			"ETH":  "wETH", // Wrapped ETH on BlackHole
			"SOL":  "wSOL", // Wrapped SOL on BlackHole
			"USDC": "wUSDC", // Wrapped USDC on BlackHole
			"USDT": "wUSDT", // Wrapped USDT on BlackHole
		},
		"ethereum": {
			"BHX":  "wBHX", // Wrapped BHX on Ethereum
			"ETH":  "ETH",
			"USDC": "USDC",
			"USDT": "USDT",
		},
		"solana": {
			"BHX":  "wBHX", // Wrapped BHX on Solana
			"SOL":  "SOL",
			"USDC": "USDC",
			"USDT": "USDT",
		},
	}

	if chainMappings, exists := tokenMappings[destChain]; exists {
		if mappedSymbol, exists := chainMappings[symbol]; exists {
			return mappedSymbol
		}
	}

	// Default to original symbol if no mapping found
	return symbol
}

// unmapTokenSymbol converts blockchain token ID back to bridge symbol
func (tc *TransactionConverter) unmapTokenSymbol(tokenID string) string {
	// Reverse mapping for display purposes
	reverseMappings := map[string]string{
		"wETH":  "ETH",
		"wSOL":  "SOL",
		"wUSDC": "USDC",
		"wUSDT": "USDT",
		"wBHX":  "BHX",
	}

	if originalSymbol, exists := reverseMappings[tokenID]; exists {
		return originalSymbol
	}

	return tokenID
}

// createTransactionData creates additional data for the transaction
func (tc *TransactionConverter) createTransactionData(bridgeTx *BridgeTransaction) []byte {
	// Create metadata for bridge transactions
	metadata := fmt.Sprintf("bridge:%s->%s:%s", 
		bridgeTx.SourceChain, 
		bridgeTx.DestChain, 
		bridgeTx.ID)
	
	return []byte(metadata)
}

// ValidateBridgeTransaction validates a bridge transaction before conversion
func (tc *TransactionConverter) ValidateBridgeTransaction(bridgeTx *BridgeTransaction) error {
	if bridgeTx.ID == "" {
		return fmt.Errorf("transaction ID is required")
	}

	if bridgeTx.SourceAddress == "" || bridgeTx.DestAddress == "" {
		return fmt.Errorf("source and destination addresses are required")
	}

	if bridgeTx.Amount == "" {
		return fmt.Errorf("amount is required")
	}

	// Validate amount is numeric
	if _, err := strconv.ParseUint(bridgeTx.Amount, 10, 64); err != nil {
		return fmt.Errorf("invalid amount format: %s", bridgeTx.Amount)
	}

	if bridgeTx.TokenSymbol == "" {
		return fmt.Errorf("token symbol is required")
	}

	// Validate chain types
	validChains := map[string]bool{
		"ethereum":  true,
		"solana":    true,
		"blackhole": true,
	}

	if !validChains[bridgeTx.SourceChain] {
		return fmt.Errorf("invalid source chain: %s", bridgeTx.SourceChain)
	}

	if !validChains[bridgeTx.DestChain] {
		return fmt.Errorf("invalid destination chain: %s", bridgeTx.DestChain)
	}

	if bridgeTx.SourceChain == bridgeTx.DestChain {
		return fmt.Errorf("source and destination chains cannot be the same")
	}

	return nil
}

// EstimateGas estimates gas cost for a bridge transaction
func (tc *TransactionConverter) EstimateGas(bridgeTx *BridgeTransaction) (uint64, error) {
	// Base gas cost
	baseGas := uint64(21000)

	// Additional gas for token operations
	if bridgeTx.TokenSymbol != "BHX" {
		baseGas += 50000 // Token transfer gas
	}

	// Cross-chain operation gas
	if bridgeTx.DestChain == "blackhole" {
		baseGas += 30000 // Minting gas
	} else {
		baseGas += 40000 // External chain relay gas
	}

	return baseGas, nil
}

// CalculateFee calculates transaction fee based on gas and gas price
func (tc *TransactionConverter) CalculateFee(gasUsed, gasPrice uint64) string {
	totalFee := gasUsed * gasPrice
	// Convert to decimal representation (assuming 18 decimals)
	feeInEth := float64(totalFee) / 1000000000000000000
	return fmt.Sprintf("%.9f", feeInEth)
}

// GetSupportedTokens returns list of supported tokens for each chain
func (tc *TransactionConverter) GetSupportedTokens() map[string][]string {
	return map[string][]string{
		"blackhole": {"BHX", "wETH", "wSOL", "wUSDC", "wUSDT"},
		"ethereum":  {"ETH", "wBHX", "USDC", "USDT", "WBTC", "LINK", "UNI"},
		"solana":    {"SOL", "wBHX", "USDC", "USDT", "RAY", "SRM", "ORCA"},
	}
}

// GetTokenDecimals returns decimal places for tokens
func (tc *TransactionConverter) GetTokenDecimals(tokenSymbol string) uint8 {
	decimals := map[string]uint8{
		"BHX":   18,
		"ETH":   18,
		"wETH":  18,
		"SOL":   9,
		"wSOL":  9,
		"USDC":  6,
		"wUSDC": 6,
		"USDT":  6,
		"wUSDT": 6,
		"WBTC":  8,
		"LINK":  18,
		"UNI":   18,
		"RAY":   6,
		"SRM":   6,
		"ORCA":  6,
	}

	if decimal, exists := decimals[tokenSymbol]; exists {
		return decimal
	}

	return 18 // Default to 18 decimals
}
