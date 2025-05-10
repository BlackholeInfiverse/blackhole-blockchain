package token

import (
	"math/big"
)

// Convert raw amount to human-readable format (adjust for decimals)
func (t *Token) FormatAmount(amount uint64) *big.Float {
	decimals := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(t.Decimals)), nil)
	result := new(big.Float).Quo(
		new(big.Float).SetUint64(amount),
		new(big.Float).SetInt(decimals),
	)
	return result
}

// Add other utilities like address validation, checksums, etc.