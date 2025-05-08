package token

import (
	"sync"
)

type Token struct {
	Name       string
	Symbol     string
	Decimals   uint8
	totalSupply uint64  // private field
	balances   map[string]uint64
	allowances map[string]map[string]uint64
	mu         sync.RWMutex
}

func NewToken(name, symbol string, decimals uint8, initialSupply uint64) *Token {
	t := &Token{
		Name:       name,
		Symbol:     symbol,
		Decimals:   decimals,
		balances:   make(map[string]uint64),
		allowances: make(map[string]map[string]uint64),
	}
	t.totalSupply = initialSupply  // Set initial supply
	return t
}
// Helper to check if address is valid (extend for your blockchain's address format)
func (t *Token) validateAddress(address string) bool {
	return len(address) > 0 // Replace with actual validation logic
}