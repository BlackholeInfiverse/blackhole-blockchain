package token

import (
	"sync"
)

type Token struct {
	Name        string
	Symbol      string
	Decimals    uint8
	totalSupply uint64
	maxSupply   uint64 // Maximum supply limit (0 = unlimited)
	balances    map[string]uint64
	allowances  map[string]map[string]uint64
	mu          sync.RWMutex
	events      []Event
}

func NewToken(name, symbol string, decimals uint8, initialSupply uint64) *Token {
	t := &Token{
		Name:        name,
		Symbol:      symbol,
		Decimals:    decimals,
		totalSupply: 0,             // Start with 0, will be updated as tokens are minted
		maxSupply:   initialSupply, // Set max supply to initial supply parameter
		balances:    make(map[string]uint64),
		allowances:  make(map[string]map[string]uint64),
		events:      []Event{},
	}
	return t
}

// NewTokenWithMaxSupply creates a token with a specific maximum supply
func NewTokenWithMaxSupply(name, symbol string, decimals uint8, maxSupply uint64) *Token {
	t := &Token{
		Name:        name,
		Symbol:      symbol,
		Decimals:    decimals,
		totalSupply: 0,
		maxSupply:   maxSupply,
		balances:    make(map[string]uint64),
		allowances:  make(map[string]map[string]uint64),
		events:      []Event{},
	}
	return t
}

func (t *Token) validateAddress(address string) bool {
	return address != "" && len(address) < 256
}
