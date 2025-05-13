package token

import (
	"sync"
)

type Token struct {
	Name        string
	Symbol      string
	Decimals    uint8
	totalSupply uint64
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
		totalSupply: initialSupply,
		balances:    make(map[string]uint64),
		allowances:  make(map[string]map[string]uint64),
		events:      []Event{},
	}
	return t
}

func (t *Token) validateAddress(address string) bool {
	return address != "" && len(address) < 256
}

