package token

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
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
	// Admin override functionality
	adminAddresses map[string]bool // Authorized admin addresses
	emergencyMode  bool            // Emergency mode flag
	paused         bool            // Pause all operations
}

func NewToken(name, symbol string, decimals uint8, initialSupply uint64) *Token {
	t := &Token{
		Name:           name,
		Symbol:         symbol,
		Decimals:       decimals,
		totalSupply:    0,             // Start with 0, will be updated as tokens are minted
		maxSupply:      initialSupply, // Set max supply to initial supply parameter
		balances:       make(map[string]uint64),
		allowances:     make(map[string]map[string]uint64),
		events:         []Event{},
		adminAddresses: make(map[string]bool),
		emergencyMode:  false,
		paused:         false,
	}
	// Set default admin (system)
	t.adminAddresses["system"] = true
	return t
}

// NewTokenWithMaxSupply creates a token with a specific maximum supply
func NewTokenWithMaxSupply(name, symbol string, decimals uint8, maxSupply uint64) *Token {
	t := &Token{
		Name:           name,
		Symbol:         symbol,
		Decimals:       decimals,
		totalSupply:    0,
		maxSupply:      maxSupply,
		balances:       make(map[string]uint64),
		allowances:     make(map[string]map[string]uint64),
		events:         []Event{},
		adminAddresses: make(map[string]bool),
		emergencyMode:  false,
		paused:         false,
	}
	// Set default admin (system)
	t.adminAddresses["system"] = true
	return t
}

func (t *Token) validateAddress(address string) bool {
	return address != "" && len(address) < 256
}

// generateTxHash generates a unique transaction hash for events
func (t *Token) generateTxHash(operation, address string, amount uint64) string {
	data := fmt.Sprintf("%s_%s_%s_%d_%d",
		t.Symbol, operation, address, amount, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("0x%x", hash[:8]) // Return first 8 bytes as hex
}
