package token

import (
	"errors"
	"log"
	"time"
)

func (t *Token) Mint(to string, amount uint64) error {
	log.Printf("Minting %d tokens to %s", amount, to)

	// Check if operations are paused (unless emergency mode)
	if !t.IsEmergencyMode() {
		if err := t.requireNotPaused(); err != nil {
			log.Printf("Mint failed: %v", err)
			return err
		}
	}

	// Input validation
	if !t.validateAddress(to) {
		err := errors.New("invalid address")
		log.Printf("Mint failed: %v", err)
		return err
	}
	if amount == 0 {
		err := errors.New("amount must be > 0")
		log.Printf("Mint failed: %v", err)
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Calculate current circulating supply once
	currentSupply := t.calculateCirculatingSupply()

	// Check maximum supply limit
	if t.maxSupply > 0 && currentSupply+amount > t.maxSupply {
		err := errors.New("mint amount would exceed maximum supply")
		log.Printf("Mint failed: %v (current: %d, requested: %d, max: %d)",
			err, currentSupply, amount, t.maxSupply)
		return err
	}

	// Overflow protection for recipient balance
	if t.balances[to] > ^uint64(0)-amount {
		err := errors.New("mint amount causes balance overflow")
		log.Printf("Mint failed: %v", err)
		return err
	}

	// Overflow protection for total supply
	if currentSupply > ^uint64(0)-amount {
		err := errors.New("mint amount causes total supply overflow")
		log.Printf("Mint failed: %v", err)
		return err
	}

	// Execute mint
	t.balances[to] += amount
	t.totalSupply = currentSupply + amount

	// Emit event with enhanced metadata
	event := Event{
		Type:      EventMint,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now(),
		TxHash:    t.generateTxHash("mint", to, amount),
		Metadata: map[string]interface{}{
			"new_balance":    t.balances[to],
			"total_supply":   t.totalSupply,
			"max_supply":     t.maxSupply,
			"supply_ratio":   float64(t.totalSupply) / float64(t.maxSupply),
		},
	}
	t.emitEvent(event)

	log.Printf("Mint successful: Balances[%s]=%d, TotalSupply=%d", to, t.balances[to], t.totalSupply)
	return nil
}

// calculateCirculatingSupply calculates the current circulating supply
func (t *Token) calculateCirculatingSupply() uint64 {
	supply := uint64(0)
	for _, balance := range t.balances {
		supply += balance
	}
	return supply
}
