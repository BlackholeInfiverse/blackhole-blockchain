package token

import (
	"errors"
	"log"
)

func (t *Token) Mint(to string, amount uint64) error {
	log.Printf("Minting %d tokens to %s", amount, to)
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

	// Check if token has a maximum supply limit
	if t.maxSupply > 0 {
		// Calculate current circulating supply
		currentSupply := uint64(0)
		for _, balance := range t.balances {
			currentSupply += balance
		}

		// Check if minting would exceed max supply
		if currentSupply+amount > t.maxSupply {
			err := errors.New("mint amount would exceed maximum supply")
			log.Printf("Mint failed: %v (current: %d, requested: %d, max: %d)", err, currentSupply, amount, t.maxSupply)
			return err
		}
	}

	// Overflow protection
	if t.balances[to] > ^uint64(0)-amount {
		err := errors.New("mint amount causes balance overflow")
		log.Printf("Mint failed: %v", err)
		return err
	}

	// Calculate current circulating supply for validation
	currentSupply := uint64(0)
	for _, balance := range t.balances {
		currentSupply += balance
	}

	t.balances[to] += amount

	// Update total supply to reflect actual circulating supply
	t.totalSupply = currentSupply + amount

	log.Printf("Mint successful: Balances[%s]=%d, TotalSupply=%d", to, t.balances[to], t.totalSupply)
	t.emitEvent(Event{Type: EventMint, To: to, Amount: amount})
	log.Printf("Event emitted for mint: %+v", Event{Type: EventMint, To: to, Amount: amount})
	return nil
}
