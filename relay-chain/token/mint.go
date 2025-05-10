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

	// Overflow protection
	if t.balances[to] > ^uint64(0)-amount {
		err := errors.New("mint amount causes balance overflow")
		log.Printf("Mint failed: %v", err)
		return err
	}
	if t.totalSupply > ^uint64(0)-amount {
		err := errors.New("mint amount causes total supply overflow")
		log.Printf("Mint failed: %v", err)
		return err
	}

	t.balances[to] += amount
	t.totalSupply += amount
	log.Printf("Mint successful: Balances[%s]=%d, TotalSupply=%d", to, t.balances[to], t.TotalSupply)
	t.emitEvent(Event{Type: EventMint, To: to, Amount: amount})
	log.Printf("Event emitted for mint: %+v", Event{Type: EventMint, To: to, Amount: amount})
	return nil
}