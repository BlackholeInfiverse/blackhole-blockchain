package token

import (
	"errors"
	"log"
	"time"
)

func (t *Token) Burn(from string, amount uint64) error {
	log.Printf("Burning %d tokens from %s", amount, from)

	// Check if operations are paused (unless emergency mode)
	if !t.IsEmergencyMode() {
		if err := t.requireNotPaused(); err != nil {
			log.Printf("Burn failed: %v", err)
			return err
		}
	}

	// Input validation
	if !t.validateAddress(from) {
		err := errors.New("invalid address")
		log.Printf("Burn failed: %v", err)
		return err
	}
	if amount == 0 {
		err := errors.New("amount must be > 0")
		log.Printf("Burn failed: %v", err)
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check sufficient balance
	if t.balances[from] < amount {
		err := errors.New("insufficient balance")
		log.Printf("Burn failed: %v (balance: %d, requested: %d)",
			err, t.balances[from], amount)
		return err
	}

	// Underflow protection for total supply
	if t.totalSupply < amount {
		err := errors.New("burn amount exceeds total supply")
		log.Printf("Burn failed: %v", err)
		return err
	}

	// Store old values for event metadata
	oldBalance := t.balances[from]
	oldTotalSupply := t.totalSupply

	// Execute burn
	t.balances[from] -= amount
	t.totalSupply -= amount

	// Emit event with enhanced metadata
	event := Event{
		Type:      EventBurn,
		From:      from,
		Amount:    amount,
		Timestamp: time.Now(),
		TxHash:    t.generateTxHash("burn", from, amount),
		Metadata: map[string]interface{}{
			"old_balance":      oldBalance,
			"new_balance":      t.balances[from],
			"old_total_supply": oldTotalSupply,
			"new_total_supply": t.totalSupply,
			"max_supply":       t.maxSupply,
		},
	}
	t.emitEvent(event)

	log.Printf("Burn successful: Balances[%s]=%d, TotalSupply=%d", from, t.balances[from], t.totalSupply)
	return nil
}