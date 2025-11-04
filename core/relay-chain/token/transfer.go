package token

import (
	"encoding/json"
	"errors"
	"log"
	"time"
)

func (t *Token) Transfer(from, to string, amount uint64) error {
	log.Printf("Transferring %d tokens from %s to %s", amount, from, to)

	// Check if operations are paused
	if err := t.requireNotPaused(); err != nil {
		log.Printf("Transfer failed: %v", err)
		return err
	}

	// Input validation
	if !t.validateAddress(from) || !t.validateAddress(to) {
		err := errors.New("invalid address")
		log.Printf("Transfer failed: %v", err)
		return err
	}
	if amount == 0 {
		err := errors.New("amount must be > 0")
		log.Printf("Transfer failed: %v", err)
		return err
	}
	if from == to {
		err := errors.New("cannot transfer to same address")
		log.Printf("Transfer failed: %v", err)
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check sufficient balance
	if t.balances[from] < amount {
		err := errors.New("insufficient balance")
		log.Printf("Transfer failed: %v (balance: %d, requested: %d)",
			err, t.balances[from], amount)
		return err
	}

	// Overflow protection for recipient
	if t.balances[to] > ^uint64(0)-amount {
		err := errors.New("transfer amount causes recipient balance overflow")
		log.Printf("Transfer failed: %v", err)
		return err
	}

	// Store old values for event metadata
	oldFromBalance := t.balances[from]
	oldToBalance := t.balances[to]

	// Execute transfer
	t.balances[from] -= amount
	t.balances[to] += amount

	// Emit event with enhanced metadata
	event := Event{
		Type:      EventTransfer,
		From:      from,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now(),
		TxHash:    t.generateTxHash("transfer", from+":"+to, amount),
		Metadata: map[string]interface{}{
			"from_old_balance": oldFromBalance,
			"from_new_balance": t.balances[from],
			"to_old_balance":   oldToBalance,
			"to_new_balance":   t.balances[to],
			"total_supply":     t.totalSupply,
		},
	}
	t.emitEvent(event)
	eventJson, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal event: %v", err)
	} else {
		log.Printf("[EVENT_JSON] %s", string(eventJson))
	}


	log.Printf("Transfer successful: %s[%d→%d], %s[%d→%d]",
		from, oldFromBalance, t.balances[from],
		to, oldToBalance, t.balances[to])
	return nil
}