package token

import (
	"errors"
	"log"
	"time"
)

func (t *Token) Approve(owner, spender string, amount uint64) error {
	log.Printf("Approving %d tokens from %s to %s", amount, owner, spender)

	// Input validation
	if !t.validateAddress(owner) || !t.validateAddress(spender) {
		err := errors.New("invalid address")
		log.Printf("Approval failed: %v", err)
		return err
	}
	if owner == spender {
		err := errors.New("cannot approve to same address")
		log.Printf("Approval failed: %v", err)
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Initialize allowances map if needed
	if t.allowances[owner] == nil {
		t.allowances[owner] = make(map[string]uint64)
	}

	// Store old allowance for event metadata
	oldAllowance := t.allowances[owner][spender]

	// Set new allowance
	t.allowances[owner][spender] = amount

	// Emit approval event
	event := Event{
		Type:      EventApproval,
		From:      owner,
		To:        spender,
		Amount:    amount,
		Timestamp: time.Now(),
		TxHash:    t.generateTxHash("approval", owner+":"+spender, amount),
		Metadata: map[string]interface{}{
			"old_allowance": oldAllowance,
			"new_allowance": amount,
			"owner":         owner,
			"spender":       spender,
		},
	}
	t.emitEvent(event)

	log.Printf("Approval successful: %s→%s allowance: %d→%d",
		owner, spender, oldAllowance, amount)
	return nil
}

func (t *Token) Allowance(owner, spender string) (uint64, error) {
	if !t.validateAddress(owner) || !t.validateAddress(spender) {
		return 0, errors.New("invalid address")
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.allowances[owner] == nil {
		return 0, nil
	}
	return t.allowances[owner][spender], nil
}

func (t *Token) TransferFrom(owner, spender, to string, amount uint64) error {
	log.Printf("TransferFrom: %d tokens from %s to %s (spender: %s)", amount, owner, to, spender)

	// Input validation
	if !t.validateAddress(owner) || !t.validateAddress(spender) || !t.validateAddress(to) {
		err := errors.New("invalid address")
		log.Printf("TransferFrom failed: %v", err)
		return err
	}
	if amount == 0 {
		err := errors.New("amount must be > 0")
		log.Printf("TransferFrom failed: %v", err)
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check allowance
	if t.allowances[owner] == nil || t.allowances[owner][spender] < amount {
		err := errors.New("allowance exceeded")
		log.Printf("TransferFrom failed: %v (allowance: %d, requested: %d)",
			err, t.allowances[owner][spender], amount)
		return err
	}

	// Check balance
	if t.balances[owner] < amount {
		err := errors.New("insufficient balance")
		log.Printf("TransferFrom failed: %v (balance: %d, requested: %d)",
			err, t.balances[owner], amount)
		return err
	}

	// Overflow protection for recipient
	if t.balances[to] > ^uint64(0)-amount {
		err := errors.New("transfer amount causes recipient balance overflow")
		log.Printf("TransferFrom failed: %v", err)
		return err
	}

	// Store old values for event metadata
	oldOwnerBalance := t.balances[owner]
	oldToBalance := t.balances[to]
	oldAllowance := t.allowances[owner][spender]

	// Execute transfer
	t.balances[owner] -= amount
	t.balances[to] += amount
	t.allowances[owner][spender] -= amount

	// Emit transfer event with enhanced metadata
	event := Event{
		Type:      EventTransfer,
		From:      owner,
		To:        to,
		Amount:    amount,
		Timestamp: time.Now(),
		TxHash:    t.generateTxHash("transferFrom", owner+":"+to, amount),
		Metadata: map[string]interface{}{
			"spender":            spender,
			"owner_old_balance":  oldOwnerBalance,
			"owner_new_balance":  t.balances[owner],
			"to_old_balance":     oldToBalance,
			"to_new_balance":     t.balances[to],
			"old_allowance":      oldAllowance,
			"new_allowance":      t.allowances[owner][spender],
			"transfer_type":      "delegated",
		},
	}
	t.emitEvent(event)

	log.Printf("TransferFrom successful: %s[%d→%d], %s[%d→%d], allowance[%d→%d]",
		owner, oldOwnerBalance, t.balances[owner],
		to, oldToBalance, t.balances[to],
		oldAllowance, t.allowances[owner][spender])
	return nil
}