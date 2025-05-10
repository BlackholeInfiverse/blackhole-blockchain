package token

import "errors"

func (t *Token) Approve(owner, spender string, amount uint64) error {
	if !t.validateAddress(owner) || !t.validateAddress(spender) {
		return errors.New("invalid address")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.allowances[owner] == nil {
		t.allowances[owner] = make(map[string]uint64)
	}
	t.allowances[owner][spender] = amount
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
	if !t.validateAddress(owner) || !t.validateAddress(spender) || !t.validateAddress(to) {
		return errors.New("invalid address")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.allowances[owner][spender] < amount {
		return errors.New("allowance exceeded")
	}
	if t.balances[owner] < amount {
		return errors.New("insufficient balance")
	}

	t.balances[owner] -= amount
	t.balances[to] += amount
	t.allowances[owner][spender] -= amount

	// Emit event
	t.emitEvent(Event{
		Type:   EventTransfer,
		From:   owner,
		To:     to,
		Amount: amount,
	})
	return nil
}