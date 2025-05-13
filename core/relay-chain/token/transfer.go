package token

import(
	"errors"
)

func (t *Token) Transfer(from, to string, amount uint64) error {
	if !t.validateAddress(from) || !t.validateAddress(to) {
		return errors.New("invalid address")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.balances[from] < amount {
		return errors.New("insufficient balance")
	}

	t.balances[from] -= amount
	t.balances[to] += amount

	// Emit event
	t.emitEvent(Event{
		Type:   EventTransfer,
		From:   from,
		To:     to,
		Amount: amount,
	})
	return nil
}