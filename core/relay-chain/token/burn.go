package token

import(
	"errors"
)

func (t *Token) Burn(from string, amount uint64) error {
	if !t.validateAddress(from) {
		return errors.New("invalid address")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.balances[from] < amount {
		return errors.New("insufficient balance")
	}

	t.balances[from] -= amount
	t.totalSupply -= amount

	// Emit event
	t.emitEvent(Event{
		Type:   EventBurn,
		From:   from,
		Amount: amount,
	})
	return nil
}