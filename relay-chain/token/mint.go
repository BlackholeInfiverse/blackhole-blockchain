package token

import(
	"errors"
)

func (t *Token) Mint(to string, amount uint64) error {
	if !t.validateAddress(to) {
			return errors.New("invalid address")
	}
	if amount == 0 {
			return errors.New("amount must be > 0")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Overflow protection
	if t.balances[to] > ^uint64(0)-amount { // Check if addition would overflow
			return errors.New("mint amount causes balance overflow")
	}
	if t.totalSupply > ^uint64(0)-amount { // Check total supply overflow
			return errors.New("mint amount causes total supply overflow")
	}

	t.balances[to] += amount
	t.totalSupply += amount
	t.emitEvent(Event{Type: EventMint, To: to, Amount: amount})
	return nil
}