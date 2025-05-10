package token

import(
	"errors"
)

func (t *Token) TotalSupply() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.totalSupply
}

func (t *Token) BalanceOf(address string) (uint64, error) {
	if !t.validateAddress(address) {
		return 0, errors.New("invalid address")
	}

	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.balances[address], nil
}