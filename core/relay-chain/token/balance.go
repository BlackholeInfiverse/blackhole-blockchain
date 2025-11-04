package token

import (
	"errors"
)

func (t *Token) TotalSupply() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.totalSupply
}

// MaxSupply returns the maximum supply limit
func (t *Token) MaxSupply() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.maxSupply
}

// CirculatingSupply calculates the actual circulating supply
func (t *Token) CirculatingSupply() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	supply := uint64(0)
	for _, balance := range t.balances {
		supply += balance
	}
	return supply
}

func (t *Token) BalanceOf(address string) (uint64, error) {
	if !t.validateAddress(address) {
		return 0, errors.New("invalid address")
	}

	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.balances[address], nil
}

// SetBalance sets the balance for an address (used for loading from persistence)
func (t *Token) SetBalance(address string, balance uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.balances[address] = balance
}

// GetAllBalances returns a copy of all balances (used for saving to persistence)
func (t *Token) GetAllBalances() map[string]uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	balances := make(map[string]uint64)
	for addr, balance := range t.balances {
		balances[addr] = balance
	}
	return balances
}

// GetAllAddressesWithBalances returns all addresses that have non-zero balances
func (t *Token) GetAllAddressesWithBalances() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	addresses := make([]string, 0, len(t.balances))
	for addr, balance := range t.balances {
		if balance > 0 {
			addresses = append(addresses, addr)
		}
	}
	return addresses
}
