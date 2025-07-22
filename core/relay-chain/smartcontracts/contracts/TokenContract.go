package contracts

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"time"
)

// Event represents a contract event
type Event struct {
	Name      string
	Data      map[string]interface{}
	Timestamp time.Time
}

// TokenContract represents an ERC20-like token contract
type TokenContract struct {
	name        string
	symbol      string
	decimals    uint8
	totalSupply *big.Int
	balances    map[string]*big.Int
	allowances  map[string]map[string]*big.Int
	owner       string
	mu          sync.RWMutex
	events      []Event
}

// NewTokenContract creates a new token contract
func NewTokenContract(name, symbol string, decimals uint8, initialSupply *big.Int, owner string) *TokenContract {
	contract := &TokenContract{
		name:        name,
		symbol:      symbol,
		decimals:    decimals,
		totalSupply: new(big.Int).Set(initialSupply),
		balances:    make(map[string]*big.Int),
		allowances:  make(map[string]map[string]*big.Int),
		owner:       owner,
		events:      make([]Event, 0),
	}
	contract.balances[owner] = new(big.Int).Set(initialSupply)

	// Emit Transfer event for initial supply
	contract.emitEvent("Transfer", map[string]interface{}{
		"from":   "0x0",
		"to":     owner,
		"amount": initialSupply.String(),
	})

	return contract
}

// emitEvent adds a new event to the contract's event log
func (t *TokenContract) emitEvent(name string, data map[string]interface{}) {
	t.events = append(t.events, Event{
		Name:      name,
		Data:      data,
		Timestamp: time.Now(),
	})
}

// GetEvents returns all events
func (t *TokenContract) GetEvents() []Event {
	return t.events
}

// Name returns the token name
func (t *TokenContract) Name(_ context.Context) string {
	return t.name
}

// Symbol returns the token symbol
func (t *TokenContract) Symbol(_ context.Context) string {
	return t.symbol
}

// Decimals returns the number of decimals
func (t *TokenContract) Decimals(_ context.Context) uint8 {
	return t.decimals
}

// TotalSupply returns the total token supply
func (t *TokenContract) TotalSupply(_ context.Context) *big.Int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return new(big.Int).Set(t.totalSupply)
}

// BalanceOf returns the balance of a given address
func (t *TokenContract) BalanceOf(_ context.Context, address string) *big.Int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if balance, exists := t.balances[address]; exists {
		return new(big.Int).Set(balance)
	}
	return new(big.Int)
}

// Transfer tokens to a specified address
func (t *TokenContract) Transfer(_ context.Context, from, to string, amount *big.Int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}

	// Validate addresses
	if from == "" || to == "" {
		return errors.New("invalid address")
	}

	fromBalance, exists := t.balances[from]
	if !exists || fromBalance.Cmp(amount) < 0 {
		return errors.New("insufficient balance")
	}

	if _, exists := t.balances[to]; !exists {
		t.balances[to] = new(big.Int)
	}

	t.balances[from] = new(big.Int).Sub(fromBalance, amount)
	t.balances[to] = new(big.Int).Add(t.balances[to], amount)

	// Emit Transfer event
	t.emitEvent("Transfer", map[string]interface{}{
		"from":   from,
		"to":     to,
		"amount": amount.String(),
	})

	return nil
}

// Approve allows another address to spend tokens
func (t *TokenContract) Approve(_ context.Context, owner, spender string, amount *big.Int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Validate addresses
	if owner == "" || spender == "" {
		return errors.New("invalid address")
	}

	if _, exists := t.allowances[owner]; !exists {
		t.allowances[owner] = make(map[string]*big.Int)
	}
	t.allowances[owner][spender] = new(big.Int).Set(amount)

	// Emit Approval event
	t.emitEvent("Approval", map[string]interface{}{
		"owner":   owner,
		"spender": spender,
		"amount":  amount.String(),
	})

	return nil
}

// Allowance returns the amount of tokens approved for spending
func (t *TokenContract) Allowance(_ context.Context, owner, spender string) *big.Int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if ownerAllowances, exists := t.allowances[owner]; exists {
		if amount, exists := ownerAllowances[spender]; exists {
			return new(big.Int).Set(amount)
		}
	}
	return new(big.Int)
}

// TransferFrom transfers tokens from one address to another using allowance
func (t *TokenContract) TransferFrom(_ context.Context, from, to, spender string, amount *big.Int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}

	// Validate addresses
	if from == "" || to == "" || spender == "" {
		return errors.New("invalid address")
	}

	// Check allowance
	if ownerAllowances, exists := t.allowances[from]; !exists || ownerAllowances[spender].Cmp(amount) < 0 {
		return errors.New("insufficient allowance")
	}

	// Check balance
	fromBalance, exists := t.balances[from]
	if !exists || fromBalance.Cmp(amount) < 0 {
		return errors.New("insufficient balance")
	}

	// Update allowance
	t.allowances[from][spender] = new(big.Int).Sub(t.allowances[from][spender], amount)

	// Update balances
	t.balances[from] = new(big.Int).Sub(fromBalance, amount)
	if _, exists := t.balances[to]; !exists {
		t.balances[to] = new(big.Int)
	}
	t.balances[to] = new(big.Int).Add(t.balances[to], amount)

	// Emit Transfer event
	t.emitEvent("Transfer", map[string]interface{}{
		"from":   from,
		"to":     to,
		"amount": amount.String(),
	})

	return nil
}
