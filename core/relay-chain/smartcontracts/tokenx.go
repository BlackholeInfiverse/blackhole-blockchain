package smartcontract

import (
	"errors"
	"sync"
	"time"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

type TokenXContract struct {
	bc          *chain.Blockchain
	name        string
	symbol      string
	decimals    uint8
	totalSupply uint64
	balances    map[string]uint64
	allowances  map[string]map[string]uint64
	admin       string
	mu          sync.RWMutex
}

func NewTokenXContract(bc *chain.Blockchain, admin string) *TokenXContract {
	return &TokenXContract{
		bc:          bc,
		name:        "BlackHole",
		symbol:      "BLH",
		decimals:    18,
		totalSupply: 1000000000,
		balances:    make(map[string]uint64),
		allowances:  make(map[string]map[string]uint64),
		admin:       admin,
	}
}

func (t *TokenXContract) Mint(to string, amount uint64, caller string) error {
	if caller != t.admin {
		return errors.New("only admin can mint")
	}
	if amount == 0 {
		return errors.New("amount must be > 0")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Prevent overflow
	if t.balances[to] > ^uint64(0)-amount || t.totalSupply > ^uint64(0)-amount {
		return errors.New("overflow")
	}

	t.balances[to] += amount
	t.totalSupply += amount

	// Create transaction and block
	tx := chain.NewTransaction("mint", "", to, amount)
	block := &chain.Block{
		Header: chain.BlockHeader{
			Index:        t.bc.GetLatestBlock().Header.Index + 1,
			Timestamp:    time.Now(),
			PreviousHash: t.bc.GetLatestBlock().CalculateHash(),
			Validator:    t.admin,
		},
		Transactions: []*chain.Transaction{tx},
	}
	t.bc.AddBlock(block)
	return nil
}

func (t *TokenXContract) Transfer(from, to string, amount uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.balances[from] < amount {
		return errors.New("insufficient balance")
	}

	t.balances[from] -= amount
	t.balances[to] += amount

	tx := chain.NewTransaction("transfer", from, to, amount)
	block := &chain.Block{
		Header: chain.BlockHeader{
			Index:        t.bc.GetLatestBlock().Header.Index + 1,
			Timestamp:    time.Now(),
			PreviousHash: t.bc.GetLatestBlock().CalculateHash(),
			Validator:    from,
		},
		Transactions: []*chain.Transaction{tx},
	}
	t.bc.AddBlock(block)
	return nil
}

func (t *TokenXContract) Burn(from string, amount uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.balances[from] < amount {
		return errors.New("insufficient balance")
	}

	t.balances[from] -= amount
	t.totalSupply -= amount

	tx := chain.NewTransaction("burn", from, "", amount)
	block := &chain.Block{
		Header: chain.BlockHeader{
			Index:        t.bc.GetLatestBlock().Header.Index + 1,
			Timestamp:    time.Now(),
			PreviousHash: t.bc.GetLatestBlock().CalculateHash(),
			Validator:    from,
		},
		Transactions: []*chain.Transaction{tx},
	}
	t.bc.AddBlock(block)
	return nil
}

func (t *TokenXContract) Approve(owner, spender string, amount uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.allowances[owner] == nil {
		t.allowances[owner] = make(map[string]uint64)
	}
	t.allowances[owner][spender] = amount

	tx := chain.NewTransaction("approve", owner, spender, amount)
	block := &chain.Block{
		Header: chain.BlockHeader{
			Index:        t.bc.GetLatestBlock().Header.Index + 1,
			Timestamp:    time.Now(),
			PreviousHash: t.bc.GetLatestBlock().CalculateHash(),
			Validator:    owner,
		},
		Transactions: []*chain.Transaction{tx},
	}
	t.bc.AddBlock(block)
	return nil
}

func (t *TokenXContract) Allowance(owner, spender string) (uint64, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.allowances[owner] == nil {
		return 0, nil
	}
	return t.allowances[owner][spender], nil
}

func (t *TokenXContract) TransferFrom(owner, spender, to string, amount uint64) error {
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

	tx := chain.NewTransaction("transferFrom", owner, to, amount)
	block := &chain.Block{
		Header: chain.BlockHeader{
			Index:        t.bc.GetLatestBlock().Header.Index + 1,
			Timestamp:    time.Now(),
			PreviousHash: t.bc.GetLatestBlock().CalculateHash(),
			Validator:    spender,
		},
		Transactions: []*chain.Transaction{tx},
	}
	t.bc.AddBlock(block)
	return nil
}

func (t *TokenXContract) BalanceOf(address string) uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.balances[address]
}