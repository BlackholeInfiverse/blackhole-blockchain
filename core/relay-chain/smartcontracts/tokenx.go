package smartcontract

import (
    "errors"
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
    admin       string // Admin address for minting
}

func NewTokenXContract(bc *chain.Blockchain, admin string) *TokenXContract {
    return &TokenXContract{
        bc:          bc,
        name:        "BlackHole",
        symbol:      "BLH",
        decimals:    18,
        totalSupply: 1000000000, // 1 billion initial supply
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
    t.balances[to] += amount
    t.totalSupply += amount
    t.bc.AddBlock(chain.NewTransaction("mint", "", to, amount))
    return nil
}

func (t *TokenXContract) Transfer(from, to string, amount uint64) error {
    if t.balances[from] < amount {
        return errors.New("insufficient balance")
    }
    t.balances[from] -= amount
    t.balances[to] += amount
    t.bc.AddBlock(chain.NewTransaction("transfer", from, to, amount))
    return nil
}

func (t *TokenXContract) Burn(from string, amount uint64) error {
    if t.balances[from] < amount {
        return errors.New("insufficient balance")
    }
    t.balances[from] -= amount
    t.totalSupply -= amount
    t.bc.AddBlock(chain.NewTransaction("burn", from, "", amount))
    return nil
}

func (t *TokenXContract) BalanceOf(address string) uint64 {
    return t.balances[address]
}