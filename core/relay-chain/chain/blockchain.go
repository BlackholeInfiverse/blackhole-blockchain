package chain

import (
	"sync"
	"time"
	"crypto/ecdsa"
)

type Blockchain struct {
	Blocks       []*Block
	StakeLedger  map[string]*ValidatorStake
	PendingTxs   []*Transaction
	mu           sync.RWMutex
	GenesisTime  time.Time
	TotalSupply  uint64
	BlockReward  uint64
}

type ValidatorStake struct {
	Amount    uint64
	PublicKey *ecdsa.PublicKey
}

func NewBlockchain() *Blockchain {
	genesis := createGenesisBlock()
	
	return &Blockchain{
		Blocks:      []*Block{genesis},
		StakeLedger: make(map[string]*ValidatorStake),
		PendingTxs:  make([]*Transaction, 0),
		GenesisTime: time.Now().UTC(),
		TotalSupply: 1000000000, // 1 billion tokens
		BlockReward: 10,         // 10 tokens per block
	}
}

func createGenesisBlock() *Block {
	genesisTxs := []*Transaction{
		{
			ID:        "genesis_tx_1",
			Type:      "GENESIS",
			From:      "0",
			To:        "foundation",
			Amount:    1000000000,
			Timestamp: time.Now().Unix(),
		},
	}
	
	return &Block{
		Header: BlockHeader{
			Index:         0,
			Timestamp:     time.Now().UTC(),
			PreviousHash:  "0",
			Validator:     "genesis_validator",
			StakeSnapshot: 0,
			MerkleRoot:    "",
		},
		Transactions: genesisTxs,
	}
}

func (bc *Blockchain) AddTransaction(tx *Transaction, publicKey *ecdsa.PublicKey) bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	
	if !tx.Verify(publicKey) {
		return false
	}
	
	bc.PendingTxs = append(bc.PendingTxs, tx)
	return true
}

func (bc *Blockchain) MineBlock(validator string, validatorPubKey *ecdsa.PublicKey) *Block {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	
	lastBlock := bc.Blocks[len(bc.Blocks)-1]
	
	// Create coinbase transaction (block reward)
	rewardTx := &Transaction{
		ID:        "",
		Type:      "BLOCK_REWARD",
		From:      "0",
		To:        validator,
		Amount:    bc.BlockReward,
		Timestamp: time.Now().Unix(),
	}
	rewardTx.ID = rewardTx.CalculateHash()
	
	// Get pending transactions (limit block size)
	var blockTxs []*Transaction
	if len(bc.PendingTxs) > 100 {
		blockTxs = bc.PendingTxs[:100]
		bc.PendingTxs = bc.PendingTxs[100:]
	} else {
		blockTxs = bc.PendingTxs
		bc.PendingTxs = make([]*Transaction, 0)
	}
	
	// Prepend reward transaction
	blockTxs = append([]*Transaction{rewardTx}, blockTxs...)
	
	// Calculate total stake
	totalStake := uint64(0)
	for _, stake := range bc.StakeLedger {
		totalStake += stake.Amount
	}
	
	// Create new block
	newBlock := NewBlock(
		lastBlock.Header.Index+1,
		blockTxs,
		lastBlock.CalculateHash(),
		validator,
		totalStake,
	)
	
	bc.Blocks = append(bc.Blocks, newBlock)
	bc.TotalSupply += bc.BlockReward // Inflationary model
	
	return newBlock
}

func (bc *Blockchain) StakeTokens(validator string, amount uint64, publicKey *ecdsa.PublicKey) bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	
	if _, exists := bc.StakeLedger[validator]; !exists {
		bc.StakeLedger[validator] = &ValidatorStake{
			Amount:    0,
			PublicKey: publicKey,
		}
	}
	
	bc.StakeLedger[validator].Amount += amount
	return true
}