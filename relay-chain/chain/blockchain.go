package chain

import (
	"context"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/p2p"
)

type Blockchain struct {
	Blocks      []*Block
	PendingTxs  []*Transaction
	StakeLedger *StakeLedger
	P2PNode     *p2p.Node
	mu          sync.RWMutex
	GenesisTime time.Time
	TotalSupply uint64
	BlockReward uint64
}

func NewBlockchain(p2pPort int) (*Blockchain, error) {
	genesis := createGenesisBlock()

	// Initialize P2P node
	node, err := p2p.NewNode(context.Background(), p2pPort)
	if err != nil {
		return nil, err
	}

	// Initialize stake ledger
	stakeLedger := NewStakeLedger()
	stakeLedger.SetStake("genesis-validator", 1000)

	bc := &Blockchain{
		Blocks:      []*Block{genesis},
		PendingTxs:  make([]*Transaction, 0),
		StakeLedger: stakeLedger,
		P2PNode:     node,
		GenesisTime: time.Now().UTC(),
		TotalSupply: 1000000000,
		BlockReward: 10,
	}

	return bc, nil
}

func createGenesisBlock() *Block {
	return NewBlock(
		0,
		[]*Transaction{},
		"0000000000000000000000000000000000000000000000000000000000000000",
		"genesis-validator",
		1000,
	)
}

func (bc *Blockchain) MineBlock(selectedValidator string) *Block {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Get current index
	index := uint64(len(bc.Blocks))

	// Get previous block's hash
	var prevHash string
	if len(bc.Blocks) > 0 {
		prevHash = bc.Blocks[len(bc.Blocks)-1].CalculateHash()
	} else {
		prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	// Get stake snapshot for validator
	stake := bc.StakeLedger.GetStake(selectedValidator)

	// Create reward transaction
	rewardTx := NewTransaction(
		TokenTransfer,
		"system",
		selectedValidator,
		bc.BlockReward,
	)

	// Combine reward transaction with pending transactions
	txs := append([]*Transaction{rewardTx}, bc.PendingTxs...)

	// Create new block
	block := NewBlock(index, txs, prevHash, selectedValidator, stake)

	// Add block to chain
	bc.Blocks = append(bc.Blocks, block)

	// Clear pending transactions
	bc.PendingTxs = make([]*Transaction, 0)

	// Update stake ledger with block reward
	bc.StakeLedger.AddStake(selectedValidator, bc.BlockReward)
	bc.TotalSupply += bc.BlockReward

	return block
}

func (bc *Blockchain) AddBlock(block *Block) bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Basic validation
	if len(bc.Blocks) == 0 {
		return false // Should have genesis block
	}

	lastBlock := bc.Blocks[len(bc.Blocks)-1]
	if block.Header.Index != uint64(len(bc.Blocks)) ||
		block.Header.PreviousHash != lastBlock.CalculateHash() {
		return false
	}

	// Update stake ledger for reward transaction
	for _, tx := range block.Transactions {
		if tx.From == "system" && tx.Type == TokenTransfer {
			bc.StakeLedger.AddStake(tx.To, tx.Amount)
		}
	}

	// Add block
	bc.Blocks = append(bc.Blocks, block)
	return true
}

func (bc *Blockchain) BroadcastTransaction(tx *Transaction) {
	data, _ := tx.Serialize()
	msg := &p2p.Message{
		Type: p2p.MessageTypeTx,
		Data: data.([]byte),
	}
	bc.P2PNode.Broadcast(msg)
}

func (bc *Blockchain) BroadcastBlock(block *Block) {
	data, _ := block.Serialize()
	msg := &p2p.Message{
		Type: p2p.MessageTypeBlock,
		Data: data.([]byte),
	}
	bc.P2PNode.Broadcast(msg)
}

func (bc *Blockchain) SyncChain() {
	msg := &p2p.Message{
		Type: p2p.MessageTypeSyncReq,
		Data: []byte{},
	}
	bc.P2PNode.Broadcast(msg)
}