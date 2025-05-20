package chain

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Blockchain struct {
	Blocks      []*Block
	PendingTxs  []*Transaction
	StakeLedger *StakeLedger
	P2PNode     *Node
	mu          sync.RWMutex
	GenesisTime time.Time
	TotalSupply uint64
	BlockReward uint64
}

func NewBlockchain(p2pPort int) (*Blockchain, error) {
	genesis := createGenesisBlock()

	// Initialize P2P node
	node, err := NewNode(context.Background(), p2pPort)
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
	block := NewBlock(
		0,
		[]*Transaction{},
		"0000000000000000000000000000000000000000000000000000000000000000",
		"genesis-validator",
		1000,
	)

	block.Header.Timestamp = time.Date(2025, 5, 15, 7, 55, 0, 0, time.UTC)
	block.Header.MerkleRoot = block.CalculateMerkleRoot()
	block.Hash = block.CalculateHash()

	return block
}

func (bc *Blockchain) MineBlock(selectedValidator string) *Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	// Get current index
	index := uint64(len(bc.Blocks))

	// Get previous block's hash
	var prevHash string
	if len(bc.Blocks) > 0 {
		prevHash = bc.Blocks[len(bc.Blocks)-1].Hash
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

	// DO NOT modify blockchain state here!
	return block
}

func (bc *Blockchain) AddBlock(block *Block) bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	fmt.Printf("🧪 Validating block %d\n", block.Header.Index)

	if len(bc.Blocks) == 0 {
		fmt.Println("❌ Blockchain is empty, expected genesis block")
		return false
	}

	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	if block.Header.Index != prevBlock.Header.Index+1 {
		fmt.Printf("❌ Invalid block index: got %d, expected %d\n", block.Header.Index, prevBlock.Header.Index+1)
		return false
	}

	if block.Header.PreviousHash != prevBlock.Hash {
		fmt.Printf("❌ Invalid previous hash: got %s, expected %s\n", block.Header.PreviousHash, prevBlock.Hash)
		return false
	}

	computedHash := block.CalculateHash()
	if block.Hash != computedHash {
		fmt.Printf("❌ Invalid block hash: got %s, expected %s\n", block.Hash, computedHash)
		return false
	}

	for _, tx := range block.Transactions {
		if !tx.Verify() {
			fmt.Println("❌ Invalid transaction in block:", tx.ID)
			return false
		}
	}

	bc.Blocks = append(bc.Blocks, block)
	fmt.Printf("✅ Block %d added successfully\n", block.Header.Index)
	return true
}
 
func (bc *Blockchain) BroadcastTransaction(tx *Transaction) {
	data, _ := tx.Serialize()
	msg := &Message{
		Type: MessageTypeTx,
		Data: data.([]byte),
	}
	bc.P2PNode.Broadcast(msg)
}

func (bc *Blockchain) BroadcastBlock(block *Block) {
	data := block.Serialize()
	msg := &Message{
		Type: MessageTypeBlock,
		Data: data,
	}
	bc.P2PNode.Broadcast(msg)
}

func (bc *Blockchain) SyncChain() {
	msg := &Message{
		Type: MessageTypeSyncReq,
		Data: []byte{},
	}
	bc.P2PNode.Broadcast(msg)
}
