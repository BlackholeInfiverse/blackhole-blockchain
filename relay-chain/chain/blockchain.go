package chain

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

type Blockchain struct {
	Blocks        []*Block
	PendingTxs    []*Transaction
	StakeLedger   *StakeLedger
	P2PNode       *Node
	mu            sync.RWMutex
	GenesisTime   time.Time
	TotalSupply   uint64
	BlockReward   uint64
	pendingBlocks map[uint64]*Block
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
		Blocks:        []*Block{genesis},
		PendingTxs:    make([]*Transaction, 0),
		StakeLedger:   stakeLedger,
		P2PNode:       node,
		GenesisTime:   time.Now().UTC(),
		TotalSupply:   1000000000,
		BlockReward:   10,
		pendingBlocks: make(map[uint64]*Block),
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

	fmt.Printf("🧪 Validating block %d, Hash=%s, PrevHash=%s\n", block.Header.Index, block.Hash, block.Header.PreviousHash)

	if len(bc.Blocks) == 0 {
		fmt.Println("❌ Blockchain is empty, expected genesis block")
		return false
	}

	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	expectedIndex := prevBlock.Header.Index + 1

	// Handle chain reorganization for higher-stake chain
	if block.Header.Index >= expectedIndex {
		currentStake := bc.calculateCumulativeStake()
		if block.Header.StakeSnapshot > currentStake {
			fmt.Printf("📤 Detected higher-stake chain at index %d, requesting blocks 1 to %d\n", block.Header.Index, block.Header.Index)
			bc.pendingBlocks[block.Header.Index] = block
			bc.requestMissingBlocks(1, block.Header.Index)
			return false
		}
		if block.Header.Index > expectedIndex {
			fmt.Printf("📤 Queuing block %d and requesting missing blocks %d to %d\n", block.Header.Index, expectedIndex, block.Header.Index-1)
			bc.pendingBlocks[block.Header.Index] = block
			bc.requestMissingBlocks(expectedIndex, block.Header.Index-1)
			return false
		}
	} else {
		fmt.Printf("⚠️ Ignoring stale block %d (chain already at %d)\n", block.Header.Index, prevBlock.Header.Index)
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
			fmt.Printf("❌ Invalid transaction in block: %s\n", tx.ID)
			return false
		}
	}

	bc.Blocks = append(bc.Blocks, block)
	bc.PendingTxs = make([]*Transaction, 0) // Clear pending transactions
	fmt.Printf("✅ Block %d added successfully\n", block.Header.Index)

	// Process queued blocks
	for {
		nextBlock, exists := bc.pendingBlocks[expectedIndex+1]
		if !exists {
			break
		}
		fmt.Printf("🧪 Attempting to add queued block %d\n", nextBlock.Header.Index)
		if nextBlock.Header.PreviousHash == block.Hash && nextBlock.CalculateHash() == nextBlock.Hash {
			bc.Blocks = append(bc.Blocks, nextBlock)
			bc.PendingTxs = make([]*Transaction, 0)
			fmt.Printf("✅ Queued block %d added successfully\n", nextBlock.Header.Index)
			delete(bc.pendingBlocks, nextBlock.Header.Index)
			expectedIndex++
			block = nextBlock
		} else {
			fmt.Printf("❌ Queued block %d invalid, discarding\n", nextBlock.Header.Index)
			delete(bc.pendingBlocks, nextBlock.Header.Index)
			break
		}
	}

	return true
}

func (bc *Blockchain) calculateCumulativeStake() uint64 {
	var totalStake uint64
	for _, block := range bc.Blocks {
		totalStake += block.Header.StakeSnapshot
	}
	return totalStake
}

func (bc *Blockchain) reorganizeChain(blocks []*Block) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Validate and replace chain
	newBlocks := []*Block{bc.Blocks[0]} // Keep genesis block
	for _, block := range blocks {
		if len(newBlocks) > 0 {
			prevBlock := newBlocks[len(newBlocks)-1]
			if block.Header.PreviousHash != prevBlock.Hash || block.CalculateHash() != block.Hash {
				fmt.Printf("❌ Invalid block %d during reorganization\n", block.Header.Index)
				return
			}
		}
		newBlocks = append(newBlocks, block)
	}

	bc.Blocks = newBlocks
	bc.PendingTxs = make([]*Transaction, 0)
	fmt.Printf("✅ Reorganized chain to height %d\n", newBlocks[len(newBlocks)-1].Header.Index)
}

func (bc *Blockchain) requestMissingBlocks(startIndex, endIndex uint64) {
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[:8], startIndex)
	binary.BigEndian.PutUint64(data[8:], endIndex)
	msg := &Message{
		Type:    MessageTypeSyncReq,
		Data:    data,
		Version: ProtocolVersion,
	}
	bc.P2PNode.Broadcast(msg)
	fmt.Printf("📤 Requested blocks %d to %d\n", startIndex, endIndex)
}

func (bc *Blockchain) BroadcastTransaction(tx *Transaction) {
	data, _ := tx.Serialize()
	msg := &Message{
		Type:    MessageTypeTx,
		Data:    data.([]byte),
		Version: ProtocolVersion,
	}
	bc.P2PNode.Broadcast(msg)
}

func (bc *Blockchain) BroadcastBlock(block *Block) {
	data := block.Serialize()
	msg := &Message{
		Type:    MessageTypeBlock,
		Data:    data,
		Version: ProtocolVersion,
	}
	bc.P2PNode.Broadcast(msg)
}

func (bc *Blockchain) SyncChain() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Initial sync
	bc.mu.RLock()
	latestIndex := uint64(0)
	if len(bc.Blocks) > 0 {
		latestIndex = bc.Blocks[len(bc.Blocks)-1].Header.Index
	}
	bc.mu.RUnlock()
	bc.requestMissingBlocks(latestIndex+1, latestIndex+100)

	for {
		select {
		case <-ticker.C:
			bc.mu.RLock()
			latestIndex := uint64(0)
			if len(bc.Blocks) > 0 {
				latestIndex = bc.Blocks[len(bc.Blocks)-1].Header.Index
			}
			bc.mu.RUnlock()
			bc.requestMissingBlocks(latestIndex+1, latestIndex+100)
			fmt.Printf("📤 Sent sync request for blocks %d to %d\n", latestIndex+1, latestIndex+100)
		}
	}
}
