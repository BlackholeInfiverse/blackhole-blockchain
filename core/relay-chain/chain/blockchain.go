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

	currentTip := bc.Blocks[len(bc.Blocks)-1]
	expectedIndex := currentTip.Header.Index + 1

	// CASE: Block is stale (already behind tip)
	if block.Header.Index < currentTip.Header.Index {
		fmt.Printf("⚠️ Stale block %d ignored (current chain height is %d)\n", block.Header.Index, currentTip.Header.Index)
		return false
	}

	// CASE: Block at current height (possible fork)
	if block.Header.Index == currentTip.Header.Index {
		fmt.Printf("🔍 Fork detected at index %d\n", block.Header.Index)

		if block.Hash == currentTip.Hash {
			fmt.Println("✅ Identical block already exists")
			return true
		}

		// Compare stake or hash to resolve fork
		if block.Header.PreviousHash == currentTip.Header.PreviousHash {
			fmt.Println("🔄 Competing block found at same height with same parent")

			if block.Header.StakeSnapshot > currentTip.Header.StakeSnapshot ||
				(block.Header.StakeSnapshot == currentTip.Header.StakeSnapshot && block.Hash < currentTip.Hash) {
				fmt.Println("🔁 Fork wins, switching to better block")
				return bc.reorganizeToFork([]*Block{block})
			}

			fmt.Println("🚫 Fork loses, ignoring")
			return false
		}

		// Deep fork (diverges earlier)
		return bc.handleFork(block)
	}

	// CASE: Block is ahead of tip (future block)
	if block.Header.Index > expectedIndex {
		fmt.Printf("⏳ Future block received (current %d < block %d), queuing\n", expectedIndex, block.Header.Index)
		bc.pendingBlocks[block.Header.Index] = block
		bc.requestMissingBlocks(expectedIndex, block.Header.Index-1)
		return false
	}

	// CASE: Normal append to tip
	if block.Header.PreviousHash != currentTip.Hash {
		fmt.Printf("❌ Invalid previous hash at height %d. Expected %s, got %s\n", block.Header.Index, currentTip.Hash, block.Header.PreviousHash)
		return false
	}

	if block.CalculateHash() != block.Hash {
		fmt.Printf("❌ Invalid block hash at height %d\n", block.Header.Index)
		return false
	}

	for _, tx := range block.Transactions {
		if !tx.Verify() {
			fmt.Printf("❌ Invalid transaction: %s\n", tx.ID)
			return false
		}
	}

	// Add block normally
	bc.Blocks = append(bc.Blocks, block)
	bc.PendingTxs = make([]*Transaction, 0)
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

// GetLatestBlock returns the most recent block in the blockchain
func (bc *Blockchain) GetLatestBlock() *Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if len(bc.Blocks) == 0 {
		return nil
	}
	return bc.Blocks[len(bc.Blocks)-1]
}

// GetChainEndingWith finds and validates a chain ending with the specified block
func (bc *Blockchain) GetChainEndingWith(block *Block) []*Block {
	// Temporary map to build the chain
	chainMap := make(map[string]*Block)
	currentHash := block.CalculateHash()
	chainMap[currentHash] = block

	// Walk backwards through previous hashes
	current := block
	for {
		// Check if we've reached genesis block
		if current.Header.PreviousHash == "" {
			break
		}

		// Try to find previous block in our database
		prevBlock, err := bc.GetBlockByPreviousHash(current.Header.PreviousHash)
		if err != nil {
			return nil // Previous block not found
		}

		// Verify block links
		if prevBlock.CalculateHash() != current.Header.PreviousHash {
			return nil // Invalid link
		}

		chainMap[prevBlock.CalculateHash()] = prevBlock
		current = prevBlock
	}

	// Convert map to ordered slice
	var chain []*Block
	current = block
	for {
		chain = append([]*Block{current}, chain...)
		if current.Header.PreviousHash == "" {
			break
		}
		current = chainMap[current.Header.PreviousHash]
	}

	return chain
}

// GetBlockByPreviousHash finds a block by what it claims to be its own hash
func (bc *Blockchain) GetBlockByPreviousHash(prevHash string) (*Block, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	for _, block := range bc.Blocks {
		if block.CalculateHash() == prevHash {
			return block, nil
		}
	}

	return nil, fmt.Errorf("block not found")
}

// Reorganize switches to a longer valid chain
func (bc *Blockchain) Reorganize(newChain []*Block) bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Validate the entire new chain
	for i, block := range newChain {
		// Skip genesis block
		if i == 0 {
			if block.Header.PreviousHash != "" {
				return false // Genesis block shouldn't have previous hash
			}
			continue
		}

		// Check block links
		prevBlockHash := newChain[i-1].CalculateHash()
		if block.Header.PreviousHash != prevBlockHash {
			return false
		}

	}

	// Only reorganize if new chain is longer
	if len(newChain) <= len(bc.Blocks) {
		return false
	}

	// Switch to new chain
	bc.Blocks = newChain
	return true
}

// func (bc *Blockchain) handleFork(newBlock *Block) bool {
// 	fmt.Printf("🔄 Handling fork for block %d with hash %s\n", newBlock.Header.Index, newBlock.Hash)

// 	// Special case: If the new block is at the same index as our latest block,
// 	// we need to replace our latest block with the new one
// 	if len(bc.Blocks) > 0 && newBlock.Header.Index == bc.Blocks[len(bc.Blocks)-1].Header.Index {
// 		// Find the previous block (the common ancestor)
// 		if len(bc.Blocks) < 2 {
// 			fmt.Printf("❌ Cannot handle fork: not enough blocks in chain\n")
// 			return false
// 		}

// 		prevBlock := bc.Blocks[len(bc.Blocks)-2]

// 		// Verify that the new block links to the previous block
// 		if newBlock.Header.PreviousHash != prevBlock.Hash {
// 			fmt.Printf("❌ Fork block has invalid previous hash: %s, expected: %s\n",
// 				newBlock.Header.PreviousHash, prevBlock.Hash)
// 			return false
// 		}

// 		// Replace the last block with the new block
// 		bc.Blocks = bc.Blocks[:len(bc.Blocks)-1] // Remove the last block
// 		bc.Blocks = append(bc.Blocks, newBlock)  // Add the new block

// 		fmt.Printf("✅ Replaced block at index %d with new block (hash: %s)\n",
// 			newBlock.Header.Index, newBlock.Hash)
// 		return true
// 	}

// 	// General case: Find the common ancestor
// 	var commonAncestorIndex int = -1

// 	// First try to find the block that matches the previous hash of the new block
// 	for i, block := range bc.Blocks {
// 		if block.Hash == newBlock.Header.PreviousHash {
// 			commonAncestorIndex = i
// 			break
// 		}
// 	}

// 	// If we couldn't find a direct match, try to find a block at the previous index
// 	if commonAncestorIndex == -1 && newBlock.Header.Index > 0 {
// 		for i, block := range bc.Blocks {
// 			if block.Header.Index == newBlock.Header.Index-1 {
// 				// Found a block at the previous index, but it has a different hash
// 				fmt.Printf("⚠️ Found block at index %d but hash doesn't match: %s vs %s\n",
// 					block.Header.Index, block.Hash, newBlock.Header.PreviousHash)

// 				// If this block has lower stake than the new block, we should reorganize
// 				// starting from an earlier point
// 				if block.Header.StakeSnapshot < newBlock.Header.StakeSnapshot {
// 					// Find the earliest block with index less than the fork point
// 					for j := i; j >= 0; j-- {
// 						if bc.Blocks[j].Header.Index < block.Header.Index-1 {
// 							commonAncestorIndex = j
// 							break
// 						}
// 					}

// 					if commonAncestorIndex == -1 {
// 						// If we couldn't find an earlier block, use the genesis block
// 						commonAncestorIndex = 0
// 					}

// 					fmt.Printf("🔄 Reorganizing chain from block %d due to higher stake\n",
// 						bc.Blocks[commonAncestorIndex].Header.Index)

// 					// Request missing blocks to build the new chain
// 					bc.pendingBlocks[newBlock.Header.Index] = newBlock
// 					bc.requestMissingBlocks(bc.Blocks[commonAncestorIndex].Header.Index+1, newBlock.Header.Index-1)
// 					return false
// 				}
// 			}
// 		}
// 	}

// 	if commonAncestorIndex == -1 {
// 		fmt.Printf("❌ Cannot find common ancestor for fork block %d\n", newBlock.Header.Index)
// 		return false
// 	}

// 	fmt.Printf("🔍 Found common ancestor at block %d (hash: %s)\n",
// 		bc.Blocks[commonAncestorIndex].Header.Index, bc.Blocks[commonAncestorIndex].Hash)

// 	// Create a new chain with blocks up to the common ancestor
// 	newChain := make([]*Block, commonAncestorIndex+1)
// 	copy(newChain, bc.Blocks[:commonAncestorIndex+1])

// 	// Add the new block to the chain
// 	newChain = append(newChain, newBlock)

// 	// Validate the new chain
// 	for i := 1; i < len(newChain); i++ {
// 		if newChain[i].Header.PreviousHash != newChain[i-1].Hash {
// 			fmt.Printf("❌ Invalid chain during fork resolution at block %d\n", newChain[i].Header.Index)
// 			return false
// 		}
// 	}

// 	// Calculate total stake for both chains
// 	var oldChainStake uint64
// 	var newChainStake uint64

// 	for _, block := range bc.Blocks {
// 		oldChainStake += block.Header.StakeSnapshot
// 	}

// 	for _, block := range newChain {
// 		newChainStake += block.Header.StakeSnapshot
// 	}

// 	fmt.Printf("📊 Chain comparison - Old chain stake: %d, New chain stake: %d\n",
// 		oldChainStake, newChainStake)

// 	// Only reorganize if the new chain has higher stake or equal stake with lower hash
// 	if newChainStake > oldChainStake ||
// 		(newChainStake == oldChainStake && newBlock.Hash < bc.Blocks[len(bc.Blocks)-1].Hash) {
// 		// Replace our chain with the new chain
// 		bc.Blocks = newChain
// 		bc.PendingTxs = make([]*Transaction, 0) // Clear pending transactions
// 		fmt.Printf("✅ Chain reorganized to follow fork at block %d\n", newBlock.Header.Index)
// 		return true
// 	} else {
// 		fmt.Printf("⚠️ Rejecting fork: new chain has lower stake or higher hash\n")
// 		return false
// 	}
// }

func (bc *Blockchain) handleFork(forkBlock *Block) bool {
	chain := bc.reconstructChain(forkBlock)
	if chain == nil || len(chain) <= len(bc.Blocks) {
		fmt.Println("🚫 Forked chain is not longer, discarding")
		return false
	}
	return bc.reorganizeToFork(chain)
}

func (bc *Blockchain) reorganizeToFork(newChain []*Block) bool {
	// Validate entire chain
	for i, block := range newChain {
		if !block.IsValid() || block.CalculateHash() != block.Hash {
			fmt.Printf("❌ Invalid block at position %d in forked chain\n", i)
			return false
		}
	}

	// Replace current chain
	bc.Blocks = newChain
	fmt.Println("✅ Chain reorganized to better fork")
	bc.PendingTxs = []*Transaction{}
	return true
}

func (bc *Blockchain) reconstructChain(block *Block) []*Block {
	// Walk back from the given block to genesis using known blocks or peer requests
	chain := []*Block{block}
	current := block

	for {
		if current.Header.Index == 0 {
			break // Genesis
		}

		parent, _ := bc.GetBlockByPreviousHash(current.Header.PreviousHash)
		if parent == nil {
			fmt.Printf("❌ Missing parent for block %d\n", current.Header.Index)
			return nil
		}

		chain = append([]*Block{parent}, chain...)
		current = parent
	}

	return chain
}
