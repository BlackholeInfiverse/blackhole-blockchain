package chain

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
)

type AccountState struct {
	Balance uint64
	Nonce   uint64
}

type Blockchain struct {
	Blocks           []*Block
	PendingTxs       []*Transaction
	StakeLedger      *StakeLedger
	BlockReward      uint64
	mu               sync.RWMutex
	txPool           *TxPool
	validatorManager *ValidatorManager
	TokenRegistry    map[string]*token.Token
	P2PNode          *Node
	GenesisTime      time.Time
	TotalSupply      uint64
	pendingBlocks    map[uint64]*Block
	GlobalState      map[string]*AccountState
	DB               *leveldb.DB
}
type RealBlockchain struct {
	Blockchain *Blockchain // Pointer to the real blockchain
}

func NewBlockchain(p2pPort int) (*Blockchain, error) {
	genesis := createGenesisBlock()

	dbPath := fmt.Sprintf("blockchaindb_%d", p2pPort)
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}

	// Initialize P2P node
	node, err := NewNode(context.Background(), p2pPort)
	if err != nil {
		return nil, err
	}

	// Initialize stake ledger
	stakeLedger := NewStakeLedger()
	stakeLedger.SetStake("genesis-validator", 1000)

	bc := &Blockchain{
		Blocks:           []*Block{genesis},
		PendingTxs:       make([]*Transaction, 0),
		StakeLedger:      stakeLedger,
		P2PNode:          node,
		GenesisTime:      time.Now().UTC(),
		TotalSupply:      1000000000,
		BlockReward:      10,
		pendingBlocks:    make(map[uint64]*Block),
		GlobalState:      make(map[string]*AccountState),
		DB:               db,
		txPool:           &TxPool{Transactions: make([]*Transaction, 0)},
		validatorManager: NewValidatorManager(stakeLedger),
		TokenRegistry:    make(map[string]*token.Token),
	}
	bc.GlobalState["system"] = &AccountState{
		Balance: 10000000, // same as genesis rewardTx.Amount
		Nonce:   0,
	}
	bc.GlobalState["03e2459b73c0c6522530f6b26e834d992dfc55d170bee35d0bcdc047fe0d61c25b"] = &AccountState{
		Balance: 1000, // give this wallet 1000 tokens initially
		Nonce:   0,
	}

	// Create native token - fix the NewToken call to match the signature
	nativeToken := token.NewToken("Blockchain Hex", "BHX", 18, 1000000000)
	bc.TokenRegistry["BHX"] = nativeToken

	// Optional: Load GlobalState from DB
	bc.loadGlobalState()
	return bc, nil
}

func createGenesisBlock() *Block {
	rewardTx := &Transaction{
		ID:        "",
		Type:      TokenTransfer,
		From:      "system",
		To:        "genesis-validator",
		Amount:    10,
		TokenID:   "BHX", // Changed from Token to TokenID
		Fee:       0,
		Nonce:     0,
		Timestamp: time.Date(2025, 5, 15, 7, 55, 0, 0, time.UTC).Unix(),
		Signature: nil,
		PublicKey: nil,
	}
	rewardTx.ID = rewardTx.CalculateHash()

	block := NewBlock(
		0,
		[]*Transaction{rewardTx},
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
	fmt.Println("index: ", index)

	// Get previous block's hash
	var prevHash string
	if len(bc.Blocks) > 0 {
		prevHash = bc.Blocks[len(bc.Blocks)-1].Hash
	} else {
		prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	// Get stake snapshot for validator
	stake := bc.StakeLedger.GetStake(selectedValidator)

	// Create reward transaction from system to validator with correct fields
	rewardTx := &Transaction{
		ID:        "",
		Type:      TokenTransfer,
		From:      "system",
		To:        selectedValidator,
		Amount:    bc.BlockReward,
		TokenID:   "BHX",
		Fee:       0,
		Nonce:     0,
		Timestamp: time.Now().Unix(),
		Signature: nil, // system transaction usually unsigned
		PublicKey: nil, // no public key needed for system tx
	}
	rewardTx.ID = rewardTx.CalculateHash()

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

	// for _, tx := range block.Transactions {
	// 	if !tx.Verify() {
	// 		fmt.Printf("❌ Invalid transaction: %s\n", tx.ID)
	// 		return false
	// 	}
	// }

	for _, tx := range block.Transactions {
		success := bc.ApplyTransaction(tx)
		if !success {
			fmt.Println("Invalid tx in block, skipping:", tx)
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
func (bc *Blockchain) GetPendingTransactions() []*Transaction {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.PendingTxs
}

func (bc *Blockchain) GetBalance(addr string) uint64 {
	state, ok := bc.GlobalState[addr]
	if !ok {
		return 0
	}
	return state.Balance
}

func (bc *Blockchain) GetNonce(address string) uint64 {
	if acc, ok := bc.GlobalState[address]; ok {
		return acc.Nonce
	}
	return 0
}

func (bc *Blockchain) ProcessTransaction(tx *Transaction) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Validate basic transaction fields
	if tx.From == "" || tx.To == "" || tx.Amount <= 0 {
		return fmt.Errorf("invalid transaction: missing fields or negative amount")
	}

	// // Ensure sender exists
	// senderState, exists := bc.GlobalState[tx.From]
	// if !exists {
	// 	return fmt.Errorf("sender not found in global state")
	// }

	// // Validate nonce
	// if tx.Nonce != senderState.Nonce {
	// 	return fmt.Errorf("invalid nonce: expected %d, got %d", senderState.Nonce, tx.Nonce)
	// }

	// // Validate balance
	// if uint64(tx.Amount) > senderState.Balance {
	// 	return fmt.Errorf("insufficient balance")
	// }

	// Queue transaction for block inclusion
	bc.PendingTxs = append(bc.PendingTxs, tx)

	return nil
}
func (bc *Blockchain) getOrCreateAccount(address string) *AccountState {
	if state, exists := bc.GlobalState[address]; exists {
		return state
	}
	
	// Create new account with zero balance
	newState := &AccountState{
		Balance: 0,
		Nonce:   0,
	}
	bc.GlobalState[address] = newState
	return newState
}

func (bc *Blockchain) ApplyTransaction(tx *Transaction) bool {
	fmt.Println("🔄 Applying transaction:")
	fmt.Printf("   ➤ From: %s\n", tx.From)
	fmt.Printf("   ➤ To: %s\n", tx.To)
	fmt.Printf("   ➤ Amount: %d\n", tx.Amount)

	sender := tx.From
	receiver := tx.To
	amount := tx.Amount

	// Get or create sender account
	senderState := bc.getOrCreateAccount(sender)
	fmt.Printf("   📤 Sender '%s' balance before transaction: %d\n", sender, senderState.Balance)

	// Check for insufficient funds
	if senderState.Balance < amount {
		fmt.Printf("   ❌ Transaction failed: Insufficient funds (has %d, needs %d)\n", senderState.Balance, amount)
		return false
	}

	// Deduct from sender
	senderState.Balance -= amount
	bc.SetBalance(sender, senderState.Balance)
	fmt.Printf("   ✅ Sender '%s' balance after deduction: %d\n", sender, senderState.Balance)

	// Get or create receiver account
	receiverState := bc.getOrCreateAccount(receiver)
	fmt.Printf("   📥 Receiver '%s' balance before transaction: %d\n", receiver, receiverState.Balance)

	// Add to receiver
	receiverState.Balance += amount
	bc.SetBalance(receiver, receiverState.Balance)
	fmt.Printf("   ✅ Receiver '%s' balance after addition: %d\n", receiver, receiverState.Balance)

	fmt.Println("✅ Transaction applied successfully")
	return true
}

func (bc *Blockchain) SetBalance(addr string, balance uint64) {
	state, ok := bc.GlobalState[addr]
	if !ok {
		state = &AccountState{}
	}
	state.Balance = balance
	bc.GlobalState[addr] = state
	_ = bc.SaveAccountState(addr, state)
}

func (bc *Blockchain) SaveAccountState(addr string, state *AccountState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return bc.DB.Put([]byte("account:"+addr), data, nil)
}
func (bc *Blockchain) LoadAccountState(addr string) (*AccountState, error) {
	data, err := bc.DB.Get([]byte("account:"+addr), nil)
	if err != nil {
		return nil, err
	}

	var state AccountState
	err = json.Unmarshal(data, &state)
	if err != nil {
		return nil, err
	}

	return &state, nil
}

func (bc *Blockchain) loadGlobalState() {
	iter := bc.DB.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		if len(key) >= 8 && key[:8] == "account:" {
			addr := key[8:]
			var state AccountState
			err := json.Unmarshal(iter.Value(), &state)
			if err == nil {
				bc.GlobalState[addr] = &state
			}
		}
	}

	if err := iter.Error(); err != nil {
		log.Println("Error loading global state:", err)
	}
}

func (bc *Blockchain) ValidateTransaction(tx *Transaction) error {
	// Existing validation...
	
	// Token-specific validation
	if tx.Type == TokenTransfer || tx.Type == StakeDeposit || tx.Type == StakeWithdraw {
		token, exists := bc.TokenRegistry[tx.TokenID]
		if !exists {
			return errors.New("token not found")
		}
		
		// Check token balance
		balance, err := token.BalanceOf(tx.From)
		if err != nil {
			return err
		}
		
		if balance < tx.Amount {
			return errors.New("insufficient token balance")
		}
	}
	
	return nil
}

func (bc *Blockchain) processTransaction(tx *Transaction) error {
	switch tx.Type {
	case RegularTransfer:
		// Process regular transfer
		// ...
	case TokenTransfer:
		token, exists := bc.TokenRegistry[tx.TokenID]
		if !exists {
			return errors.New("token not found")
		}
		return token.Transfer(tx.From, tx.To, tx.Amount)
	case StakeDeposit:
		token, exists := bc.TokenRegistry[tx.TokenID]
		if !exists {
			return errors.New("token not found")
		}
		// Transfer tokens to staking contract
		if err := token.Transfer(tx.From, "staking_contract", tx.Amount); err != nil {
			return err
		}
		// Update stake ledger
		bc.StakeLedger.AddStake(tx.From, tx.Amount)
		return nil
	case StakeWithdraw:
		// Implement stake withdrawal logic
		// ...
	}
	return nil
}
