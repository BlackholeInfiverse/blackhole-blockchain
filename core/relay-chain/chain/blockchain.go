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

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
	"github.com/syndtr/goleveldb/leveldb"
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
	DEX              interface{}
	EscrowManager    interface{}
	MultiSigManager  interface{}
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

	// Initialize some token balances for testing
	nativeToken.Mint("system", 10000000)                                                         // System has 10M tokens
	nativeToken.Mint("03e2459b73c0c6522530f6b26e834d992dfc55d170bee35d0bcdc047fe0d61c25b", 1000) // Test wallet
	nativeToken.Mint("staking_contract", 0)                                                      // Initialize staking contract

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

	// Skip validation for system transactions (rewards, minting)
	if tx.From == "system" {
		bc.PendingTxs = append(bc.PendingTxs, tx)
		return nil
	}

	// Ensure sender exists and has sufficient balance
	senderState := bc.getOrCreateAccount(tx.From)

	// Validate balance based on transaction type
	switch tx.Type {
	case RegularTransfer:
		if senderState.Balance < tx.Amount {
			return fmt.Errorf("insufficient balance: has %d, needs %d", senderState.Balance, tx.Amount)
		}
	case TokenTransfer:
		// Check token balance
		token, exists := bc.TokenRegistry[tx.TokenID]
		if !exists {
			return fmt.Errorf("token %s not found", tx.TokenID)
		}
		balance, err := token.BalanceOf(tx.From)
		if err != nil {
			return fmt.Errorf("failed to get token balance: %v", err)
		}
		if balance < tx.Amount {
			return fmt.Errorf("insufficient token balance: has %d, needs %d", balance, tx.Amount)
		}
	case StakeDeposit:
		// Check token balance for staking
		token, exists := bc.TokenRegistry[tx.TokenID]
		if !exists {
			return fmt.Errorf("token %s not found", tx.TokenID)
		}
		balance, err := token.BalanceOf(tx.From)
		if err != nil {
			return fmt.Errorf("failed to get token balance: %v", err)
		}
		if balance < tx.Amount {
			return fmt.Errorf("insufficient token balance for staking: has %d, needs %d", balance, tx.Amount)
		}
	}

	// Queue transaction for block inclusion
	bc.PendingTxs = append(bc.PendingTxs, tx)
	fmt.Printf("✅ Transaction validated and added to pending pool\n")

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
	fmt.Printf("   ➤ Type: %d\n", tx.Type)
	fmt.Printf("   ➤ From: %s\n", tx.From)
	fmt.Printf("   ➤ To: %s\n", tx.To)
	fmt.Printf("   ➤ Amount: %d\n", tx.Amount)
	fmt.Printf("   ➤ TokenID: %s\n", tx.TokenID)

	switch tx.Type {
	case RegularTransfer:
		return bc.applyRegularTransfer(tx)
	case TokenTransfer:
		return bc.applyTokenTransfer(tx)
	case StakeDeposit:
		return bc.applyStakeDeposit(tx)
	case StakeWithdraw:
		return bc.applyStakeWithdraw(tx)
	default:
		fmt.Printf("   ❌ Unknown transaction type: %d\n", tx.Type)
		return false
	}
}

func (bc *Blockchain) applyRegularTransfer(tx *Transaction) bool {
	sender := tx.From
	receiver := tx.To
	amount := tx.Amount

	// Get or create sender account
	senderState := bc.getOrCreateAccount(sender)
	fmt.Printf("   📤 Sender '%s' balance before transaction: %d\n", sender, senderState.Balance)

	// Check for insufficient funds (should already be validated, but double-check)
	if sender != "system" && senderState.Balance < amount {
		fmt.Printf("   ❌ Transaction failed: Insufficient funds (has %d, needs %d)\n", senderState.Balance, amount)
		return false
	}

	// Deduct from sender (unless it's a system transaction)
	if sender != "system" {
		senderState.Balance -= amount
		bc.SetBalance(sender, senderState.Balance)
		fmt.Printf("   ✅ Sender '%s' balance after deduction: %d\n", sender, senderState.Balance)
	}

	// Get or create receiver account
	receiverState := bc.getOrCreateAccount(receiver)
	fmt.Printf("   📥 Receiver '%s' balance before transaction: %d\n", receiver, receiverState.Balance)

	// Add to receiver
	receiverState.Balance += amount
	bc.SetBalance(receiver, receiverState.Balance)
	fmt.Printf("   ✅ Receiver '%s' balance after addition: %d\n", receiver, receiverState.Balance)

	fmt.Println("✅ Regular transfer applied successfully")
	return true
}

func (bc *Blockchain) applyTokenTransfer(tx *Transaction) bool {
	token, exists := bc.TokenRegistry[tx.TokenID]
	if !exists {
		fmt.Printf("   ❌ Token %s not found\n", tx.TokenID)
		return false
	}

	err := token.Transfer(tx.From, tx.To, tx.Amount)
	if err != nil {
		fmt.Printf("   ❌ Token transfer failed: %v\n", err)
		return false
	}

	fmt.Printf("   ✅ Token transfer applied successfully: %d %s from %s to %s\n",
		tx.Amount, tx.TokenID, tx.From, tx.To)
	return true
}

func (bc *Blockchain) applyStakeDeposit(tx *Transaction) bool {
	token, exists := bc.TokenRegistry[tx.TokenID]
	if !exists {
		fmt.Printf("   ❌ Token %s not found\n", tx.TokenID)
		return false
	}

	// Transfer tokens to staking contract
	err := token.Transfer(tx.From, "staking_contract", tx.Amount)
	if err != nil {
		fmt.Printf("   ❌ Stake deposit failed: %v\n", err)
		return false
	}

	// Update stake ledger
	bc.StakeLedger.AddStake(tx.From, tx.Amount)

	fmt.Printf("   ✅ Stake deposit applied successfully: %d %s staked by %s\n",
		tx.Amount, tx.TokenID, tx.From)
	fmt.Printf("   📊 New stake for %s: %d\n", tx.From, bc.StakeLedger.GetStake(tx.From))
	return true
}

func (bc *Blockchain) applyStakeWithdraw(tx *Transaction) bool {
	// Check if user has enough stake
	currentStake := bc.StakeLedger.GetStake(tx.From)
	if currentStake < tx.Amount {
		fmt.Printf("   ❌ Insufficient stake: has %d, trying to withdraw %d\n", currentStake, tx.Amount)
		return false
	}

	token, exists := bc.TokenRegistry[tx.TokenID]
	if !exists {
		fmt.Printf("   ❌ Token %s not found\n", tx.TokenID)
		return false
	}

	// Transfer tokens back from staking contract
	err := token.Transfer("staking_contract", tx.From, tx.Amount)
	if err != nil {
		fmt.Printf("   ❌ Stake withdrawal failed: %v\n", err)
		return false
	}

	// Update stake ledger
	bc.StakeLedger.SetStake(tx.From, currentStake-tx.Amount)

	fmt.Printf("   ✅ Stake withdrawal applied successfully: %d %s withdrawn by %s\n",
		tx.Amount, tx.TokenID, tx.From)
	fmt.Printf("   📊 New stake for %s: %d\n", tx.From, bc.StakeLedger.GetStake(tx.From))
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

// GetBlockchainInfo returns comprehensive blockchain information for UI
func (bc *Blockchain) GetBlockchainInfo() map[string]interface{} {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	// Get all account balances
	accounts := make(map[string]interface{})
	for addr, state := range bc.GlobalState {
		accounts[addr] = map[string]interface{}{
			"balance": state.Balance,
			"nonce":   state.Nonce,
		}
	}

	// Get token balances
	tokenBalances := make(map[string]map[string]uint64)
	for tokenSymbol, token := range bc.TokenRegistry {
		tokenBalances[tokenSymbol] = make(map[string]uint64)
		// Get balances for known addresses
		for addr := range bc.GlobalState {
			if balance, err := token.BalanceOf(addr); err == nil {
				tokenBalances[tokenSymbol][addr] = balance
			}
		}
		// Also check staking contract
		if balance, err := token.BalanceOf("staking_contract"); err == nil {
			tokenBalances[tokenSymbol]["staking_contract"] = balance
		}
	}

	// Get stake information
	stakes := bc.StakeLedger.GetAllStakes()

	// Get recent blocks
	recentBlocks := make([]map[string]interface{}, 0)
	start := len(bc.Blocks) - 10
	if start < 0 {
		start = 0
	}
	for i := start; i < len(bc.Blocks); i++ {
		block := bc.Blocks[i]
		recentBlocks = append(recentBlocks, map[string]interface{}{
			"index":        block.Header.Index,
			"hash":         block.Hash,
			"previousHash": block.Header.PreviousHash,
			"timestamp":    block.Header.Timestamp,
			"validator":    block.Header.Validator,
			"txCount":      len(block.Transactions),
		})
	}

	return map[string]interface{}{
		"blockHeight":   len(bc.Blocks),
		"pendingTxs":    len(bc.PendingTxs),
		"totalSupply":   bc.TotalSupply,
		"blockReward":   bc.BlockReward,
		"accounts":      accounts,
		"tokenBalances": tokenBalances,
		"stakes":        stakes,
		"recentBlocks":  recentBlocks,
		"tokenRegistry": bc.getTokenRegistryInfo(),
	}
}

func (bc *Blockchain) getTokenRegistryInfo() map[string]interface{} {
	tokens := make(map[string]interface{})
	for symbol, token := range bc.TokenRegistry {
		tokens[symbol] = map[string]interface{}{
			"name":        token.Name,
			"symbol":      token.Symbol,
			"decimals":    token.Decimals,
			"totalSupply": token.TotalSupply(),
		}
	}
	return tokens
}

// AddTokenBalance adds tokens to an address (admin function for testing)
func (bc *Blockchain) AddTokenBalance(address, tokenSymbol string, amount uint64) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	token, exists := bc.TokenRegistry[tokenSymbol]
	if !exists {
		return fmt.Errorf("token %s not found", tokenSymbol)
	}

	err := token.Mint(address, amount)
	if err != nil {
		return fmt.Errorf("failed to mint tokens: %v", err)
	}

	fmt.Printf("✅ Added %d %s tokens to %s\n", amount, tokenSymbol, address)
	return nil
}
