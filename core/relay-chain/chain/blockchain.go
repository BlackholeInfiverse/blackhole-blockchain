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

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/cache"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/cybersecurity"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/registry"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
	"github.com/syndtr/goleveldb/leveldb"
)

// AtomicTransaction represents an atomic transaction that can be rolled back
type AtomicTransaction struct {
	mu             sync.RWMutex
	committed      bool
	rollback       bool
	operations     []func() error
	undoOperations []func() error
	hash           string
}

type AccountState struct {
	Balance uint64
	Nonce   uint64
}

// hello this is me

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
	CrossChainDEX    interface{} // Will be *dex.CrossChainDEX
	EscrowManager    interface{}
	MultiSigManager  interface{}
	OTCManager       interface{} // Will be *otc.OTCManager
	SlashingManager  *SlashingManager
	ValidatorFaucet  interface{} // Will be *faucet.ValidatorFaucet

	// Economic system
	RewardInflationMgr *RewardInflationManager

	// Production-grade caching and registry
	BalanceCache    *cache.ProductionBalanceCache
	AccountRegistry *registry.AccountRegistry

	// Cybersecurity system
	SecurityManager *cybersecurity.SecurityManager

	// Mempool configuration
	MempoolThreshold int // Number of transactions to trigger auto block creation
}

type RealBlockchain struct {
	Blockchain *Blockchain // Pointer to the real blockchain
}

// BeginTransaction starts a new atomic transaction
func (bc *Blockchain) BeginTransaction() *AtomicTransaction {
	return &AtomicTransaction{
		operations:     make([]func() error, 0),
		undoOperations: make([]func() error, 0),
		committed:      false,
		rollback:       false,
	}
}

// Transfer adds a token transfer operation to the atomic transaction
func (tx *AtomicTransaction) Transfer(token *token.Token, from, to string, amount uint64) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rollback {
		return errors.New("transaction already committed or rolled back")
	}

	// Add the transfer operation
	tx.operations = append(tx.operations, func() error {
		return token.Transfer(from, to, amount)
	})

	// Add the undo operation (reverse transfer)
	tx.undoOperations = append(tx.undoOperations, func() error {
		return token.Transfer(to, from, amount)
	})

	return nil
}

// Commit commits all operations in the atomic transaction
func (tx *AtomicTransaction) Commit() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rollback {
		return errors.New("transaction already committed or rolled back")
	}

	// Execute all operations
	for _, op := range tx.operations {
		if err := op(); err != nil {
			// If any operation fails, rollback all previous operations
			tx.rollback = true
			for i := len(tx.undoOperations) - 1; i >= 0; i-- {
				if undoErr := tx.undoOperations[i](); undoErr != nil {
					// Log the undo error but continue with rollback
					log.Printf("Error during rollback: %v", undoErr)
				}
			}
			return fmt.Errorf("transaction failed: %v", err)
		}
	}

	tx.committed = true
	tx.hash = fmt.Sprintf("tx_%d", time.Now().UnixNano())
	return nil
}

// Rollback rolls back all operations in the atomic transaction
func (tx *AtomicTransaction) Rollback() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed {
		return errors.New("transaction already committed")
	}

	if tx.rollback {
		return errors.New("transaction already rolled back")
	}

	// Execute all undo operations in reverse order
	for i := len(tx.undoOperations) - 1; i >= 0; i-- {
		if err := tx.undoOperations[i](); err != nil {
			// Log the error but continue with remaining rollbacks
			log.Printf("Error during rollback: %v", err)
		}
	}

	tx.rollback = true
	return nil
}

// Hash returns the transaction hash
func (tx *AtomicTransaction) Hash() string {
	tx.mu.RLock()
	defer tx.mu.RUnlock()
	return tx.hash
}

func NewBlockchain(p2pPort int) (*Blockchain, error) {
	// Use consistent database path to persist state between restarts
	dbPath := fmt.Sprintf("blockchaindb_%d", p2pPort)
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}

	// Check if this is a fresh start or restart
	isExistingBlockchain := checkExistingBlockchain(db)

	var genesis *Block
	if isExistingBlockchain {
		fmt.Printf("🔄 Existing blockchain detected - loading from database...\n")
		// Load genesis from database
		genesis, err = loadGenesisFromDB(db)
		if err != nil {
			fmt.Printf("⚠️ Failed to load genesis from DB, creating new: %v\n", err)
			genesis = createGenesisBlock()
			isExistingBlockchain = false
		}
	} else {
		fmt.Printf("🆕 Fresh blockchain start - creating genesis block...\n")
		genesis = createGenesisBlock()
	}

	// Initialize P2P node
	node, err := NewNode(context.Background(), p2pPort)
	if err != nil {
		return nil, err
	}

	// Initialize stake ledger
	stakeLedger := NewStakeLedger()
	// Genesis validator starts with 1000 stake (will get tokens minted to match)

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
		MempoolThreshold: 3, // Default: create block when 3 transactions are pending
	}

	// Initialize slashing manager after TokenRegistry is created
	bc.SlashingManager = NewSlashingManager(stakeLedger, bc.TokenRegistry)

	// Initialize production-grade caching system
	encryptionKey := []byte("blackhole-blockchain-cache-key-2024") // In production, use proper key management
	bc.BalanceCache = cache.NewProductionBalanceCache(encryptionKey)

	// Initialize account registry
	bc.AccountRegistry = registry.NewAccountRegistry(db)

	// Initialize Cross-Chain DEX (will be properly initialized later with bridge)
	// bc.CrossChainDEX = dex.NewCrossChainDEX(localDEX, bridge, bc)

	// Initialize genesis state for fresh blockchain (TokenRegistry only)
	if !isExistingBlockchain {
		fmt.Printf("🆕 Initializing fresh blockchain state (TokenRegistry only)...\n")
		// Note: All balances now managed through TokenRegistry
		// Genesis balances will be set up in token initialization below
	} else {
		fmt.Printf("🔄 Loading existing blockchain (TokenRegistry only)...\n")
	}

	// Create native token with proper supply management
	nativeToken := token.NewTokenWithMaxSupply("Blockchain Hex", "BHX", 18, 1000000000) // 1B max supply
	bc.TokenRegistry["BHX"] = nativeToken

	// Create ETH token for OTC trading
	ethToken := token.NewTokenWithMaxSupply("Ethereum", "ETH", 18, 100000000) // 100M max supply
	bc.TokenRegistry["ETH"] = ethToken

	// Create USDT token for OTC trading
	usdtToken := token.NewTokenWithMaxSupply("Tether USD", "USDT", 6, 1000000000) // 1B max supply
	bc.TokenRegistry["USDT"] = usdtToken

	// Only initialize token distribution for fresh blockchain
	if !isExistingBlockchain {
		fmt.Printf("🪙 Minting initial tokens for fresh blockchain...\n")

		// Initialize controlled token distribution
		// System gets initial allocation for rewards and operations
		err = nativeToken.Mint("system", 10000000) // 10M tokens (1% of max supply)
		if err != nil {
			return nil, fmt.Errorf("failed to mint system tokens: %v", err)
		}

		// Test wallet gets small allocation
		err = nativeToken.Mint("03e2459b73c0c6522530f6b26e834d992dfc55d170bee35d0bcdc047fe0d61c25b", 1000)
		if err != nil {
			return nil, fmt.Errorf("failed to mint test tokens: %v", err)
		}

		// Initialize genesis validator with consistent stake and tokens
		genesisValidatorStake := uint64(1000)
		stakeLedger.SetStake("genesis-validator", genesisValidatorStake)

		// Mint tokens to genesis validator to match their stake
		err = nativeToken.Mint("genesis-validator", genesisValidatorStake)
		if err != nil {
			return nil, fmt.Errorf("failed to mint genesis validator tokens: %v", err)
		}

		// Mint tokens to system account for bridge testing
		systemBalance := uint64(10000000)
		err = nativeToken.Mint("system", systemBalance)
		if err != nil {
			return nil, fmt.Errorf("failed to mint system tokens: %v", err)
		}

		// Mint some tokens to test accounts
		testAccounts := map[string]uint64{
			"alice":   1000,
			"bob":     500,
			"charlie": 300,
		}

		for account, balance := range testAccounts {
			err = nativeToken.Mint(account, balance)
			if err != nil {
				fmt.Printf("⚠️ Failed to mint tokens to %s: %v\n", account, err)
			}
		}

		fmt.Printf("✅ Genesis validator initialized with %d stake and %d BHX tokens\n",
			genesisValidatorStake, genesisValidatorStake)
		fmt.Printf("✅ System account initialized with %d BHX tokens\n", systemBalance)
		fmt.Printf("✅ Test accounts initialized with tokens\n")
	} else {
		fmt.Printf("🔄 Loading existing blockchain - restoring token balances...\n")

		// For existing blockchain, load token balances from persistent storage
		bc.loadTokenBalances()

		// Initialize genesis validator stake from saved data
		genesisValidatorStake := uint64(1000)
		stakeLedger.SetStake("genesis-validator", genesisValidatorStake)
		fmt.Printf("🔄 Restored genesis validator with %d stake\n", genesisValidatorStake)
	}

	// Only mint additional tokens for fresh blockchain
	if !isExistingBlockchain {
		// Initialize ETH token balances for testing
		err = ethToken.Mint("system", 1000000) // 1M ETH to system
		if err != nil {
			return nil, fmt.Errorf("failed to mint ETH to system: %v", err)
		}

		err = ethToken.Mint("03e2459b73c0c6522530f6b26e834d992dfc55d170bee35d0bcdc047fe0d61c25b", 10000) // 10K ETH to test wallet
		if err != nil {
			return nil, fmt.Errorf("failed to mint ETH to test wallet: %v", err)
		}

		// Initialize USDT token balances for testing
		err = usdtToken.Mint("system", 10000000) // 10M USDT to system
		if err != nil {
			return nil, fmt.Errorf("failed to mint USDT to system: %v", err)
		}

		err = usdtToken.Mint("03e2459b73c0c6522530f6b26e834d992dfc55d170bee35d0bcdc047fe0d61c25b", 50000) // 50K USDT to test wallet
		if err != nil {
			return nil, fmt.Errorf("failed to mint USDT to test wallet: %v", err)
		}

		fmt.Printf("✅ Additional tokens initialized: ETH and USDT\n")
	} else {
		fmt.Printf("🔄 Skipping additional token minting for existing blockchain\n")
	}

	// Start validator monitoring in background
	go bc.MonitorValidatorPerformance()
	fmt.Printf("⚡ Slashing manager initialized and monitoring started\n")

	// Initialize Reward Inflation Manager
	bc.RewardInflationMgr = NewRewardInflationManager(bc)
	bc.RewardInflationMgr.StartInflationAdjustment()
	fmt.Printf("💰 Reward inflation manager initialized and started\n")

	// Initialize OTC Manager (temporarily disabled due to import cycle)
	// TODO: Fix import cycle and re-enable
	// otcManager := otc.NewOTCManager(bc)
	// bc.OTCManager = otcManager
	// fmt.Printf("✅ OTC Manager initialized\n")

	// Load GlobalState and Token balances from DB
	bc.loadGlobalState()
	bc.loadTokenBalances()

	// Handle fresh vs existing blockchain
	if !isExistingBlockchain {
		// Save genesis block for fresh blockchain
		err = bc.saveGenesisBlock()
		if err != nil {
			fmt.Printf("⚠️ Failed to save genesis block: %v\n", err)
		} else {
			fmt.Printf("✅ Genesis block saved to database\n")
		}

		// Save initial token balances for fresh blockchain
		bc.saveAllTokenBalances()
		fmt.Printf("✅ Fresh blockchain initialized and saved to persistent storage\n")
	} else {
		fmt.Printf("✅ Existing blockchain state loaded from persistent storage\n")
	}

	// Debug: Print all loaded balances
	bc.debugPrintAllBalances()

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

		// Report invalid block violation
		if block.Header.Validator != "" {
			bc.SlashingManager.AutoSlash(block.Header.Validator, InvalidBlock,
				fmt.Sprintf("Invalid block hash at height %d", block.Header.Index),
				block.Header.Index)
		}
		return false
	}

	// for _, tx := range block.Transactions {
	// 	if !tx.Verify() {
	// 		fmt.Printf("❌ Invalid transaction: %s\n", tx.ID)
	// 		return false
	// 	}
	// }

	// Track suspicious transactions but be much more conservative about slashing
	suspiciousCount := 0
	totalTransactions := len(block.Transactions)

	for _, tx := range block.Transactions {
		// Validate transaction security before applying
		if !bc.validateTransactionSecurity(tx) {
			fmt.Printf("⚠️ Suspicious transaction detected: %s\n", tx.ID)
			suspiciousCount++

			// Skip this transaction but continue processing the block
			fmt.Printf("⏭️ Skipping suspicious transaction %s\n", tx.ID)
			continue
		}

		success := bc.ApplyTransaction(tx)
		if !success {
			fmt.Println("⚠️ Failed to apply transaction, skipping:", tx.ID)
		}
	}

	// Only report violations if there's a significant percentage of suspicious transactions
	// AND there are multiple transactions (avoid false positives on single transactions)
	if totalTransactions > 1 && suspiciousCount > 0 {
		suspiciousPercentage := float64(suspiciousCount) / float64(totalTransactions)

		// Only report if more than 50% of transactions are suspicious
		if suspiciousPercentage > 0.5 {
			fmt.Printf("🚨 High percentage of suspicious transactions: %d/%d (%.1f%%)\n",
				suspiciousCount, totalTransactions, suspiciousPercentage*100)

			if block.Header.Validator != "" {
				// Report for manual review, don't auto-slash
				bc.SlashingManager.ReportViolation(block.Header.Validator, MaliciousTransaction,
					fmt.Sprintf("High suspicious transaction rate: %d/%d (%.1f%%) in block %d",
						suspiciousCount, totalTransactions, suspiciousPercentage*100, block.Header.Index),
					block.Header.Index)
			}
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

// GetBalance now uses TokenRegistry - specify token symbol
func (bc *Blockchain) GetTokenBalance(addr, tokenSymbol string) uint64 {
	token, exists := bc.TokenRegistry[tokenSymbol]
	if !exists {
		return 0
	}
	balance, err := token.BalanceOf(addr)
	if err != nil {
		return 0
	}
	return balance
}

// GetTokenBalanceWithCache retrieves token balance using production cache system
func (bc *Blockchain) GetTokenBalanceWithCache(userID, address, tokenSymbol string, forValidation bool) (uint64, error) {
	// Try cache first
	if bc.BalanceCache != nil {
		if balance, hit, err := bc.BalanceCache.GetBalance(userID, address, tokenSymbol, forValidation); err == nil && hit {
			return balance, nil
		}
	}

	// Cache miss - get from persistent storage first, then from token
	var balance uint64
	var err error

	// First try to load from persistent storage
	key := fmt.Sprintf("token_balance:%s:%s", tokenSymbol, address)
	if data, dbErr := bc.DB.Get([]byte(key), nil); dbErr == nil {
		if json.Unmarshal(data, &balance) == nil {
			log.Printf("📊 Cache miss - loaded from DB: %s[%s] = %d", tokenSymbol, address, balance)
		} else {
			balance = 0 // Default to 0 if unmarshal fails
		}
	} else {
		// Fallback to token registry
		token, exists := bc.TokenRegistry[tokenSymbol]
		if !exists {
			return 0, fmt.Errorf("token %s not found", tokenSymbol)
		}

		balance, err = token.BalanceOf(address)
		if err != nil {
			return 0, err
		}
		log.Printf("📊 Cache miss - loaded from token: %s[%s] = %d", tokenSymbol, address, balance)
	}

	// Update cache
	if bc.BalanceCache != nil {
		bc.BalanceCache.SetBalance(userID, address, tokenSymbol, balance, "blockchain_query")
	}

	// Record token interaction in registry
	if bc.AccountRegistry != nil {
		bc.AccountRegistry.RecordTokenInteraction(address, tokenSymbol, "", balance > 0, balance)
	}

	return balance, nil
}

// GetAllTokenBalancesWithCache retrieves all token balances for an address using cache
func (bc *Blockchain) GetAllTokenBalancesWithCache(userID, address string) (map[string]uint64, error) {
	balances := make(map[string]uint64)

	for tokenSymbol := range bc.TokenRegistry {
		balance, err := bc.GetTokenBalanceWithCache(userID, address, tokenSymbol, false)
		if err != nil {
			log.Printf("Warning: Failed to get balance for %s:%s: %v", address, tokenSymbol, err)
			balance = 0 // Default to 0 on error
		}
		balances[tokenSymbol] = balance
	}

	return balances, nil
}

// PreloadUserBalances preloads all balances for a user's wallets into cache
func (bc *Blockchain) PreloadUserBalances(userID string, addresses []string) error {
	if bc.BalanceCache == nil {
		return fmt.Errorf("balance cache not initialized")
	}

	tokens := make([]string, 0, len(bc.TokenRegistry))
	for tokenSymbol := range bc.TokenRegistry {
		tokens = append(tokens, tokenSymbol)
	}

	// Balance loader function - loads from persistent storage first, then from token
	balanceLoader := func(address, tokenSymbol string) uint64 {
		// First try to load from persistent storage
		key := fmt.Sprintf("token_balance:%s:%s", tokenSymbol, address)
		if data, err := bc.DB.Get([]byte(key), nil); err == nil {
			var balance uint64
			if json.Unmarshal(data, &balance) == nil {
				log.Printf("📊 Loaded from DB: %s[%s] = %d", tokenSymbol, address, balance)
				return balance
			}
		}

		// Fallback to token registry
		token, exists := bc.TokenRegistry[tokenSymbol]
		if !exists {
			return 0
		}

		balance, err := token.BalanceOf(address)
		if err != nil {
			return 0
		}

		log.Printf("📊 Loaded from token: %s[%s] = %d", tokenSymbol, address, balance)
		return balance
	}

	return bc.BalanceCache.PreloadUserBalances(userID, addresses, tokens, balanceLoader)
}

// RegisterWalletAddress registers a new wallet address in the account registry
func (bc *Blockchain) RegisterWalletAddress(address, userID, walletName string) error {
	if bc.AccountRegistry == nil {
		return fmt.Errorf("account registry not initialized")
	}

	return bc.AccountRegistry.RegisterAccount(address, "wallet_ui", false, userID, walletName)
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

	// All transaction types now use TokenRegistry for balance validation
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

	// Queue transaction for block inclusion
	bc.PendingTxs = append(bc.PendingTxs, tx)
	fmt.Printf("✅ Transaction validated and added to pending pool (%d/%d transactions)\n", len(bc.PendingTxs), bc.MempoolThreshold)

	// Auto-create block when we reach the threshold
	if len(bc.PendingTxs) >= bc.MempoolThreshold {
		fmt.Printf("🔥 Mempool threshold reached! Auto-creating block with %d transactions...\n", len(bc.PendingTxs))
		go bc.autoCreateBlock()
	}

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

// autoCreateBlock automatically creates a block when mempool threshold is reached
func (bc *Blockchain) autoCreateBlock() {
	// Small delay to allow for more transactions to accumulate
	time.Sleep(100 * time.Millisecond)

	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Double-check we still have enough transactions
	if len(bc.PendingTxs) < bc.MempoolThreshold {
		fmt.Printf("⚠️ Transaction count dropped below threshold (%d), skipping auto-block creation\n", bc.MempoolThreshold)
		return
	}

	// Select a validator (simplified - use first available validator or default)
	selectedValidator := bc.selectValidatorForAutoBlock()

	fmt.Printf("🏗️ Auto-creating block with validator: %s\n", selectedValidator)

	// Create the block (this will include all pending transactions)
	block := bc.createBlockWithPendingTxs(selectedValidator)

	// Validate and add the block
	if bc.validateAndAddBlock(block) {
		fmt.Printf("✅ Auto-created block %d with %d transactions successfully!\n",
			block.Header.Index, len(block.Transactions))

		// Clear pending transactions since they're now in the block
		bc.PendingTxs = make([]*Transaction, 0)

		// Broadcast the new block to peers
		if bc.P2PNode != nil {
			go bc.BroadcastBlock(block)
		}
	} else {
		fmt.Printf("❌ Failed to add auto-created block\n")
	}
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
	// All transfers now use TokenRegistry (RegularTransfer = TokenTransfer)
	token, exists := bc.TokenRegistry[tx.TokenID]
	if !exists {
		fmt.Printf("   ❌ Token %s not found\n", tx.TokenID)
		return false
	}

	// Get balances before transfer
	senderBalance, _ := token.BalanceOf(tx.From)
	receiverBalance, _ := token.BalanceOf(tx.To)

	fmt.Printf("   📤 Sender '%s' balance before transaction: %d %s\n", tx.From, senderBalance, tx.TokenID)
	fmt.Printf("   📥 Receiver '%s' balance before transaction: %d %s\n", tx.To, receiverBalance, tx.TokenID)

	// Execute transfer through TokenRegistry
	err := token.Transfer(tx.From, tx.To, tx.Amount)
	if err != nil {
		fmt.Printf("   ❌ Transfer failed: %v\n", err)
		return false
	}

	// Get balances after transfer
	newSenderBalance, _ := token.BalanceOf(tx.From)
	newReceiverBalance, _ := token.BalanceOf(tx.To)

	fmt.Printf("   ✅ Sender '%s' balance after transfer: %d %s\n", tx.From, newSenderBalance, tx.TokenID)
	fmt.Printf("   ✅ Receiver '%s' balance after transfer: %d %s\n", tx.To, newReceiverBalance, tx.TokenID)

	fmt.Println("✅ Regular transfer applied successfully via TokenRegistry")
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

	// Get updated balances
	fromBalance, _ := token.BalanceOf(tx.From)
	toBalance, _ := token.BalanceOf(tx.To)

	// Save updated balances to persistent storage
	bc.saveTokenBalance(tx.TokenID, tx.From, fromBalance)
	bc.saveTokenBalance(tx.TokenID, tx.To, toBalance)

	// Update cache for all users who might have these addresses
	if bc.BalanceCache != nil {
		// Invalidate cache entries for both addresses to force fresh data
		// Note: In a real system, we'd need to track which users have which addresses
		// For now, we'll update with a generic "system" user ID
		bc.BalanceCache.UpdateBalance("system", tx.From, tx.TokenID, fromBalance)
		bc.BalanceCache.UpdateBalance("system", tx.To, tx.TokenID, toBalance)
	}

	// Record token interactions in registry
	if bc.AccountRegistry != nil {
		bc.AccountRegistry.RecordTokenInteraction(tx.From, tx.TokenID, tx.ID, fromBalance > 0, fromBalance)
		bc.AccountRegistry.RecordTokenInteraction(tx.To, tx.TokenID, tx.ID, toBalance > 0, toBalance)
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

	// Get updated balances
	fromBalance, _ := token.BalanceOf(tx.From)
	stakingBalance, _ := token.BalanceOf("staking_contract")

	// Save updated balances to persistent storage
	bc.saveTokenBalance(tx.TokenID, tx.From, fromBalance)
	bc.saveTokenBalance(tx.TokenID, "staking_contract", stakingBalance)

	// Update cache
	if bc.BalanceCache != nil {
		bc.BalanceCache.UpdateBalance("system", tx.From, tx.TokenID, fromBalance)
		bc.BalanceCache.UpdateBalance("system", "staking_contract", tx.TokenID, stakingBalance)
	}

	// Record token interactions in registry
	if bc.AccountRegistry != nil {
		bc.AccountRegistry.RecordTokenInteraction(tx.From, tx.TokenID, tx.ID, fromBalance > 0, fromBalance)
		bc.AccountRegistry.RecordTokenInteraction("staking_contract", tx.TokenID, tx.ID, stakingBalance > 0, stakingBalance)
	}

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

	// Get updated balances
	fromBalance, _ := token.BalanceOf(tx.From)
	stakingBalance, _ := token.BalanceOf("staking_contract")

	// Save updated balances to persistent storage
	bc.saveTokenBalance(tx.TokenID, tx.From, fromBalance)
	bc.saveTokenBalance(tx.TokenID, "staking_contract", stakingBalance)

	// Update cache
	if bc.BalanceCache != nil {
		bc.BalanceCache.UpdateBalance("system", tx.From, tx.TokenID, fromBalance)
		bc.BalanceCache.UpdateBalance("system", "staking_contract", tx.TokenID, stakingBalance)
	}

	// Record token interactions in registry
	if bc.AccountRegistry != nil {
		bc.AccountRegistry.RecordTokenInteraction(tx.From, tx.TokenID, tx.ID, fromBalance > 0, fromBalance)
		bc.AccountRegistry.RecordTokenInteraction("staking_contract", tx.TokenID, tx.ID, stakingBalance > 0, stakingBalance)
	}

	fmt.Printf("   ✅ Stake withdrawal applied successfully: %d %s withdrawn by %s\n",
		tx.Amount, tx.TokenID, tx.From)
	fmt.Printf("   📊 New stake for %s: %d\n", tx.From, bc.StakeLedger.GetStake(tx.From))
	return true
}

// selectValidatorForAutoBlock selects a validator for auto block creation
func (bc *Blockchain) selectValidatorForAutoBlock() string {
	// Try to get an active validator from stake ledger
	if bc.StakeLedger != nil {
		stakes := bc.StakeLedger.GetAllStakes()
		if len(stakes) > 0 {
			// Return the validator with highest stake
			return bc.StakeLedger.GetHighestStakeValidator()
		}
	}

	// Fallback to a default validator
	return "auto-validator"
}

// createBlockWithPendingTxs creates a block with current pending transactions
func (bc *Blockchain) createBlockWithPendingTxs(selectedValidator string) *Block {
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
	if stake == 0 {
		stake = 100 // Default stake for auto-validator
	}

	// Create reward transaction
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
		Signature: nil,
		PublicKey: nil,
	}
	rewardTx.ID = rewardTx.CalculateHash()

	// Combine reward transaction with pending transactions
	txs := append([]*Transaction{rewardTx}, bc.PendingTxs...)

	// Create new block
	block := NewBlock(index, txs, prevHash, selectedValidator, stake)

	return block
}

// validateAndAddBlock validates and adds a block to the blockchain
func (bc *Blockchain) validateAndAddBlock(block *Block) bool {
	// Perform security validation if cybersecurity is enabled
	if bc.SecurityManager != nil {
		if err := bc.ValidateBlockSecurity(block); err != nil {
			fmt.Printf("❌ Block failed security validation: %v\n", err)
			return false
		}
	}

	// Basic block validation
	if !block.IsValid() {
		fmt.Printf("❌ Block failed basic validation\n")
		return false
	}

	// Check if block extends the current chain
	if len(bc.Blocks) > 0 {
		currentTip := bc.Blocks[len(bc.Blocks)-1]
		if block.Header.PreviousHash != currentTip.Hash {
			fmt.Printf("❌ Block doesn't extend current chain tip\n")
			return false
		}
		if block.Header.Index != currentTip.Header.Index+1 {
			fmt.Printf("❌ Block index mismatch\n")
			return false
		}
	}

	// Apply all transactions in the block
	for _, tx := range block.Transactions {
		if !bc.ApplyTransaction(tx) {
			fmt.Printf("❌ Failed to apply transaction %s\n", tx.ID)
			return false
		}
	}

	// Add block to chain
	bc.Blocks = append(bc.Blocks, block)

	// Update validator's last block time (simplified - could be enhanced)
	// Note: ValidatorManager doesn't have UpdateValidatorActivity method
	// This could be implemented if needed for more advanced validator tracking

	return true
}

// SetMempoolThreshold sets the number of transactions required to trigger auto block creation
func (bc *Blockchain) SetMempoolThreshold(threshold int) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if threshold < 1 {
		threshold = 1 // Minimum threshold is 1
	}

	bc.MempoolThreshold = threshold
	fmt.Printf("🔧 Mempool threshold updated to %d transactions\n", threshold)
}

// GetMempoolThreshold returns the current mempool threshold
func (bc *Blockchain) GetMempoolThreshold() int {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.MempoolThreshold
}

// GetMempoolStatus returns current mempool status
func (bc *Blockchain) GetMempoolStatus() map[string]interface{} {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	return map[string]interface{}{
		"pending_transactions": len(bc.PendingTxs),
		"threshold":           bc.MempoolThreshold,
		"progress":            fmt.Sprintf("%d/%d", len(bc.PendingTxs), bc.MempoolThreshold),
		"auto_block_ready":    len(bc.PendingTxs) >= bc.MempoolThreshold,
	}
}

// SetBalance removed - use TokenRegistry.Mint/Transfer instead
// This ensures all balance changes go through proper token operations

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

// loadTokenBalances loads token balances from persistent storage
func (bc *Blockchain) loadTokenBalances() {
	iter := bc.DB.NewIterator(nil, nil)
	defer iter.Release()

	loadedBalances := 0

	log.Printf("🔄 Loading token balances from persistent storage...")

	for iter.Next() {
		key := string(iter.Key())
		if len(key) >= 13 && key[:13] == "token_balance" {
			// Key format: "token_balance:SYMBOL:ADDRESS"
			keyWithoutPrefix := string(iter.Key())[14:] // Remove "token_balance:" prefix

			// Find the first colon to separate token symbol from address
			colonIndex := -1
			for i, char := range keyWithoutPrefix {
				if char == ':' {
					colonIndex = i
					break
				}
			}

			if colonIndex > 0 && colonIndex < len(keyWithoutPrefix)-1 {
				tokenSymbol := keyWithoutPrefix[:colonIndex]
				address := keyWithoutPrefix[colonIndex+1:]

				var balance uint64
				err := json.Unmarshal(iter.Value(), &balance)
				if err == nil {
					if token, exists := bc.TokenRegistry[tokenSymbol]; exists {
						token.SetBalance(address, balance)
						loadedBalances++
						log.Printf("✅ Loaded balance: %s[%s] = %d", tokenSymbol, address, balance)
					} else {
						log.Printf("⚠️ Token %s not found in registry", tokenSymbol)
					}
				} else {
					log.Printf("⚠️ Failed to unmarshal balance for %s:%s: %v", tokenSymbol, address, err)
				}
			} else {
				log.Printf("⚠️ Invalid key format: %s", key)
			}
		}
	}

	if err := iter.Error(); err != nil {
		log.Printf("❌ Error loading token balances: %v", err)
	} else {
		log.Printf("✅ Loaded %d token balances from persistent storage", loadedBalances)

		// Print current token balances for verification
		for symbol, token := range bc.TokenRegistry {
			allBalances := token.GetAllBalances()
			if len(allBalances) > 0 {
				log.Printf("📋 %s balances after loading:", symbol)
				for addr, bal := range allBalances {
					log.Printf("   %s: %d", addr, bal)
				}
			}
		}
	}
}

// saveTokenBalance saves a single token balance to persistent storage
func (bc *Blockchain) saveTokenBalance(tokenSymbol, address string, balance uint64) error {
	key := fmt.Sprintf("token_balance:%s:%s", tokenSymbol, address)
	data, err := json.Marshal(balance)
	if err != nil {
		return err
	}
	return bc.DB.Put([]byte(key), data, nil)
}

// saveAllTokenBalances saves all token balances to persistent storage
func (bc *Blockchain) saveAllTokenBalances() {
	savedCount := 0
	for symbol, token := range bc.TokenRegistry {
		balances := token.GetAllBalances()
		for address, balance := range balances {
			// Save ALL balances, including zeros for registered addresses
			err := bc.saveTokenBalance(symbol, address, balance)
			if err != nil {
				log.Printf("❌ Error saving token balance for %s:%s: %v", symbol, address, err)
			} else {
				savedCount++
				log.Printf("💾 Saved balance: %s[%s] = %d", symbol, address, balance)
			}
		}

		// Also save zero balances for addresses in the account registry
		if bc.AccountRegistry != nil {
			allAccounts := bc.AccountRegistry.GetAllAccounts()
			for address := range allAccounts {
				// Check if this address already has a balance entry
				if _, exists := balances[address]; !exists {
					// Save zero balance for this address
					err := bc.saveTokenBalance(symbol, address, 0)
					if err != nil {
						log.Printf("❌ Error saving zero balance for %s:%s: %v", symbol, address, err)
					} else {
						savedCount++
						log.Printf("💾 Saved zero balance: %s[%s] = 0", symbol, address)
					}
				}
			}
		}
	}
	log.Printf("✅ Saved %d token balances to persistent storage", savedCount)
}

// Shutdown gracefully saves all state before closing
func (bc *Blockchain) Shutdown() {
	log.Printf("🔄 Shutting down blockchain - saving all state...")

	// Save all token balances
	bc.saveAllTokenBalances()

	log.Printf("✅ Blockchain shutdown complete - all state saved")
}

// debugPrintAllBalances prints all current token balances for debugging
func (bc *Blockchain) debugPrintAllBalances() {
	fmt.Printf("\n🔍 DEBUG: Current Token Balances\n")
	fmt.Printf("================================\n")

	totalBalances := 0
	for symbol, token := range bc.TokenRegistry {
		balances := token.GetAllBalances()
		if len(balances) > 0 {
			fmt.Printf("📋 %s Token Balances:\n", symbol)
			for address, balance := range balances {
				fmt.Printf("   %s: %d\n", address, balance)
				totalBalances++
			}
		} else {
			fmt.Printf("📋 %s Token: No balances found\n", symbol)
		}
	}

	if totalBalances == 0 {
		fmt.Printf("⚠️ No token balances found in any token!\n")
	} else {
		fmt.Printf("✅ Total balance entries: %d\n", totalBalances)
	}
	fmt.Printf("================================\n\n")
}

// checkExistingBlockchain checks if there's existing blockchain data in the database
func checkExistingBlockchain(db *leveldb.DB) bool {
	// Check for existing blocks
	iter := db.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		// Look for block data or token balances
		if len(key) >= 5 && (key[:5] == "block" || key[:13] == "token_balance") {
			return true
		}
	}

	return false
}

// loadGenesisFromDB loads the genesis block from database
func loadGenesisFromDB(db *leveldb.DB) (*Block, error) {
	// Try to load block 0 (genesis)
	data, err := db.Get([]byte("block_0"), nil)
	if err != nil {
		return nil, err
	}

	var genesis Block
	err = json.Unmarshal(data, &genesis)
	if err != nil {
		return nil, err
	}

	return &genesis, nil
}

// saveGenesisBlock saves the genesis block to database
func (bc *Blockchain) saveGenesisBlock() error {
	if len(bc.Blocks) == 0 {
		return fmt.Errorf("no genesis block to save")
	}

	genesis := bc.Blocks[0]
	data, err := json.Marshal(genesis)
	if err != nil {
		return err
	}

	return bc.DB.Put([]byte("block_0"), data, nil)
}

// saveInitialTokenBalances saves initial token balances after genesis
func (bc *Blockchain) saveInitialTokenBalances() {
	// Check if we already have token balances saved (not a fresh start)
	iter := bc.DB.NewIterator(nil, nil)
	defer iter.Release()

	hasExistingBalances := false
	for iter.Next() {
		key := string(iter.Key())
		if len(key) >= 13 && key[:13] == "token_balance" {
			hasExistingBalances = true
			break
		}
	}

	// Only save if this is a fresh start
	if !hasExistingBalances {
		bc.saveAllTokenBalances()
		log.Printf("✅ Initial token balances saved to persistent storage")
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

		// Get ALL addresses that have token balances (not just GlobalState addresses)
		allAddresses := make(map[string]bool)

		// Add addresses from GlobalState
		for addr := range bc.GlobalState {
			allAddresses[addr] = true
		}

		// Add addresses that have token balances
		tokenAddresses := token.GetAllAddressesWithBalances()
		for _, addr := range tokenAddresses {
			allAddresses[addr] = true
		}

		// Add special addresses
		allAddresses["staking_contract"] = true
		allAddresses["system"] = true

		// Get balances for all known addresses
		for addr := range allAddresses {
			if balance, err := token.BalanceOf(addr); err == nil && balance > 0 {
				tokenBalances[tokenSymbol][addr] = balance
			}
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

	// Calculate actual circulating supply from BHX token
	circulatingSupply := uint64(0)
	maxSupply := uint64(0)
	if bhxToken, exists := bc.TokenRegistry["BHX"]; exists {
		circulatingSupply = bhxToken.CirculatingSupply()
		maxSupply = bhxToken.MaxSupply()
	}

	return map[string]interface{}{
		"blockHeight":       len(bc.Blocks),
		"pendingTxs":        len(bc.PendingTxs),
		"totalSupply":       circulatingSupply, // Use actual circulating supply
		"maxSupply":         maxSupply,         // Show maximum supply
		"blockReward":       bc.BlockReward,
		"accounts":          accounts,
		"tokenBalances":     tokenBalances,
		"stakes":            stakes,
		"recentBlocks":      recentBlocks,
		"tokenRegistry":     bc.getTokenRegistryInfo(),
		"supplyUtilization": float64(circulatingSupply) / float64(maxSupply) * 100, // Percentage used
	}
}

func (bc *Blockchain) getTokenRegistryInfo() map[string]interface{} {
	tokens := make(map[string]interface{})
	for symbol, token := range bc.TokenRegistry {
		tokens[symbol] = map[string]interface{}{
			"name":              token.Name,
			"symbol":            token.Symbol,
			"decimals":          token.Decimals,
			"circulatingSupply": token.CirculatingSupply(),
			"maxSupply":         token.MaxSupply(),
			"utilization":       float64(token.CirculatingSupply()) / float64(token.MaxSupply()) * 100,
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

	// 🔥 CRITICAL FIX: Save the balance to persistent storage!
	newBalance, _ := token.BalanceOf(address)
	err = bc.saveTokenBalance(tokenSymbol, address, newBalance)
	if err != nil {
		fmt.Printf("⚠️ Warning: Failed to save balance to database: %v\n", err)
	} else {
		fmt.Printf("💾 Balance saved to database: %s[%s] = %d\n", tokenSymbol, address, newBalance)
	}

	// Register address in account registry
	if bc.AccountRegistry != nil {
		bc.AccountRegistry.RegisterAccount(address, "admin_mint", false, "", "")
		bc.AccountRegistry.RecordTokenInteraction(address, tokenSymbol, "admin_mint", true, newBalance)
	}

	fmt.Printf("✅ Added %d %s tokens to %s (new balance: %d)\n", amount, tokenSymbol, address, newBalance)
	return nil
}

// Slashing-related validation functions
func (bc *Blockchain) validateTransactionSecurity(tx *Transaction) bool {
	// Check for malicious transaction patterns - MUCH MORE CONSERVATIVE

	// 1. Check for extremely excessive amounts (potential drain attack)
	// Increased threshold to 1 billion (1,000,000,000) to avoid false positives
	if tx.Amount > 1000000000 {
		fmt.Printf("🚨 Extremely large transaction detected: %d (threshold: 1,000,000,000)\n", tx.Amount)
		return false
	}

	// 2. Check for invalid self-transfers (but allow staking)
	if tx.From == tx.To && tx.Type != StakeDeposit && tx.Type != StakeWithdraw {
		fmt.Printf("🚨 Invalid self-transfer detected (non-staking): %s\n", tx.ID)
		return false
	}

	// 3. Check for extreme timestamp manipulation (extended window)
	currentTime := time.Now().Unix()
	if tx.Timestamp > currentTime+3600 { // 1 hour in future (was 5 minutes)
		fmt.Printf("🚨 Extreme future timestamp detected: %d vs %d (diff: %d seconds)\n",
			tx.Timestamp, currentTime, tx.Timestamp-currentTime)
		return false
	}

	// 4. Check for excessive duplicate nonces (potential replay attack)
	// Only flag if there are many duplicates, not just one or two
	if bc.isDuplicateNonce(tx) {
		fmt.Printf("🚨 Excessive nonce reuse detected (potential replay attack): %s\n", tx.ID)
		return false
	}

	// 5. Additional check: Ensure transaction has valid signature (if available)
	if tx.From == "" || tx.To == "" {
		fmt.Printf("🚨 Invalid transaction addresses: from=%s, to=%s\n", tx.From, tx.To)
		return false
	}

	return true
}

func (bc *Blockchain) detectDoubleSign(block *Block) bool {
	// Check if validator has already signed a block at this height
	for _, existingBlock := range bc.Blocks {
		if existingBlock.Header.Index == block.Header.Index &&
			existingBlock.Header.Validator == block.Header.Validator &&
			existingBlock.Hash != block.Hash {
			fmt.Printf("🚨 Double signing detected: validator %s signed multiple blocks at height %d\n",
				block.Header.Validator, block.Header.Index)
			return true
		}
	}
	return false
}

func (bc *Blockchain) isDuplicateNonce(tx *Transaction) bool {
	// Skip nonce validation for system transactions
	if tx.From == "system" || tx.From == "staking_contract" || tx.From == "burn_address" {
		return false
	}

	// Skip nonce validation for certain transaction types that don't need strict ordering
	if tx.Type == StakeDeposit || tx.Type == StakeWithdraw {
		return false
	}

	// Only check recent blocks (last 100) to avoid performance issues
	// and reduce false positives from old transactions
	startIndex := 0
	if len(bc.Blocks) > 100 {
		startIndex = len(bc.Blocks) - 100
	}

	duplicateCount := 0
	for i := startIndex; i < len(bc.Blocks); i++ {
		block := bc.Blocks[i]
		for _, existingTx := range block.Transactions {
			if existingTx.From == tx.From &&
				existingTx.Nonce == tx.Nonce &&
				existingTx.ID != tx.ID &&
				existingTx.Type == tx.Type { // Same transaction type
				duplicateCount++
			}
		}
	}

	// Only flag as duplicate if we see multiple instances
	// This reduces false positives from legitimate retries
	if duplicateCount > 2 {
		fmt.Printf("🚨 Multiple duplicate nonces detected: %d instances of nonce %d for %s\n",
			duplicateCount, tx.Nonce, tx.From)
		return true
	}

	return false
}

// Validator monitoring functions
func (bc *Blockchain) MonitorValidatorPerformance() {
	// This would run as a goroutine to monitor validator behavior
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bc.checkValidatorDowntime()
		}
	}
}

func (bc *Blockchain) checkValidatorDowntime() {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	// Check if any validators haven't produced blocks recently
	currentTime := time.Now().Unix()
	downtimeThreshold := int64(300) // 5 minutes

	validators := bc.StakeLedger.GetAllStakes()
	for validator := range validators {
		if bc.SlashingManager.IsValidatorJailed(validator) {
			continue // Skip jailed validators
		}

		lastBlockTime := bc.getLastBlockTimeForValidator(validator)
		downtime := currentTime - lastBlockTime

		// Only report if downtime is reasonable (not years!)
		if downtime > downtimeThreshold && downtime < 86400 { // Between 5 minutes and 24 hours
			fmt.Printf("⏰ Validator %s has been down for %d seconds\n", validator, downtime)

			// Only report once per hour to avoid spam
			if bc.shouldReportDowntime(validator, downtime) {
				bc.SlashingManager.ReportViolation(validator, Downtime,
					fmt.Sprintf("Validator down for %d seconds", downtime),
					bc.GetLatestBlock().Header.Index)
			}
		}
	}
}

// Track last downtime report to avoid spam
var lastDowntimeReport = make(map[string]int64)

func (bc *Blockchain) shouldReportDowntime(validator string, downtime int64) bool {
	lastReport, exists := lastDowntimeReport[validator]
	currentTime := time.Now().Unix()

	// Report if never reported before, or if 1 hour has passed since last report
	if !exists || currentTime-lastReport > 3600 {
		lastDowntimeReport[validator] = currentTime
		return true
	}

	return false
}

func (bc *Blockchain) getLastBlockTimeForValidator(validator string) int64 {
	// Find the most recent block produced by this validator
	for i := len(bc.Blocks) - 1; i >= 0; i-- {
		if bc.Blocks[i].Header.Validator == validator {
			return bc.Blocks[i].Header.Timestamp.Unix()
		}
	}
	// If validator never produced a block, return current time minus a reasonable period
	return time.Now().Unix() - 3600 // 1 hour ago
}

// ================================
// CYBERSECURITY INTEGRATION
// ================================

// InitializeCybersecurity initializes the cybersecurity system
func (bc *Blockchain) InitializeCybersecurity() error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.SecurityManager != nil {
		return fmt.Errorf("cybersecurity system already initialized")
	}

	bc.SecurityManager = cybersecurity.NewSecurityManager()

	// Deploy default security contracts
	if err := bc.deployDefaultSecurityContracts(); err != nil {
		return fmt.Errorf("failed to deploy default security contracts: %v", err)
	}

	// Start the security manager
	if err := bc.SecurityManager.Start(); err != nil {
		return fmt.Errorf("failed to start security manager: %v", err)
	}

	log.Printf("🔒 Cybersecurity system initialized successfully")
	return nil
}

// deployDefaultSecurityContracts deploys essential security contracts
func (bc *Blockchain) deployDefaultSecurityContracts() error {
	contracts := []struct {
		contractType cybersecurity.SecurityContractType
		name         string
		description  string
	}{
		{
			cybersecurity.ThreatDetectionContract,
			"Blockchain Threat Detection",
			"Monitors blockchain for suspicious activities and potential threats",
		},
		{
			cybersecurity.AccessControlContract,
			"Blockchain Access Control",
			"Manages access permissions for blockchain operations",
		},
		{
			cybersecurity.AuditContract,
			"Blockchain Audit System",
			"Logs and tracks all security-relevant events",
		},
		{
			cybersecurity.ComplianceContract,
			"Regulatory Compliance",
			"Ensures blockchain operations meet regulatory requirements",
		},
		{
			cybersecurity.IncidentResponseContract,
			"Security Incident Response",
			"Handles security incidents and automated responses",
		},
		{
			cybersecurity.SecurityMonitoringContract,
			"Real-time Security Monitoring",
			"Continuous monitoring of blockchain security metrics",
		},
	}

	for _, contract := range contracts {
		_, err := bc.SecurityManager.DeploySecurityContract(
			contract.contractType,
			contract.name,
			contract.description,
			"system",
		)
		if err != nil {
			return fmt.Errorf("failed to deploy %s: %v", contract.name, err)
		}
	}

	return nil
}

// ValidateTransactionSecurity performs comprehensive security validation on transactions
func (bc *Blockchain) ValidateTransactionSecurity(tx *Transaction) error {
	if bc.SecurityManager == nil {
		log.Printf("⚠️ Security manager not initialized, skipping security validation")
		return nil
	}

	// Serialize transaction for analysis
	txData, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to serialize transaction for security analysis: %v", err)
	}

	// Detect threats in transaction data
	threats := bc.SecurityManager.DetectThreats(txData, fmt.Sprintf("transaction:%s", tx.ID))

	// Process detected threats
	for _, threat := range threats {
		bc.SecurityManager.LogSecurityEvent(
			tx.From,
			"transaction_threat_detected",
			tx.ID,
			cybersecurity.AuditFailure,
			fmt.Sprintf("Threat detected: %s (confidence: %.2f)", threat.Description, threat.Confidence),
		)

		// Block high-confidence threats
		if threat.Confidence >= 0.8 && threat.Severity >= cybersecurity.SeverityHigh {
			// Report as security incident
			bc.SecurityManager.ReportIncident(
				fmt.Sprintf("High-confidence threat in transaction %s", tx.ID),
				threat.Description,
				"automated_system",
				threat.Severity,
				cybersecurity.CategoryBreach,
			)
			return fmt.Errorf("transaction blocked due to security threat: %s", threat.Description)
		}
	}

	// Check access permissions
	allowed, reason := bc.SecurityManager.CheckAccess(tx.From, "blockchain_transaction", "submit")
	if !allowed {
		bc.SecurityManager.LogSecurityEvent(
			tx.From,
			"transaction_access_denied",
			tx.ID,
			cybersecurity.AuditFailure,
			reason,
		)
		return fmt.Errorf("transaction access denied: %s", reason)
	}

	// Log successful validation
	bc.SecurityManager.LogSecurityEvent(
		tx.From,
		"transaction_security_validated",
		tx.ID,
		cybersecurity.AuditSuccess,
		"Transaction passed security validation",
	)

	return nil
}

// ValidateBlockSecurity performs security validation on blocks
func (bc *Blockchain) ValidateBlockSecurity(block *Block) error {
	if bc.SecurityManager == nil {
		return nil
	}

	// Serialize block for analysis
	blockData, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to serialize block for security analysis: %v", err)
	}

	// Detect threats in block data
	threats := bc.SecurityManager.DetectThreats(blockData, fmt.Sprintf("block:%s", block.Hash))

	// Process detected threats
	for _, threat := range threats {
		if threat.Confidence >= 0.7 && threat.Severity >= cybersecurity.SeverityMedium {
			bc.SecurityManager.ReportIncident(
				fmt.Sprintf("Security threat in block %s", block.Hash),
				threat.Description,
				"automated_system",
				threat.Severity,
				cybersecurity.CategoryBreach,
			)
			return fmt.Errorf("block rejected due to security threat: %s", threat.Description)
		}
	}

	return nil
}

// GetSecurityMetrics returns current security metrics
func (bc *Blockchain) GetSecurityMetrics() map[string]interface{} {
	if bc.SecurityManager == nil {
		return map[string]interface{}{
			"status": "not_initialized",
		}
	}

	metrics := bc.SecurityManager.GetSecurityMetrics()
	metrics["blockchain_integration"] = "active"
	metrics["last_security_check"] = time.Now()

	return metrics
}

// AddSecurityRule adds a custom security rule to the blockchain
func (bc *Blockchain) AddSecurityRule(contractID string, rule cybersecurity.SecurityRule) error {
	if bc.SecurityManager == nil {
		return fmt.Errorf("security manager not initialized")
	}

	return bc.SecurityManager.AddSecurityRule(contractID, rule)
}

// ReportSecurityIncident reports a security incident
func (bc *Blockchain) ReportSecurityIncident(title, description, reporter string, severity cybersecurity.SeverityLevel) error {
	if bc.SecurityManager == nil {
		return fmt.Errorf("security manager not initialized")
	}

	_, err := bc.SecurityManager.ReportIncident(title, description, reporter, severity, cybersecurity.CategoryBreach)
	return err
}
