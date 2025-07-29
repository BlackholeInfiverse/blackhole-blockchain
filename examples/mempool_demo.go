package main

import (
	"fmt"
	"log"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

func main() {
	fmt.Println("🔗 BlackHole Blockchain Mempool Demo")
	fmt.Println("====================================")
	fmt.Println("Demonstrating automatic block creation when 3 transactions are in mempool")
	fmt.Println()

	// Initialize blockchain
	blockchain := initializeBlockchain()

	// Show initial status
	fmt.Println("📊 Initial Blockchain Status:")
	showBlockchainStatus(blockchain)
	fmt.Println()

	// Demo 1: Add transactions one by one and watch auto-block creation
	fmt.Println("🧪 Demo 1: Adding transactions to trigger auto-block creation")
	fmt.Println("------------------------------------------------------------")

	// Transaction 1
	fmt.Println("📤 Adding transaction 1...")
	tx1 := createTestTransaction("alice", "bob", 100, "BHX", 1)
	err := blockchain.ProcessTransaction(tx1)
	if err != nil {
		log.Printf("Error processing transaction 1: %v", err)
	}
	showMempoolStatus(blockchain)
	time.Sleep(500 * time.Millisecond)

	// Transaction 2
	fmt.Println("\n📤 Adding transaction 2...")
	tx2 := createTestTransaction("bob", "charlie", 50, "BHX", 2)
	err = blockchain.ProcessTransaction(tx2)
	if err != nil {
		log.Printf("Error processing transaction 2: %v", err)
	}
	showMempoolStatus(blockchain)
	time.Sleep(500 * time.Millisecond)

	// Transaction 3 - This should trigger auto-block creation
	fmt.Println("\n📤 Adding transaction 3 (should trigger auto-block creation)...")
	tx3 := createTestTransaction("charlie", "dave", 25, "BHX", 3)
	err = blockchain.ProcessTransaction(tx3)
	if err != nil {
		log.Printf("Error processing transaction 3: %v", err)
	}
	showMempoolStatus(blockchain)

	// Wait for auto-block creation to complete
	fmt.Println("\n⏳ Waiting for auto-block creation...")
	time.Sleep(2 * time.Second)

	// Show final status
	fmt.Println("\n📊 Final Blockchain Status:")
	showBlockchainStatus(blockchain)
	fmt.Println()

	// Demo 2: Configure different threshold
	fmt.Println("🧪 Demo 2: Configuring different mempool threshold")
	fmt.Println("------------------------------------------------")

	// Set threshold to 2 transactions
	blockchain.SetMempoolThreshold(2)
	showMempoolStatus(blockchain)

	// Add transactions to test new threshold
	fmt.Println("\n📤 Adding transaction 4...")
	tx4 := createTestTransaction("dave", "eve", 10, "BHX", 4)
	err = blockchain.ProcessTransaction(tx4)
	if err != nil {
		log.Printf("Error processing transaction 4: %v", err)
	}
	showMempoolStatus(blockchain)
	time.Sleep(500 * time.Millisecond)

	// Transaction 5 - Should trigger auto-block creation with threshold=2
	fmt.Println("\n📤 Adding transaction 5 (should trigger auto-block creation with threshold=2)...")
	tx5 := createTestTransaction("eve", "frank", 5, "BHX", 5)
	err = blockchain.ProcessTransaction(tx5)
	if err != nil {
		log.Printf("Error processing transaction 5: %v", err)
	}
	showMempoolStatus(blockchain)

	// Wait for auto-block creation
	fmt.Println("\n⏳ Waiting for auto-block creation...")
	time.Sleep(2 * time.Second)

	// Show final status
	fmt.Println("\n📊 Final Blockchain Status:")
	showBlockchainStatus(blockchain)

	// Demo 3: Show mempool configuration options
	fmt.Println("\n🧪 Demo 3: Mempool Configuration Options")
	fmt.Println("---------------------------------------")

	// Test different thresholds
	thresholds := []int{1, 5, 10}
	for _, threshold := range thresholds {
		blockchain.SetMempoolThreshold(threshold)
		status := blockchain.GetMempoolStatus()
		fmt.Printf("Threshold %d: %v\n", threshold, status)
	}

	fmt.Println("\n✅ Mempool demo completed!")
	fmt.Println("🎯 Key Features Demonstrated:")
	fmt.Println("   - Automatic block creation when mempool threshold is reached")
	fmt.Println("   - Configurable mempool threshold")
	fmt.Println("   - Real-time mempool status monitoring")
	fmt.Println("   - Transaction batching into blocks")
}

func initializeBlockchain() *chain.Blockchain {
	// Create a new blockchain instance
	blockchain := &chain.Blockchain{
		Blocks:           make([]*chain.Block, 0),
		PendingTxs:       make([]*chain.Transaction, 0),
		MempoolThreshold: 3, // Default threshold
	}

	// Initialize basic components
	blockchain.StakeLedger = chain.NewStakeLedger()
	blockchain.GlobalState = make(map[string]*chain.AccountState)
	blockchain.BlockReward = 10

	log.Println("✅ Blockchain initialized with mempool auto-block creation")
	return blockchain
}

func createTestTransaction(from, to string, amount uint64, tokenID string, nonce uint64) *chain.Transaction {
	tx := &chain.Transaction{
		Type:      chain.TokenTransfer,
		From:      from,
		To:        to,
		Amount:    amount,
		TokenID:   tokenID,
		Fee:       1,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
	}
	tx.ID = tx.CalculateHash()
	return tx
}

func showBlockchainStatus(blockchain *chain.Blockchain) {
	fmt.Printf("   📦 Total blocks: %d\n", len(blockchain.Blocks))
	fmt.Printf("   🔗 Chain height: %d\n", len(blockchain.Blocks)-1)
	
	if len(blockchain.Blocks) > 0 {
		latestBlock := blockchain.Blocks[len(blockchain.Blocks)-1]
		fmt.Printf("   🏷️  Latest block: #%d with %d transactions\n", 
			latestBlock.Header.Index, len(latestBlock.Transactions))
		fmt.Printf("   🕒 Latest block time: %s\n", 
			latestBlock.Header.Timestamp.Format("15:04:05"))
	}
	
	showMempoolStatus(blockchain)
}

func showMempoolStatus(blockchain *chain.Blockchain) {
	status := blockchain.GetMempoolStatus()
	fmt.Printf("   💾 Mempool status: %s\n", status["progress"])
	fmt.Printf("   🎯 Auto-block ready: %v\n", status["auto_block_ready"])
	
	if status["auto_block_ready"].(bool) {
		fmt.Printf("   🔥 THRESHOLD REACHED - Block creation will be triggered!\n")
	}
}
