package main

import (
	"fmt"
	"log"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

func main() {
	fmt.Println("🔗 BlackHole Blockchain Simple Mempool Demo")
	fmt.Println("===========================================")
	fmt.Println("Demonstrating automatic block creation when 3 transactions are in mempool")
	fmt.Println()

	// Initialize blockchain with some initial balances
	blockchain := initializeBlockchainWithBalances()

	// Show initial status
	fmt.Println("📊 Initial Blockchain Status:")
	showBlockchainStatus(blockchain)
	fmt.Println()

	// Demo: Add transactions one by one and watch auto-block creation
	fmt.Println("🧪 Adding transactions to trigger auto-block creation")
	fmt.Println("----------------------------------------------------")

	// Transaction 1
	fmt.Println("📤 Adding transaction 1...")
	tx1 := createRegularTransaction("alice", "bob", 100, 1)
	err := blockchain.ProcessTransaction(tx1)
	if err != nil {
		log.Printf("Error processing transaction 1: %v", err)
	} else {
		fmt.Printf("✅ Transaction 1 added successfully\n")
	}
	showMempoolStatus(blockchain)
	time.Sleep(500 * time.Millisecond)

	// Transaction 2
	fmt.Println("\n📤 Adding transaction 2...")
	tx2 := createRegularTransaction("bob", "charlie", 50, 2)
	err = blockchain.ProcessTransaction(tx2)
	if err != nil {
		log.Printf("Error processing transaction 2: %v", err)
	} else {
		fmt.Printf("✅ Transaction 2 added successfully\n")
	}
	showMempoolStatus(blockchain)
	time.Sleep(500 * time.Millisecond)

	// Transaction 3 - This should trigger auto-block creation
	fmt.Println("\n📤 Adding transaction 3 (should trigger auto-block creation)...")
	tx3 := createRegularTransaction("charlie", "dave", 25, 3)
	err = blockchain.ProcessTransaction(tx3)
	if err != nil {
		log.Printf("Error processing transaction 3: %v", err)
	} else {
		fmt.Printf("✅ Transaction 3 added successfully\n")
	}
	showMempoolStatus(blockchain)

	// Wait for auto-block creation to complete
	fmt.Println("\n⏳ Waiting for auto-block creation...")
	time.Sleep(3 * time.Second)

	// Show final status
	fmt.Println("\n📊 Final Blockchain Status:")
	showBlockchainStatus(blockchain)
	fmt.Println()

	// Demo 2: Test with different threshold
	fmt.Println("🧪 Demo 2: Testing with threshold = 2")
	fmt.Println("------------------------------------")

	// Set threshold to 2 transactions
	blockchain.SetMempoolThreshold(2)
	showMempoolStatus(blockchain)

	// Add transactions to test new threshold
	fmt.Println("\n📤 Adding transaction 4...")
	tx4 := createRegularTransaction("dave", "eve", 10, 4)
	err = blockchain.ProcessTransaction(tx4)
	if err != nil {
		log.Printf("Error processing transaction 4: %v", err)
	} else {
		fmt.Printf("✅ Transaction 4 added successfully\n")
	}
	showMempoolStatus(blockchain)
	time.Sleep(500 * time.Millisecond)

	// Transaction 5 - Should trigger auto-block creation with threshold=2
	fmt.Println("\n📤 Adding transaction 5 (should trigger auto-block creation with threshold=2)...")
	tx5 := createRegularTransaction("eve", "frank", 5, 5)
	err = blockchain.ProcessTransaction(tx5)
	if err != nil {
		log.Printf("Error processing transaction 5: %v", err)
	} else {
		fmt.Printf("✅ Transaction 5 added successfully\n")
	}
	showMempoolStatus(blockchain)

	// Wait for auto-block creation
	fmt.Println("\n⏳ Waiting for auto-block creation...")
	time.Sleep(3 * time.Second)

	// Show final status
	fmt.Println("\n📊 Final Blockchain Status:")
	showBlockchainStatus(blockchain)

	fmt.Println("\n✅ Simple mempool demo completed!")
	fmt.Println("🎯 Key Features Demonstrated:")
	fmt.Println("   - Automatic block creation when mempool threshold is reached")
	fmt.Println("   - Configurable mempool threshold")
	fmt.Println("   - Real-time mempool status monitoring")
	fmt.Println("   - Transaction batching into blocks")
}

func initializeBlockchainWithBalances() *chain.Blockchain {
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

	// Set up initial balances for demo accounts
	blockchain.GlobalState["alice"] = &chain.AccountState{Balance: 1000, Nonce: 0}
	blockchain.GlobalState["bob"] = &chain.AccountState{Balance: 500, Nonce: 0}
	blockchain.GlobalState["charlie"] = &chain.AccountState{Balance: 300, Nonce: 0}
	blockchain.GlobalState["dave"] = &chain.AccountState{Balance: 200, Nonce: 0}
	blockchain.GlobalState["eve"] = &chain.AccountState{Balance: 100, Nonce: 0}
	blockchain.GlobalState["frank"] = &chain.AccountState{Balance: 50, Nonce: 0}

	log.Println("✅ Blockchain initialized with mempool auto-block creation and initial balances")
	return blockchain
}

func createRegularTransaction(from, to string, amount uint64, nonce uint64) *chain.Transaction {
	tx := &chain.Transaction{
		Type:      chain.RegularTransfer,
		From:      from,
		To:        to,
		Amount:    amount,
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
		
		// Show some transaction details from the latest block
		if len(latestBlock.Transactions) > 1 { // Skip reward transaction
			fmt.Printf("   📋 Recent transactions in latest block:\n")
			for i, tx := range latestBlock.Transactions {
				if i == 0 {
					fmt.Printf("      - Reward: %d to %s\n", tx.Amount, tx.To)
				} else {
					fmt.Printf("      - Transfer: %s → %s (%d)\n", tx.From, tx.To, tx.Amount)
				}
			}
		}
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
	
	// Show pending transactions
	if len(blockchain.PendingTxs) > 0 {
		fmt.Printf("   📋 Pending transactions:\n")
		for i, tx := range blockchain.PendingTxs {
			fmt.Printf("      %d. %s → %s (%d)\n", i+1, tx.From, tx.To, tx.Amount)
		}
	}
}
