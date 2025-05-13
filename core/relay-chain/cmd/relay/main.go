package relay

import (
	"fmt"
	"log"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/api"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/consensus"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/crypto"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
)

func Run() {
	// Initialize components
	t := token.NewToken("BlackHole", "BLH", 18, 0)
	// bc := chain.NewBlockchain()
	// validator := consensus.New
	// Validator() // Removed as NewValidator is undefined

	// Initialize consensus state
	consensus.Validators = make(map[string]*consensus.Validator)
	consensus.Stakes = make(map[string]*consensus.Stake)
	consensus.Rewards = []consensus.Reward{}

	// Start API server
	log.Println("Starting Relay Chain API server...")
	go api.StartServer()

	// Schedule reward distribution after a delay for testing
	go func() {
		// Wait 10 seconds to allow staking via API
		log.Println("Waiting 10 seconds before distributing rewards...")
		time.Sleep(30 * time.Second)
		log.Println("Distributing rewards for epoch 1...")
		consensus.DistributeRewards(1, t)
	}()

	// Keep the node running

	// Generate test key pairs
	privKey1, pubKey1, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	// Create sample transaction
	tx := chain.NewTransaction(chain.OTCTransfer, pubKey1, "recipient_address", 100)
	tx.Nonce = 1

	// Sign transaction
	err = tx.Sign(privKey1)
	if err != nil {
		log.Fatal(err)
	}

	// Verify transaction
	pubKey, err := crypto.ParsePublicKey(pubKey1)
	if err != nil {
		log.Fatal(err)
	}

	if tx.Verify(pubKey) {
		fmt.Println("Transaction verified successfully")
	} else {
		fmt.Println("Transaction verification failed")
	}

	// Initialize staking
	err = consensus.StakeTokens(pubKey1, "", 1000, "validator")
	if err != nil {
		log.Fatal(err)
	}

	// Mint tokens
	err = t.Mint(pubKey1, 10000)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Blockchain components initialized successfully")

	select {}
}
