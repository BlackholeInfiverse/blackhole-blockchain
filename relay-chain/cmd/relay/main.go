package relay

import (
	"log"
	"time"
	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/api"
	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/consensus"
	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/token"
)

func Run() {
	// Initialize token instance
	t := token.NewToken("TokenX", "TX", 18, 0)

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
		time.Sleep(10 * time.Second)
		log.Println("Distributing rewards for epoch 1...")
		consensus.DistributeRewards(1, t)
	}()

	// Keep the node running
	select {}
}