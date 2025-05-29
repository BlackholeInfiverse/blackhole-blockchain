package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/api"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/consensus"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/crypto"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
)

func main() {
	// Register blockchain types
	chain.RegisterGobTypes()

	// Setup context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Get port from args (default 3000)
	port := 3000
	if len(os.Args) > 1 {
		fmt.Sscanf(os.Args[1], "%d", &port)
	}

	// Initialize blockchain
	bc, err := chain.NewBlockchain(port)
	if err != nil {
		log.Fatal("Failed to create blockchain:", err)
	}

	// Node ID for logging
	nodeID := fmt.Sprintf("node_%d", port)
	fmt.Printf("🚀 Peer multiaddr: /ip4/127.0.0.1/tcp/%d/p2p/%s\n", port, bc.P2PNode.Host.ID())

	// Connect to peers from args
	if len(os.Args) > 2 {
		for _, addr := range os.Args[2:] {
			if strings.Contains(addr, "12D3KooWKzQh2siF6pAidubw16GrZDhRZqFSeEJFA7BCcKvpopmG") {
				fmt.Println("🚫 Skipping problematic peer:", addr)
				continue
			}
			fmt.Println("🌐 Connecting to:", addr)
			if err := bc.P2PNode.Connect(ctx, addr); err != nil {
				log.Println("❌ Connection failed:", err)
			}
		}
	}

	// Set blockchain for P2P node
	bc.P2PNode.SetChain(bc)

	// Initialize TokenX
	t := token.NewToken("BlackHole", "BLH", 18, 1000000000)

	// Initialize consensus
	consensus.Validators = make(map[string]*consensus.Validator)
	consensus.Stakes = make(map[string]*consensus.Stake)
	consensus.Rewards = []consensus.Reward{}
	validator := consensus.NewValidator(bc.StakeLedger)

	// Generate test key pair for initial staking
	_, pubKey1, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	// Mint and stake initial TokenX
	err = t.Mint(pubKey1, 10000)
	if err != nil {
		log.Fatal(err)
	}
	err = consensus.StakeTokens(pubKey1, "", 1000, "validator")
	if err != nil {
		log.Fatal(err)
	}

	// Start API server for dApps
	log.Println("Starting Relay Chain API server...")
	go api.StartServer()

	// Periodic reward distribution (hourly)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.Tick(1 * time.Hour):
				log.Println("Distributing rewards...")
				consensus.DistributeRewards(time.Now().Unix(), t)
			}
		}
	}()

	// Periodic blockchain state logging
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := bc.LogBlockchainState(nodeID); err != nil {
					log.Printf("❌ Failed to log blockchain state: %v", err)
				}
			}
		}
	}()

	// Mining loop
	go func() {
		ticker := time.NewTicker(6 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				validatorAddr := validator.SelectValidator()
				if validatorAddr == "" {
					log.Println("⚠️ No validator selected")
					continue
				}
				block := bc.MineBlock(validatorAddr)
				if validator.ValidateBlock(block, bc) {
					bc.BroadcastBlock(block)
					time.Sleep(500 * time.Millisecond)
					if bc.AddBlock(block) {
						bc.StakeLedger.AddStake(block.Header.Validator, bc.BlockReward)
						bc.TotalSupply += bc.BlockReward
						log.Printf("✅ Block %d added", block.Header.Index)
					} else {
						log.Printf("⚠️ Failed to add block %d", block.Header.Index)
					}
				} else {
					log.Printf("❌ Failed to validate block %d", block.Header.Index)
				}
			}
		}
	}()

	// Handle interrupts
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		if err := bc.LogBlockchainState(nodeID); err != nil {
			log.Printf("❌ Failed to log final state: %v", err)
		}
		cancel()
	}()

	// Start CLI
	startCLI(ctx, bc, validator, nodeID)
}

func startCLI(ctx context.Context, bc *chain.Blockchain, validator *consensus.Validator, nodeID string) {
	fmt.Println("🖥️ BlackHole Blockchain CLI")
	fmt.Println("Commands: status, mine, log, list, compare, exit")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			return
		}
		switch scanner.Text() {
		case "status":
			fmt.Printf("📊 Block height: %d\nPending Txs: %d\nTotal Supply: %d BLH\nLatest Hash: %s\n",
				len(bc.Blocks), len(bc.PendingTxs), bc.TotalSupply, bc.Blocks[len(bc.Blocks)-1].CalculateHash())
		case "mine":
			fmt.Println("⛏️ Mining block...")
			validatorAddr := validator.SelectValidator()
			if validatorAddr != "" {
				block := bc.MineBlock(validatorAddr)
				if validator.ValidateBlock(block, bc) {
					bc.BroadcastBlock(block)
					time.Sleep(500 * time.Millisecond)
					if bc.AddBlock(block) {
						bc.StakeLedger.AddStake(block.Header.Validator, bc.BlockReward)
						bc.TotalSupply += bc.BlockReward
						fmt.Printf("✅ Block %d added\n", block.Header.Index)
					}
				}
			}
		case "log":
			if err := bc.LogBlockchainState(nodeID); err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else {
				fmt.Println("✅ State logged")
			}
		case "list":
			files, err := chain.ListBlockchainStateFiles()
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else if len(files) == 0 {
				fmt.Println("No state files")
			} else {
				for i, file := range files {
					fmt.Printf("%d. %s\n", i+1, file)
				}
			}
		case "compare":
			files, err := chain.ListBlockchainStateFiles()
			if err != nil || len(files) < 2 {
				fmt.Println("❌ Need 2+ state files")
				continue
			}
			fmt.Println("📋 State files:")
			for i, file := range files {
				fmt.Printf("%d. %s\n", i+1, file)
			}
			fmt.Println("🔍 Enter first file number:")
			scanner.Scan()
			idx1, _ := strconv.Atoi(scanner.Text())
			if idx1 < 1 || idx1 > len(files) {
				fmt.Println("❌ Invalid number")
			 continue
			}
			fmt.Println("🔍 Enter second file number:")
			scanner.Scan()
			idx2, _ := strconv.Atoi(scanner.Text())
			if idx2 < 1 || idx2 > len(files) {
				fmt.Println("❌ Invalid number")
			 continue
			}
			result, err := chain.CompareBlockchainStates(files[idx1-1], files[idx2-1])
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else {
				fmt.Println(result)
			}
		case "exit":
			fmt.Println("👋 Shutting down...")
			os.Exit(0)
		default:
			fmt.Println("❓ Unknown command")
		}
	}
}