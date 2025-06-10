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
)

func main() {
	chain.RegisterGobTypes()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port := 3000
	if len(os.Args) > 1 {
		fmt.Sscanf(os.Args[1], "%d", &port)
	}

	bc, err := chain.NewBlockchain(port)
	if err != nil {
		log.Fatal("Failed to create blockchain:", err)
	}

	// Create a node ID based on port for logging
	nodeID := fmt.Sprintf("node_%d", port)

	fmt.Println("🚀 Your peer multiaddr:")
	fmt.Printf("   /ip4/127.0.0.1/tcp/%d/p2p/%s\n", port, bc.P2PNode.Host.ID())

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

	bc.P2PNode.SetChain(bc)

	// Log initial blockchain state
	if err := bc.LogBlockchainState(nodeID); err != nil {
		log.Printf("❌ Failed to log blockchain state: %v", err)
	}

	go bc.SyncChain()

	validator := consensus.NewValidator(bc.StakeLedger)

	// Set up periodic blockchain state logging
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		// Log final state before exiting
		if err := bc.LogBlockchainState(nodeID); err != nil {
			log.Printf("❌ Failed to log final blockchain state: %v", err)
		}
		cancel()
	}()

	go miningLoop(ctx, bc, validator, nodeID)

	// Start API server for UI
	apiServer := api.NewAPIServer(bc, 8080)
	go apiServer.Start()

	startCLI(ctx, bc, nodeID)
}
func miningLoop(ctx context.Context, bc *chain.Blockchain, validator *consensus.Validator, nodeID string) {
	ticker := time.NewTicker(6 * time.Second) // Optional minimal interval
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if len(bc.GetPendingTransactions()) == 0 {
				fmt.Println("🚫 No pending transactions, skipping block mining")
				continue // 🚫 No transaction, don't mine
			}

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
					// Get token system for rewards
					tokenSystem := bc.TokenRegistry["BHX"]
					if tokenSystem == nil {
						log.Printf("❌ BHX token not found in registry")
						return
					}

					// Try to mint block reward (respects max supply)
					err := tokenSystem.Mint(block.Header.Validator, bc.BlockReward)
					if err != nil {
						log.Printf("⚠️ Failed to mint block reward: %v", err)
						// Continue without reward if supply limit reached
					} else {
						log.Printf("💰 Block reward of %d BHX minted to %s", bc.BlockReward, block.Header.Validator)
					}

					// Update stake ledger
					bc.StakeLedger.AddStake(block.Header.Validator, bc.BlockReward)

					log.Printf("✅ Block %d added with %d transactions", block.Header.Index, len(block.Transactions))
				}
			}
		}
	}
}

func startCLI(ctx context.Context, bc *chain.Blockchain, nodeID string) {
	fmt.Println("🖥️ BlackHole Blockchain CLI")
	fmt.Println("Available commands:")
	fmt.Println("  status  - Show blockchain status")
	fmt.Println("  log     - Log blockchain state to file")
	fmt.Println("  list    - List all blockchain state files")
	fmt.Println("  compare - Compare blockchain states from two files")
	fmt.Println("  exit    - Shutdown node")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			return
		}

		switch scanner.Text() {
		case "status":
			fmt.Println("📊 Blockchain Status")
			fmt.Printf("  Block height       : %d\n", len(bc.Blocks))
			fmt.Printf("  Pending Tx count   : %d\n", len(bc.PendingTxs))
			fmt.Printf("  Total Supply       : %d BHX\n", bc.TotalSupply)
			fmt.Printf("  Latest Block Hash  : %s\n", bc.Blocks[len(bc.Blocks)-1].CalculateHash())
		case "log":
			fmt.Println("📝 Logging blockchain state...")
			if err := bc.LogBlockchainState(nodeID); err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else {
				fmt.Println("✅ Blockchain state logged successfully")
			}
		case "list":
			fmt.Println("📋 Listing blockchain state files:")
			files, err := chain.ListBlockchainStateFiles()
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else if len(files) == 0 {
				fmt.Println("No blockchain state files found")
			} else {
				for i, file := range files {
					fmt.Printf("%d. %s\n", i+1, file)
				}
			}
		case "compare":
			// First list all available files
			files, err := chain.ListBlockchainStateFiles()
			if err != nil {
				fmt.Printf("❌ Error listing blockchain state files: %v\n", err)
				continue
			}
			if len(files) < 2 {
				fmt.Println("❌ Need at least 2 blockchain state files to compare")
				continue
			}

			fmt.Println("� Available blockchain state files:")
			for i, file := range files {
				fmt.Printf("%d. %s\n", i+1, file)
			}

			// Get first file selection
			fmt.Println("🔍 Enter number of first blockchain state file:")
			scanner.Scan()
			fileNum1 := scanner.Text()
			idx1, err := strconv.Atoi(fileNum1)
			if err != nil || idx1 < 1 || idx1 > len(files) {
				fmt.Println("❌ Invalid file number")
				continue
			}

			// Get second file selection
			fmt.Println("🔍 Enter number of second blockchain state file:")
			scanner.Scan()
			fileNum2 := scanner.Text()
			idx2, err := strconv.Atoi(fileNum2)
			if err != nil || idx2 < 1 || idx2 > len(files) {
				fmt.Println("❌ Invalid file number")
				continue
			}

			// Compare the selected files
			result, err := chain.CompareBlockchainStates(files[idx1-1], files[idx2-1])
			if err != nil {
				fmt.Printf("❌ Error comparing blockchain states: %v\n", err)
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
func MineOnce(ctx context.Context, bc *chain.Blockchain, validator *consensus.Validator, nodeID string) {
	validatorAddr := validator.SelectValidator()
	if validatorAddr == "" {
		log.Println("⚠️ No validator selected")
		return
	}

	block := bc.MineBlock(validatorAddr)
	if validator.ValidateBlock(block, bc) {
		// First broadcast the block
		bc.BroadcastBlock(block)

		// Wait longer to allow network propagation and processing by other nodes
		// This reduces the chance of forks by giving other nodes time to receive
		// and process our block before we add it to our own chain
		fmt.Printf("⏳ Waiting for block propagation...\n")
		time.Sleep(500 * time.Millisecond)

		// Then try to add it to our chain
		if bc.AddBlock(block) {
			// Try to mint block reward (respects max supply)
			tokenSystem := bc.TokenRegistry["BHX"]
			if tokenSystem != nil {
				err := tokenSystem.Mint(block.Header.Validator, bc.BlockReward)
				if err != nil {
					log.Printf("⚠️ Failed to mint block reward: %v", err)
				} else {
					log.Printf("💰 Block reward of %d BHX minted to %s", bc.BlockReward, block.Header.Validator)
				}
			}

			// Update stake ledger
			bc.StakeLedger.AddStake(block.Header.Validator, bc.BlockReward)

			log.Println("=====================================")
			log.Printf("✅ Block %d added successfully", block.Header.Index)
			log.Printf("🕒 Timestamp     : %s", block.Header.Timestamp.Format(time.RFC3339))
			log.Printf("🔗 PreviousHash  : %s", block.Header.PreviousHash)
			log.Printf("🔐 Current Hash  : %s", block.CalculateHash())
			// Display transaction details...
			log.Println("=====================================")

			// Log blockchain state after mining a block
			if err := bc.LogBlockchainState(nodeID); err != nil {
				log.Printf("❌ Failed to log blockchain state after mining: %v", err)
			}
		} else {
			log.Printf("⚠️ Failed to add our own mined block %d to chain", block.Header.Index)
		}
	} else {
		log.Printf("❌ Failed to validate block %d", block.Header.Index)
	}
}
func startCLI1(ctx context.Context, bc *chain.Blockchain, validator *consensus.Validator, nodeID string) {
	fmt.Println("🖥️ BlackHole Blockchain CLI")
	fmt.Println("Available commands:")
	fmt.Println("  status  - Show blockchain status")
	fmt.Println("  mine    - Manually mine a block")
	fmt.Println("  log     - Log blockchain state to file")
	fmt.Println("  list    - List all blockchain state files")
	fmt.Println("  compare - Compare blockchain states from two files")
	fmt.Println("  exit    - Shutdown node")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			return
		}

		switch scanner.Text() {
		case "status":
			fmt.Println("📊 Blockchain Status")
			fmt.Printf("  Block height       : %d\n", len(bc.Blocks))
			fmt.Printf("  Pending Tx count   : %d\n", len(bc.PendingTxs))
			fmt.Printf("  Total Supply       : %d BHX\n", bc.TotalSupply)
			fmt.Printf("  Latest Block Hash  : %s\n", bc.Blocks[len(bc.Blocks)-1].CalculateHash())
		case "mine":
			fmt.Println("⛏️ Mining new block...")
			MineOnce(ctx, bc, validator, nodeID)
		case "log":
			fmt.Println("📝 Logging blockchain state...")
			if err := bc.LogBlockchainState(nodeID); err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else {
				fmt.Println("✅ Blockchain state logged successfully")
			}
		case "list":
			fmt.Println("📋 Listing blockchain state files:")
			files, err := chain.ListBlockchainStateFiles()
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else if len(files) == 0 {
				fmt.Println("No blockchain state files found")
			} else {
				for i, file := range files {
					fmt.Printf("%d. %s\n", i+1, file)
				}
			}
		case "compare":
			// First list all available files
			files, err := chain.ListBlockchainStateFiles()
			if err != nil {
				fmt.Printf("❌ Error listing blockchain state files: %v\n", err)
				continue
			}
			if len(files) < 2 {
				fmt.Println("❌ Need at least 2 blockchain state files to compare")
				continue
			}

			fmt.Println("� Available blockchain state files:")
			for i, file := range files {
				fmt.Printf("%d. %s\n", i+1, file)
			}

			// Get first file selection
			fmt.Println("🔍 Enter number of first blockchain state file:")
			scanner.Scan()
			fileNum1 := scanner.Text()
			idx1, err := strconv.Atoi(fileNum1)
			if err != nil || idx1 < 1 || idx1 > len(files) {
				fmt.Println("❌ Invalid file number")
				continue
			}

			// Get second file selection
			fmt.Println("🔍 Enter number of second blockchain state file:")
			scanner.Scan()
			fileNum2 := scanner.Text()
			idx2, err := strconv.Atoi(fileNum2)
			if err != nil || idx2 < 1 || idx2 > len(files) {
				fmt.Println("❌ Invalid file number")
				continue
			}

			// Compare the selected files
			result, err := chain.CompareBlockchainStates(files[idx1-1], files[idx2-1])
			if err != nil {
				fmt.Printf("❌ Error comparing blockchain states: %v\n", err)
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
