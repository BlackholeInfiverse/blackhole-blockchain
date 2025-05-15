package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/consensus"
)

func main() {
	// Setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize blockchain
	bc, err := chain.NewBlockchain(3000)
	if err != nil {
		log.Fatalf("❌ Failed to initialize blockchain: %v", err)
	}
	fmt.Printf("✅ StakeLedger: %+v\n", bc.StakeLedger)

	// Connect to peers if given
	if len(os.Args) > 1 {
		for _, addr := range os.Args[1:] {
			if err := bc.P2PNode.Connect(ctx, addr); err != nil {
				log.Printf("⚠️  Could not connect to %s: %v", addr, err)
			}
		}
	}

	// Setup PoS validator
	validator := consensus.NewValidator(bc.StakeLedger)
	bc.P2PNode.SetChain(bc)

	// Start chain sync in background
	go bc.SyncChain()

	// Graceful shutdown on CTRL+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\n🛑 Shutting down...")
		cancel()
	}()

	// Start mining loop
	go miningLoop(ctx, bc, validator)

	// Start CLI
	startCLI(ctx, bc)
}

func miningLoop(ctx context.Context, bc *chain.Blockchain, validator *consensus.Validator) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			selectedValidator := validator.SelectValidator()
			if selectedValidator == "" {
				log.Println("⚠️ No validator selected")
				continue
			}

			block := bc.MineBlock(selectedValidator)

			if validator.ValidateBlock(block, bc) {
				// ✅ Append ONLY if valid
				bc.Blocks = append(bc.Blocks, block)
				bc.PendingTxs = []*chain.Transaction{}
				bc.StakeLedger.AddStake(block.Header.Validator, bc.BlockReward)
				bc.TotalSupply += bc.BlockReward

				// ✅ Print details and broadcast
				log.Printf("✅ Block %d added with hash: %s\n", block.Header.Index, block.Hash)
				log.Printf("🕒 Timestamp     : %s", block.Header.Timestamp.Format(time.RFC3339))
log.Printf("🔗 PreviousHash  : %s", block.Header.PreviousHash)
log.Printf("🔐 Current Hash  : %s", block.Hash)
				bc.BroadcastBlock(block)
			} else {
				log.Printf("❌ Failed to validate block %d\n", block.Header.Index)
			}
		}
	}
}

func startCLI(ctx context.Context, bc *chain.Blockchain) {
	fmt.Println("🚀 BlackHole Blockchain CLI")
	fmt.Println("Commands:\n  status\n  exit")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			fmt.Print("> ")
			if !scanner.Scan() {
				return
			}
			switch scanner.Text() {
			case "status":
				fmt.Printf("📊 Height: %d   📦 Pending TXs: %d\n",
					len(bc.Blocks), len(bc.PendingTxs))
			case "exit":
				fmt.Println("👋 Bye!")
				return
			default:
				fmt.Println("❓ Unknown command")
			}
		}
	}
}
