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
	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize blockchain with P2P
	bc, err := chain.NewBlockchain(3000)
	if err != nil {
		log.Fatal(err)
	}

	// Connect to bootstrap nodes (if any)
	if len(os.Args) > 1 {
		for _, addr := range os.Args[1:] {
			if err := bc.P2PNode.Connect(ctx, addr); err != nil {
				log.Printf("Failed to connect to %s: %v", addr, err)
			}
		}
	}

	// Initialize consensus with StakeLedger
	validator := consensus.NewValidator(bc.StakeLedger)

	// Set blockchain reference in P2P node
	bc.P2PNode.SetChain(bc)

	// Start blockchain sync
	go bc.SyncChain()

	// Handle interrupts
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		cancel()
	}()

	// Start mining loop
	go mineBlocks(ctx, bc, validator)

	// Start CLI
	startCLI(ctx, bc, validator)
}

func mineBlocks(ctx context.Context, bc *chain.Blockchain, validator *consensus.Validator) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Mining logic
			selectedValidator := validator.SelectValidator()
			if selectedValidator == "" {
				log.Println("No validator selected")
				continue
			}
			block := bc.MineBlock(selectedValidator)

			if validator.ValidateBlock(block, bc) {
				bc.BroadcastBlock(block)
				fmt.Printf("Mined block %d\n", block.Header.Index)
			} else {
				log.Println("Failed to validate block")
			}
		}
	}
}

func startCLI(ctx context.Context, bc *chain.Blockchain, validator *consensus.Validator) {
	// Simple CLI interface
	fmt.Println("BlackHole Blockchain CLI")
	fmt.Println("Commands:")
	fmt.Println("  status - Show blockchain status")
	fmt.Println("  exit - Shutdown node")

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

			cmd := scanner.Text()
			switch cmd {
			case "status":
				fmt.Printf("Block height: %d\n", len(bc.Blocks))
				fmt.Printf("Pending transactions: %d\n", len(bc.PendingTxs))
			case "exit":
				fmt.Println("Shutting down...")
				return
			default:
				fmt.Println("Unknown command")
			}
		}
	}
}