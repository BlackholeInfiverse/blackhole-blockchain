package main

import (
    "bufio"
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"
    "time"
    "strings"

    "github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/chain"
    "github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/consensus"
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

    go bc.SyncChain()

    validator := consensus.NewValidator(bc.StakeLedger)

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, os.Interrupt)
    go func() {
        <-sigCh
        cancel()
    }()

    go miningLoop(ctx, bc, validator)

    startCLI(ctx, bc)
}

// ... (miningLoop, startCLI unchanged)
func miningLoop(ctx context.Context, bc *chain.Blockchain, validator *consensus.Validator) {
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
				bc.Blocks = append(bc.Blocks, block)
				bc.PendingTxs = []*chain.Transaction{}
				bc.StakeLedger.AddStake(block.Header.Validator, bc.BlockReward)
				bc.TotalSupply += bc.BlockReward
				bc.BroadcastBlock(block)

				log.Println("=====================================")
				log.Printf("✅ Block %d added successfully", block.Header.Index)
				log.Printf("🕒 Timestamp     : %s", block.Header.Timestamp.Format(time.RFC3339))
				log.Printf("🔗 PreviousHash  : %s", block.Header.PreviousHash)
				log.Printf("🔐 Current Hash  : %s", block.CalculateHash())
				log.Println("=====================================")
			} else {
				log.Printf("❌ Failed to validate block %d", block.Header.Index)
			}
		}
	}
}

func startCLI(ctx context.Context, bc *chain.Blockchain) {
	fmt.Println("🖥️ BlackHole Blockchain CLI")
	fmt.Println("Available commands:")
	fmt.Println("  status - Show blockchain status")
	fmt.Println("  exit   - Shutdown node")

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
		case "exit":
			fmt.Println("👋 Shutting down...")
			os.Exit(0)
		default:
			fmt.Println("❓ Unknown command")
		}
	}
}
