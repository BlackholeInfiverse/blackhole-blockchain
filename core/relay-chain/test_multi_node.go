package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

func startNode(port int, ctx context.Context) (*chain.Blockchain, error) {
	fmt.Printf("🚀 Starting node on port %d...\n", port)
	
	bc, err := chain.NewBlockchain(port)
	if err != nil {
		return nil, fmt.Errorf("failed to create blockchain: %v", err)
	}
	
	if bc.SecureP2PNode != nil {
		bc.SecureP2PNode.SetBlockchain(bc)
		fmt.Printf("✅ Node %d initialized - Secure P2P ID: %s\n", port, bc.SecureP2PNode.Host.ID())
	}
	
	// Start a transaction generator for this node
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Create a test transaction
				tx := &chain.Transaction{
					ID:        fmt.Sprintf("test-tx-%d-%d", port, time.Now().Unix()),
					Type:      chain.TokenTransfer,
					From:      "genesis-validator",
					To:        "test-receiver",
					Amount:    1,
					TokenID:   "BHX",
					Timestamp: time.Now().Unix(),
					Nonce:     0,
				}
				
				// Add to pending transactions
				err := bc.ProcessTransaction(tx)
				if err != nil {
					fmt.Printf("⚠️  Node %d: Failed to process transaction: %v\n", port, err)
					continue
				}
				fmt.Printf("🔄 Node %d: Added test transaction %s\n", port, tx.ID)
				
				// Broadcast transaction
				bc.BroadcastTransaction(tx)
			}
		}
	}()
	
	return bc, nil
}

func main() {
	fmt.Println("🌐 Testing multi-node P2P network...")
	
	chain.RegisterGobTypes()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Start first node
	node1, err := startNode(4000, ctx)
	if err != nil {
		log.Fatal("Failed to start node 1:", err)
	}
	
	// Wait a bit for first node to initialize
	time.Sleep(2 * time.Second)
	
	// Start second node
	node2, err := startNode(4001, ctx)
	if err != nil {
		log.Fatal("Failed to start node 2:", err)
	}
	
	// Wait for peer discovery
	fmt.Println("⏳ Waiting for peer discovery...")
	time.Sleep(10 * time.Second)
	
	// Check peer connections
	if node1.SecureP2PNode != nil && node2.SecureP2PNode != nil {
		peers1 := node1.SecureP2PNode.GetConnectedPeers()
		peers2 := node2.SecureP2PNode.GetConnectedPeers()
		
		fmt.Printf("👥 Node 1 connected peers: %d\n", len(peers1))
		fmt.Printf("👥 Node 2 connected peers: %d\n", len(peers2))
		
		if len(peers1) > 0 || len(peers2) > 0 {
			fmt.Println("✅ Peer discovery working!")
		} else {
			fmt.Println("⚠️  No peers discovered - check mDNS or network configuration")
		}
	}
	
	// Monitor for a while
	fmt.Println("🔄 Monitoring network for 30 seconds...")
	time.Sleep(30 * time.Second)
	
	// Final stats
	fmt.Printf("📊 Final stats:\n")
	fmt.Printf("   Node 1 - Blocks: %d, Pending Txs: %d\n", len(node1.Blocks), len(node1.PendingTxs))
	fmt.Printf("   Node 2 - Blocks: %d, Pending Txs: %d\n", len(node2.Blocks), len(node2.PendingTxs))
	
	if node1.SecureP2PNode != nil && node2.SecureP2PNode != nil {
		fmt.Printf("   Node 1 peers: %d, Node 2 peers: %d\n", 
			len(node1.SecureP2PNode.GetConnectedPeers()),
			len(node2.SecureP2PNode.GetConnectedPeers()))
	}
	
	fmt.Println("🎯 Multi-node test completed!")
}