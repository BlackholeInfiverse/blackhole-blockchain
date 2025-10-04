package main

import (
	"fmt"
	"log"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

func main() {
	fmt.Println("🚀 Testing blockchain initialization...")
	
	chain.RegisterGobTypes()
	
	bc, err := chain.NewBlockchain(3000)
	if err != nil {
		log.Fatal("Failed to create blockchain:", err)
	}
	
	fmt.Printf("✅ Blockchain initialized successfully!\n")
	fmt.Printf("📊 Block height: %d\n", len(bc.Blocks))
	fmt.Printf("🆔 Legacy P2P ID: %s\n", bc.P2PNode.Host.ID())
	
	if bc.SecureP2PNode != nil {
		fmt.Printf("🔐 Secure P2P ID: %s\n", bc.SecureP2PNode.Host.ID())
		fmt.Printf("👥 Connected peers: %d\n", len(bc.SecureP2PNode.GetConnectedPeers()))
	} else {
		fmt.Printf("❌ Secure P2P node not initialized\n")
	}
	
	fmt.Println("🎯 Test completed successfully!")
}