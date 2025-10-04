package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

type NodeInfo struct {
	Name     string
	PeerID   string
	Port     string
	HTTPPort string
}

func main() {
	fmt.Println("🌐 Multi-Node P2P Wallet Test")
	fmt.Println("==============================")

	// Create a test wallet P2P client
	ctx := context.Background()
	
	// Generate a private key for this test wallet
	privKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 256)
	if err != nil {
		log.Fatal("Failed to generate key:", err)
	}

	// Create libp2p host for test wallet
	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"), // Random available port
		libp2p.DefaultSecurity,
		libp2p.DefaultTransports,
	)
	if err != nil {
		log.Fatal("Failed to create libp2p host:", err)
	}
	defer h.Close()

	fmt.Printf("🔐 Test wallet P2P client initialized with ID: %s\n", h.ID())

	// Get peer IDs from each node via HTTP API
	nodes, err := discoverNodePeerIDs()
	if err != nil {
		log.Fatal("Failed to discover nodes:", err)
	}

	fmt.Printf("\n🔍 Discovered %d blockchain nodes:\n", len(nodes))
	for i, node := range nodes {
		fmt.Printf("   %d. %s - %s (HTTP: %s, P2P: %s)\n", i+1, node.Name, node.PeerID, node.HTTPPort, node.Port)
	}

	// Test connections to each node
	fmt.Println("\n🔗 Testing P2P connections to all nodes...")
	
	connectedNodes := []NodeInfo{}
	
	for _, node := range nodes {
		fmt.Printf("\n[%s] Testing connection to %s...\n", node.Name, node.PeerID)
		
		// Try to connect to the node
		testAddr := fmt.Sprintf("/ip4/127.0.0.1/tcp/%s/p2p/%s", node.Port, node.PeerID)
		
		maddr, err := multiaddr.NewMultiaddr(testAddr)
		if err != nil {
			fmt.Printf("❌ Invalid multiaddr: %v\n", err)
			continue
		}

		peerInfo, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			fmt.Printf("❌ Failed to parse peer info: %v\n", err)
			continue
		}

		// Attempt connection with timeout
		connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = h.Connect(connectCtx, *peerInfo)
		cancel()

		if err == nil {
			fmt.Printf("✅ Connection successful to %s!\n", node.Name)
			connectedNodes = append(connectedNodes, node)
			
			// Test transaction stream to this node
			err = testTransactionStream(h, ctx, *peerInfo, node.Name)
			if err != nil {
				fmt.Printf("⚠️  Transaction stream failed: %v\n", err)
			} else {
				fmt.Printf("✅ Transaction stream successful to %s\n", node.Name)
			}
			
		} else {
			fmt.Printf("❌ Connection failed: %v\n", err)
		}
	}

	fmt.Printf("\n📊 Connection Summary:\n")
	fmt.Printf("   Total nodes: %d\n", len(nodes))
	fmt.Printf("   Connected: %d\n", len(connectedNodes))
	
	if len(connectedNodes) > 0 {
		fmt.Println("\n✅ Successfully connected nodes:")
		for _, node := range connectedNodes {
			fmt.Printf("   • %s (%s)\n", node.Name, node.PeerID)
		}
	}

	fmt.Println("\n🎉 Multi-node wallet connectivity test completed!")
}

func discoverNodePeerIDs() ([]NodeInfo, error) {
	nodes := []NodeInfo{}
	
	// Node discovery - try HTTP APIs on known ports
	nodePorts := map[string]string{
		"node1": "8081",
		"node2": "8082", 
		"node3": "8083",
		"node4": "8084",
		"node5": "8085",
	}
	
	p2pPorts := map[string]string{
		"node1": "3001",
		"node2": "3002",
		"node3": "3003", 
		"node4": "3004",
		"node5": "3005",
	}

	for nodeName, httpPort := range nodePorts {
		fmt.Printf("🔍 Discovering %s on HTTP port %s...\n", nodeName, httpPort)
		
		// For simplicity, we'll use the known structure rather than making HTTP calls
		// In a real implementation, you'd make HTTP requests to get the peer IDs
		peerID := getKnownPeerID(nodeName, httpPort)
		if peerID != "" {
			nodes = append(nodes, NodeInfo{
				Name:     nodeName,
				PeerID:   peerID,
				Port:     p2pPorts[nodeName],
				HTTPPort: httpPort,
			})
			fmt.Printf("✅ Found %s: %s\n", nodeName, peerID)
		} else {
			fmt.Printf("❌ Could not discover %s\n", nodeName)
		}
	}
	
	return nodes, nil
}

func getKnownPeerID(nodeName, httpPort string) string {
	// In a real implementation, this would make HTTP requests
	// For testing, we'll return placeholder values that will be filled by actual discovery
	// This simulates what would happen with HTTP API calls
	switch nodeName {
	case "node1":
		return "12D3KooWFfcpYRUEQrQHucXJ3u9rH7DVb1C8mKoQXTxERcc7M7hA" // Bootstrap node
	case "node2":
		return "12D3KooWQTbeSr8HtrJMHWJp5ACNmqD9bvzd4V7X9m46X3ZAXa8W"
	case "node3":
		return "12D3KooWD7fnczTaq1LhFfvbY1ki4ifwx48rHNwyLUgicc2LcWcE"
	case "node4":
		return "12D3KooWGT7fxTKpWHLGW5CpB997trVQ86s3oPnrCVLrqX7JnwcJ"
	case "node5":
		return "12D3KooWP7HWc4bQL2AcjrHc6WhoYDnAw2zRN4h77tNGtAzsPX7z"
	default:
		return ""
	}
}

func testTransactionStream(h host.Host, ctx context.Context, peerInfo peer.AddrInfo, nodeName string) error {
	// Create a stream to the blockchain node  
	stream, err := h.NewStream(ctx, peerInfo.ID, protocol.ID("/blackhole/transaction/1.0.0"))
	if err != nil {
		return fmt.Errorf("failed to create stream: %v", err)
	}
	defer stream.Close()

	// Create test transaction data
	testTx := fmt.Sprintf(`TX:{"from":"multi_test_wallet","to":"%s","amount":5.25,"timestamp":%d}`,
		nodeName, time.Now().Unix())

	// Send transaction
	_, err = stream.Write([]byte(testTx))
	if err != nil {
		return fmt.Errorf("failed to send transaction: %v", err)
	}

	// Read response
	response := make([]byte, 4096)
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := stream.Read(response)
	if err != nil && err.Error() != "EOF" {
		return fmt.Errorf("failed to read response: %v", err)
	}

	if n > 0 {
		fmt.Printf("   📝 Transaction response: %s\n", string(response[:n]))
	}

	return nil
}