package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

func main() {
	fmt.Println("🧪 P2P Connection Test - Wallet to Blockchain")
	fmt.Println("=============================================")

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
	fmt.Printf("🏠 Listening on: %v\n", h.Addrs())

	// Target blockchain peer ID (from the API response - secure P2P Node1)
	targetPeerID := "12D3KooWFfcpYRUEQrQHucXJ3u9rH7DVb1C8mKoQXTxERcc7M7hA"
	
	// Test connection addresses (Docker-exposed ports)
	testAddresses := []string{
		fmt.Sprintf("/ip4/127.0.0.1/tcp/3001/p2p/%s", targetPeerID), // Docker secure P2P
		fmt.Sprintf("/ip4/127.0.0.1/tcp/3100/p2p/%s", targetPeerID), // Docker legacy P2P  
		fmt.Sprintf("/ip4/127.0.0.1/tcp/30303/p2p/%s", targetPeerID), // Docker P2P networking
	}

	peerID, err := peer.Decode(targetPeerID)
	if err != nil {
		log.Fatal("Invalid peer ID:", err)
	}

	var connectedAddr string
	connected := false

	fmt.Println("\n🔍 Testing connection to blockchain node...")

	for i, addrStr := range testAddresses {
		fmt.Printf("\n[%d/%d] Testing: %s\n", i+1, len(testAddresses), addrStr)
		
		maddr, err := multiaddr.NewMultiaddr(addrStr)
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
			fmt.Printf("✅ Connection successful!\n")
			connectedAddr = addrStr
			connected = true
			break
		} else {
			fmt.Printf("❌ Connection failed: %v\n", err)
		}
	}

	if !connected {
		fmt.Println("\n❌ Failed to connect to blockchain node on any address")
		fmt.Println("💡 Make sure the blockchain container is running:")
		fmt.Println("   docker-compose up -d blockchain")
		return
	}

	fmt.Printf("\n✅ Successfully connected via: %s\n", connectedAddr)

	// Test transaction stream
	fmt.Println("\n💸 Testing transaction stream...")
	
	stream, err := h.NewStream(ctx, peerID, protocol.ID("/blackhole/transaction/1.0.0"))
	if err != nil {
		fmt.Printf("❌ Failed to create transaction stream: %v\n", err)
		return
	}
	defer stream.Close()

	fmt.Println("✅ Transaction stream created successfully")

	// Send a test transaction
	testTx := `TX:{"from":"test_wallet","to":"test_recipient","amount":10.5,"timestamp":1696347123}`
	
	fmt.Printf("📤 Sending test transaction: %s\n", testTx)
	
	_, err = stream.Write([]byte(testTx))
	if err != nil {
		fmt.Printf("❌ Failed to send transaction: %v\n", err)
		return
	}

	// Read response
	response := make([]byte, 4096)
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := stream.Read(response)
	if err != nil && err.Error() != "EOF" {
		fmt.Printf("❌ Failed to read response: %v\n", err)
		return
	}

	if n > 0 {
		fmt.Printf("✅ Received response: %s\n", string(response[:n]))
	} else {
		fmt.Println("⚠️ No response received (this might be normal)")
	}

	// Keep connection open for a moment to see if blockchain logs show activity
	fmt.Println("\n⏳ Keeping connection open for 3 seconds...")
	time.Sleep(3 * time.Second)

	fmt.Println("\n🎉 P2P connection test completed successfully!")
	fmt.Println("💡 Check the blockchain logs with: docker-compose logs blockchain --tail=10")
}