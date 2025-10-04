package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

func main() {
	fmt.Println("🌟 BlackHole Enhanced Wallet with Network Discovery")
	fmt.Println("==================================================")

	// Initialize P2P wallet client
	client, err := chain.NewWalletP2PClient()
	if err != nil {
		log.Fatal("Failed to create wallet P2P client:", err)
	}
	defer client.Close()

	fmt.Println("🔍 Starting network discovery... Please wait...")
	time.Sleep(2 * time.Second) // Give time for discovery

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println("\n=== BlackHole Enhanced Wallet ===")
		fmt.Println("1. Discover available networks")
		fmt.Println("2. Connect to a network")
		fmt.Println("3. Show current network")
		fmt.Println("4. Refresh network list")
		fmt.Println("5. Manual network connection")
		fmt.Println("6. Show wallet info")
		fmt.Println("7. Send transaction (P2P Test)")
		fmt.Println("8. Disconnect from network")
		fmt.Println("9. Exit")
		fmt.Print("Choose an option: ")

		if !scanner.Scan() {
			break
		}

		choice := strings.TrimSpace(scanner.Text())
		switch choice {
		case "1":
			discoverNetworks(client)
		case "2":
			connectToNetwork(client, scanner)
		case "3":
			showCurrentNetwork(client)
		case "4":
			refreshNetworks(client)
		case "5":
			manualConnect(client, scanner)
		case "6":
			showWalletInfo(client)
		case "7":
			sendTransaction(client, scanner)
		case "8":
			disconnectFromNetwork(client)
		case "9":
			fmt.Println("👋 Goodbye!")
			return
		default:
			fmt.Println("❌ Invalid option. Please try again.")
		}
	}
}

func discoverNetworks(client *chain.WalletP2PClient) {
	fmt.Println("\n🔍 Discovering available blockchain networks...")
	
	networks := client.RefreshNetworks()
	
	if len(networks) == 0 {
		fmt.Println("❌ No blockchain networks discovered.")
		fmt.Println("💡 Make sure blockchain nodes are running and announcing themselves.")
		return
	}

	fmt.Printf("✅ Found %d blockchain network(s):\n\n", len(networks))
	
	for i, network := range networks {
		fmt.Printf("📍 Network %d:\n", i+1)
		fmt.Printf("   Name: %s\n", network.Name)
		fmt.Printf("   Network ID: %s\n", network.NetworkID)
		fmt.Printf("   Chain ID: %s\n", network.ChainID)
		fmt.Printf("   Version: %s\n", network.Version)
		fmt.Printf("   Peer ID: %s\n", network.PeerID)
		fmt.Printf("   Block Height: %d\n", network.BlockHeight)
		fmt.Printf("   Total Supply: %d\n", network.TotalSupply)
		fmt.Printf("   Last Seen: %s\n", formatTime(network.LastSeen))
		
		if len(network.Addresses) > 0 {
			fmt.Println("   Addresses:")
			for _, addr := range network.Addresses {
				fmt.Printf("     - %s\n", addr)
			}
		}
		fmt.Println()
	}
}

func connectToNetwork(client *chain.WalletP2PClient, scanner *bufio.Scanner) {
	fmt.Println("\n🔗 Connect to Blockchain Network")
	
	networks := client.GetAvailableNetworks()
	if len(networks) == 0 {
		fmt.Println("❌ No networks available. Please discover networks first.")
		return
	}

	fmt.Println("Available networks:")
	for i, network := range networks {
		fmt.Printf("%d. %s (%s) - Block Height: %d\n", 
			i+1, network.Name, network.NetworkID, network.BlockHeight)
	}

	fmt.Print("Enter network number to connect: ")
	if !scanner.Scan() {
		return
	}

	choice, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
	if err != nil || choice < 1 || choice > len(networks) {
		fmt.Println("❌ Invalid network number.")
		return
	}

	selectedNetwork := networks[choice-1]
	
	err = client.ConnectToNetwork(selectedNetwork.PeerID)
	if err != nil {
		fmt.Printf("❌ Failed to connect to network: %v\n", err)
		return
	}

	fmt.Printf("✅ Successfully connected to %s!\n", selectedNetwork.Name)
	fmt.Printf("🔗 Network: %s (%s)\n", selectedNetwork.NetworkID, selectedNetwork.ChainID)
	fmt.Printf("📊 Block Height: %d\n", selectedNetwork.BlockHeight)
	fmt.Printf("💰 Total Supply: %d\n", selectedNetwork.TotalSupply)
}

func showCurrentNetwork(client *chain.WalletP2PClient) {
	fmt.Println("\n📊 Current Network Status")
	
	network := client.GetCurrentNetwork()
	if network == nil {
		fmt.Println("❌ Not connected to any network.")
		return
	}

	fmt.Printf("✅ Connected to: %s\n", network.Name)
	fmt.Printf("🆔 Network ID: %s\n", network.NetworkID)
	fmt.Printf("🔗 Chain ID: %s\n", network.ChainID)
	fmt.Printf("📊 Block Height: %d\n", network.BlockHeight)
	fmt.Printf("💰 Total Supply: %d\n", network.TotalSupply)
	fmt.Printf("🕒 Last Seen: %s\n", formatTime(network.LastSeen))
	fmt.Printf("🆔 Peer ID: %s\n", network.PeerID)
	
	if len(network.Addresses) > 0 {
		fmt.Println("📍 Addresses:")
		for _, addr := range network.Addresses {
			fmt.Printf("   - %s\n", addr)
		}
	}

	// Show connection status
	elapsed := time.Since(network.LastSeen)
	if elapsed < 30*time.Second {
		fmt.Printf("🟢 Connection Status: Active (last update %v ago)\n", elapsed.Round(time.Second))
	} else {
		fmt.Printf("🟡 Connection Status: Potentially stale (last update %v ago)\n", elapsed.Round(time.Second))
	}
}

func refreshNetworks(client *chain.WalletP2PClient) {
	fmt.Println("\n🔄 Refreshing network discovery...")
	
	time.Sleep(500 * time.Millisecond) // Brief pause for announcements
	networks := client.RefreshNetworks()
	
	fmt.Printf("✅ Discovery complete. Found %d network(s).\n", len(networks))
	
	if len(networks) > 0 {
		fmt.Println("\nQuick overview:")
		for _, network := range networks {
			elapsed := time.Since(network.LastSeen)
			fmt.Printf("  📍 %s (%s) - Height: %d - Last seen: %v ago\n", 
				network.Name, network.NetworkID, network.BlockHeight, elapsed.Round(time.Second))
		}
	}
}

func manualConnect(client *chain.WalletP2PClient, scanner *bufio.Scanner) {
	fmt.Println("\n🔧 Manual Network Connection")
	fmt.Println("Enter peer ID of the blockchain node you want to connect to:")
	fmt.Print("Peer ID: ")

	if !scanner.Scan() {
		return
	}

	peerID := strings.TrimSpace(scanner.Text())
	if peerID == "" {
		fmt.Println("❌ Peer ID cannot be empty.")
		return
	}

	fmt.Printf("🔄 Attempting to connect to peer: %s\n", peerID)

	err := client.ConnectByPeerID(peerID)
	if err != nil {
		fmt.Printf("❌ Failed to connect: %v\n", err)
		fmt.Println("💡 Make sure the peer ID is correct and the node is running.")
		return
	}

	fmt.Println("✅ Successfully connected!")
	
	// Show connected network info
	network := client.GetCurrentNetwork()
	if network != nil {
		fmt.Printf("📊 Connected to: %s (%s)\n", network.Name, network.NetworkID)
	}
}

func showWalletInfo(client *chain.WalletP2PClient) {
	fmt.Println("\n💰 Wallet Information")
	
	info := client.GetWalletInfo()
	fmt.Printf("🆔 Wallet Peer ID: %s\n", info["wallet_peer_id"])
	fmt.Printf("🔗 Connected Networks: %v\n", info["connected_networks"])
	fmt.Printf("🌐 Current Network: %s\n", info["current_network"])
	fmt.Printf("🔍 Discovery Active: %v\n", info["discovery_active"])
	
	if addresses, ok := info["wallet_addresses"].([]string); ok && len(addresses) > 0 {
		fmt.Println("📍 Wallet Addresses:")
		for _, addr := range addresses {
			fmt.Printf("   - %s\n", addr)
		}
	}
	
	connectedPeers := client.GetConnectedPeers()
	if len(connectedPeers) > 0 {
		fmt.Println("🔗 Connected Blockchain Peers:")
		for i, peer := range connectedPeers {
			fmt.Printf("   %d. %s (%s)\n", i+1, peer.Name, peer.PeerID)
		}
	}
}

func disconnectFromNetwork(client *chain.WalletP2PClient) {
	fmt.Println("\n🔌 Disconnect from Network")
	
	current := client.GetCurrentNetwork()
	if current == nil {
		fmt.Println("❌ Not connected to any network")
		return
	}
	
	fmt.Printf("Currently connected to: %s (%s)\n", current.Name, current.NetworkID)
	fmt.Print("Are you sure you want to disconnect? (y/N): ")
	
	var response string
	fmt.Scanln(&response)
	
	if strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
		err := client.Disconnect()
		if err != nil {
			fmt.Printf("❌ Failed to disconnect: %v\n", err)
		} else {
			fmt.Println("✅ Successfully disconnected from network")
		}
	} else {
		fmt.Println("Disconnect cancelled")
	}
}

func sendTransaction(client *chain.WalletP2PClient, scanner *bufio.Scanner) {
	fmt.Println("\n💸 Send P2P Transaction")
	
	// Check if connected
	network := client.GetCurrentNetwork()
	if network == nil {
		fmt.Println("❌ Not connected to any network. Please connect first.")
		return
	}
	
	fmt.Printf("📡 Connected to: %s\n\n", network.Name)
	
	// Get sender address
	fmt.Print("From address (sender): ")
	if !scanner.Scan() {
		return
	}
	fromAddr := strings.TrimSpace(scanner.Text())
	if fromAddr == "" {
		fromAddr = "wallet_" + client.GetWalletInfo()["wallet_peer_id"].(string)[:8]
		fmt.Printf("   Using default: %s\n", fromAddr)
	}
	
	// Get recipient address
	fmt.Print("To address (recipient): ")
	if !scanner.Scan() {
		return
	}
	toAddr := strings.TrimSpace(scanner.Text())
	if toAddr == "" {
		toAddr = "node_blackhole"
		fmt.Printf("   Using default: %s\n", toAddr)
	}
	
	// Get amount
	fmt.Print("Amount (e.g., 10.5): ")
	if !scanner.Scan() {
		return
	}
	amountStr := strings.TrimSpace(scanner.Text())
	amount, err := strconv.ParseFloat(amountStr, 64)
	if err != nil || amount <= 0 {
		fmt.Println("❌ Invalid amount. Must be a positive number.")
		return
	}
	
	fmt.Println("\n📋 Transaction Summary:")
	fmt.Printf("   From:   %s\n", fromAddr)
	fmt.Printf("   To:     %s\n", toAddr)
	fmt.Printf("   Amount: %.6f BHT\n", amount)
	fmt.Print("\nConfirm transaction? (y/N): ")
	
	if !scanner.Scan() {
		return
	}
	
	confirm := strings.ToLower(strings.TrimSpace(scanner.Text()))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("❌ Transaction cancelled")
		return
	}
	
	fmt.Println("\n⏳ Sending transaction over P2P...")
	
	// Send the transaction
	txHash, err := client.SendTransaction(fromAddr, toAddr, amount)
	if err != nil {
		fmt.Printf("❌ Failed to send transaction: %v\n", err)
		return
	}
	
	fmt.Println("\n✅ Transaction sent successfully!")
	fmt.Printf("📝 Transaction Hash: %s\n", txHash)
	fmt.Println("\n💡 The transaction has been submitted to the blockchain network.")
	fmt.Println("   It will be processed and included in the next block.")
}

func formatTime(t time.Time) string {
	if time.Since(t) < 1*time.Minute {
		return "Just now"
	}
	return t.Format("15:04:05")
}
