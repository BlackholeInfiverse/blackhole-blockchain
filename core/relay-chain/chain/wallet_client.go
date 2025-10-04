package chain

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

// WalletP2PClient represents a P2P client for wallet connections
type WalletP2PClient struct {
	host            host.Host
	ctx             context.Context
	cancel          context.CancelFunc
	connectedPeers  map[peer.ID]*NetworkInfo
	peersLock       sync.RWMutex
	discoveryService *NetworkDiscoveryService
	httpDiscovery   *HTTPNetworkDiscovery
	currentNetwork   *NetworkInfo
	networkLock      sync.RWMutex
}

// NewWalletP2PClient creates a new P2P client for wallets
func NewWalletP2PClient() (*WalletP2PClient, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Generate a private key for this wallet
	privKey, _, err := crypto.GenerateKeyPair(crypto.Ed25519, 256)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	// Create libp2p host for wallet
	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"), // Random available port
		libp2p.DefaultSecurity,
		libp2p.DefaultTransports,
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %v", err)
	}

	// Initialize discovery service on different port to avoid conflicts
	discoveryService := NewNetworkDiscoveryService(8889)
	err = discoveryService.Start()
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to start discovery service: %v", err)
	}

	client := &WalletP2PClient{
		host:            h,
		ctx:             ctx,
		cancel:          cancel,
		connectedPeers:  make(map[peer.ID]*NetworkInfo),
		discoveryService: discoveryService,
		httpDiscovery:   NewHTTPNetworkDiscovery(),
	}

	// Set stream handler for blockchain communication
	h.SetStreamHandler(protocol.ID("/blackhole/wallet/1.0.0"), client.handleStream)

	log.Printf("🔐 Wallet P2P client initialized with ID: %s", h.ID())
	return client, nil
}

// GetAvailableNetworks returns discovered blockchain networks
func (wc *WalletP2PClient) GetAvailableNetworks() []*NetworkInfo {
	// Try HTTP discovery first (more reliable)
	httpNetworks := wc.httpDiscovery.DiscoverLocalNetworks()
	
	// If HTTP discovery found networks, use those
	if len(httpNetworks) > 0 {
		log.Printf("🌐 HTTP discovery found %d networks", len(httpNetworks))
		return httpNetworks
	}
	
	// Fallback to UDP discovery
	log.Printf("🔍 Falling back to UDP discovery...")
	return wc.discoveryService.GetAvailableNetworks()
}

// RefreshNetworks triggers network discovery refresh
func (wc *WalletP2PClient) RefreshNetworks() []*NetworkInfo {
	time.Sleep(100 * time.Millisecond) // Brief pause for announcements
	return wc.GetAvailableNetworks()
}

// ConnectToNetwork establishes a P2P connection to a blockchain network
func (wc *WalletP2PClient) ConnectToNetwork(peerID string) error {
	network, exists := wc.discoveryService.FindNetwork(peerID)
	if !exists {
		return fmt.Errorf("network with peer ID %s not found or expired", peerID)
	}

	// Parse peer ID
	targetPeerID, err := peer.Decode(peerID)
	if err != nil {
		return fmt.Errorf("invalid peer ID: %v", err)
	}

	// Try to connect using network addresses
	var lastErr error
	connected := false

	for _, addrStr := range network.Addresses {
		maddr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			lastErr = fmt.Errorf("invalid multiaddr %s: %v", addrStr, err)
			continue
		}

		peerInfo, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			lastErr = fmt.Errorf("failed to parse peer info from %s: %v", addrStr, err)
			continue
		}

		// Attempt connection with timeout
		connectCtx, cancel := context.WithTimeout(wc.ctx, 10*time.Second)
		err = wc.host.Connect(connectCtx, *peerInfo)
		cancel()

		if err == nil {
			// Connection successful
			wc.peersLock.Lock()
			wc.connectedPeers[targetPeerID] = network
			wc.peersLock.Unlock()

			wc.networkLock.Lock()
			wc.currentNetwork = network
			wc.networkLock.Unlock()

			connected = true
			log.Printf("🔗 Wallet successfully connected to %s (%s)", network.Name, peerID)
			break
		} else {
			lastErr = fmt.Errorf("failed to connect to %s: %v", addrStr, err)
		}
	}

	if !connected {
		return fmt.Errorf("failed to connect to network: %v", lastErr)
	}

	return nil
}

// ConnectByPeerID connects to a network using just the peer ID (manual entry)
func (wc *WalletP2PClient) ConnectByPeerID(peerIDStr string) error {
	// First try to find it in discovered networks
	if _, exists := wc.discoveryService.FindNetwork(peerIDStr); exists {
		return wc.ConnectToNetwork(peerIDStr)
	}

	// If not found in discovery, try direct connection with common addresses
	targetPeerID, err := peer.Decode(peerIDStr)
	if err != nil {
		return fmt.Errorf("invalid peer ID: %v", err)
	}

	// Try common local addresses - Docker-exposed ports first, then direct
	commonAddresses := []string{
		// Docker-exposed ports (most likely to work)
		fmt.Sprintf("/ip4/127.0.0.1/tcp/3001/p2p/%s", peerIDStr), // Docker secure P2P
		fmt.Sprintf("/ip4/127.0.0.1/tcp/3100/p2p/%s", peerIDStr), // Docker legacy P2P
		fmt.Sprintf("/ip4/127.0.0.1/tcp/30303/p2p/%s", peerIDStr), // Docker P2P networking
		// Direct local node ports
		fmt.Sprintf("/ip4/127.0.0.1/tcp/3002/p2p/%s", peerIDStr), // Local node secure P2P
		fmt.Sprintf("/ip4/127.0.0.1/tcp/3101/p2p/%s", peerIDStr), // Local node legacy P2P
		// Fallback addresses
		fmt.Sprintf("/ip4/localhost/tcp/3001/p2p/%s", peerIDStr),
		fmt.Sprintf("/ip4/localhost/tcp/3100/p2p/%s", peerIDStr),
	}

	var lastErr error
	log.Printf("🔎 Trying to connect to peer %s using %d common addresses...", peerIDStr, len(commonAddresses))
	
	for i, addrStr := range commonAddresses {
		log.Printf("🔗 Attempt %d/%d: %s", i+1, len(commonAddresses), addrStr)
		
		maddr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			log.Printf("⚠️  Invalid multiaddr: %v", err)
			lastErr = err
			continue
		}

		peerInfo, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			log.Printf("⚠️  Failed to parse peer info: %v", err)
			lastErr = err
			continue
		}

		connectCtx, cancel := context.WithTimeout(wc.ctx, 8*time.Second)
		err = wc.host.Connect(connectCtx, *peerInfo)
		cancel()

		if err == nil {
			log.Printf("✅ Connection successful!")
			// Create network info for manual connection
			manualNetwork := &NetworkInfo{
				NetworkID: "unknown",
				Name:      "Manual Connection",
				PeerID:    peerIDStr,
				Addresses: []string{addrStr},
				LastSeen:  time.Now(),
			}

			wc.peersLock.Lock()
			wc.connectedPeers[targetPeerID] = manualNetwork
			wc.peersLock.Unlock()

			wc.networkLock.Lock()
			wc.currentNetwork = manualNetwork
			wc.networkLock.Unlock()

			log.Printf("🔗 Wallet manually connected to peer %s via %s", peerIDStr, addrStr)
			return nil
		} else {
			log.Printf("❌ Connection failed: %v", err)
			lastErr = err
		}
	}

	return fmt.Errorf("failed to connect to peer %s: %v", peerIDStr, lastErr)
}

// GetCurrentNetwork returns the currently connected network
func (wc *WalletP2PClient) GetCurrentNetwork() *NetworkInfo {
	wc.networkLock.RLock()
	defer wc.networkLock.RUnlock()
	return wc.currentNetwork
}

// GetConnectedPeers returns list of connected blockchain peers
func (wc *WalletP2PClient) GetConnectedPeers() []*NetworkInfo {
	wc.peersLock.RLock()
	defer wc.peersLock.RUnlock()

	var peers []*NetworkInfo
	for peerID, network := range wc.connectedPeers {
		// Check if still connected
		if wc.host.Network().Connectedness(peerID) == 1 { // Connected
			peers = append(peers, network)
		} else {
			// Remove disconnected peer
			delete(wc.connectedPeers, peerID)
		}
	}
	return peers
}

// Disconnect disconnects from the current network
func (wc *WalletP2PClient) Disconnect() error {
	wc.networkLock.Lock()
	currentNetwork := wc.currentNetwork
	wc.currentNetwork = nil
	wc.networkLock.Unlock()

	if currentNetwork == nil {
		return fmt.Errorf("not connected to any network")
	}

	// Parse and disconnect from peer
	peerID, err := peer.Decode(currentNetwork.PeerID)
	if err == nil {
		err = wc.host.Network().ClosePeer(peerID)
		if err != nil {
			log.Printf("⚠️ Error closing connection to peer: %v", err)
		}
	}

	wc.peersLock.Lock()
	delete(wc.connectedPeers, peerID)
	wc.peersLock.Unlock()

	log.Printf("🔌 Disconnected from network: %s", currentNetwork.Name)
	return nil
}

// GetWalletInfo returns information about this wallet's P2P node
func (wc *WalletP2PClient) GetWalletInfo() map[string]interface{} {
	connected := wc.GetConnectedPeers()
	current := wc.GetCurrentNetwork()

	var currentNetworkName string
	if current != nil {
		currentNetworkName = current.Name
	} else {
		currentNetworkName = "Not connected"
	}

	addresses := make([]string, 0)
	for _, addr := range wc.host.Addrs() {
		addresses = append(addresses, fmt.Sprintf("%s/p2p/%s", addr, wc.host.ID()))
	}

	return map[string]interface{}{
		"wallet_peer_id":     wc.host.ID().String(),
		"wallet_addresses":   addresses,
		"connected_networks": len(connected),
		"current_network":    currentNetworkName,
		"discovery_active":   true,
	}
}

// handleStream handles incoming streams from blockchain nodes
func (wc *WalletP2PClient) handleStream(stream network.Stream) {
	defer stream.Close()
	remotePeer := stream.Conn().RemotePeer()
	log.Printf("📨 Received stream from blockchain peer: %s", remotePeer)
	
	// Handle blockchain-specific communication here
	// For now, just acknowledge the connection
}

// SendTransaction sends a transaction to the connected blockchain node
func (wc *WalletP2PClient) SendTransaction(from, to string, amount float64) (string, error) {
	wc.networkLock.RLock()
	currentNetwork := wc.currentNetwork
	wc.networkLock.RUnlock()

	if currentNetwork == nil {
		return "", fmt.Errorf("not connected to any blockchain network")
	}

	// Parse the peer ID
	peerID, err := peer.Decode(currentNetwork.PeerID)
	if err != nil {
		return "", fmt.Errorf("invalid peer ID: %v", err)
	}

	// Check if still connected
	if wc.host.Network().Connectedness(peerID) != 1 {
		return "", fmt.Errorf("not connected to blockchain peer %s", currentNetwork.PeerID)
	}

	// Create a stream to the blockchain node
	stream, err := wc.host.NewStream(wc.ctx, peerID, protocol.ID("/blackhole/transaction/1.0.0"))
	if err != nil {
		return "", fmt.Errorf("failed to create stream: %v", err)
	}
	defer stream.Close()

	// Create transaction data
	txData := fmt.Sprintf("TX:{\"from\":\"%s\",\"to\":\"%s\",\"amount\":%.6f,\"timestamp\":%d}",
		from, to, amount, time.Now().Unix())

	// Send transaction
	_, err = stream.Write([]byte(txData))
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %v", err)
	}

	// Read response
	response := make([]byte, 4096)
	n, err := stream.Read(response)
	if err != nil && err.Error() != "EOF" {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	if n > 0 {
		txHash := string(response[:n])
		log.Printf("✅ Transaction sent successfully. Hash: %s", txHash)
		return txHash, nil
	}

	return "pending", nil
}

// Close shuts down the wallet P2P client
func (wc *WalletP2PClient) Close() error {
	if wc.cancel != nil {
		wc.cancel()
	}
	if wc.discoveryService != nil {
		wc.discoveryService.Stop()
	}
	if wc.host != nil {
		return wc.host.Close()
	}
	return nil
}
