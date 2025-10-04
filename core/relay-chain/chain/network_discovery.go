package chain

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// NetworkInfo represents information about a blockchain network
type NetworkInfo struct {
	NetworkID    string    `json:"network_id"`
	ChainID      string    `json:"chain_id"`
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	PeerID       string    `json:"peer_id"`
	Addresses    []string  `json:"addresses"`
	BlockHeight  uint64    `json:"block_height"`
	TotalSupply  uint64    `json:"total_supply"`
	LastSeen     time.Time `json:"last_seen"`
	HTTPEndpoint string    `json:"http_endpoint"`
}

// NetworkDiscoveryService helps wallets discover available blockchain networks
type NetworkDiscoveryService struct {
	mu            sync.RWMutex
	networks      map[string]*NetworkInfo
	broadcastAddr string
	listenPort    int
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewNetworkDiscoveryService creates a new network discovery service
func NewNetworkDiscoveryService(listenPort int) *NetworkDiscoveryService {
	ctx, cancel := context.WithCancel(context.Background())
	return &NetworkDiscoveryService{
		networks:      make(map[string]*NetworkInfo),
		broadcastAddr: "255.255.255.255:8888", // Broadcast address for network discovery
		listenPort:    listenPort,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start begins the network discovery service
func (nds *NetworkDiscoveryService) Start() error {
	// Start UDP listener for network announcements
	go nds.startListener()
	
	log.Printf("🔍 Network Discovery Service started on port %d", nds.listenPort)
	return nil
}

// Stop stops the network discovery service
func (nds *NetworkDiscoveryService) Stop() {
	nds.cancel()
}

// startListener listens for network announcements
func (nds *NetworkDiscoveryService) startListener() {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", nds.listenPort))
	if err != nil {
		log.Printf("❌ Failed to resolve UDP address: %v", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("❌ Failed to listen on UDP: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("👂 Listening for network announcements on port %d", nds.listenPort)

	buffer := make([]byte, 1024)
	for {
		select {
		case <-nds.ctx.Done():
			return
		default:
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remoteAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("❌ Error reading UDP message: %v", err)
				continue
			}

			var networkInfo NetworkInfo
			if err := json.Unmarshal(buffer[:n], &networkInfo); err != nil {
				log.Printf("❌ Failed to parse network announcement: %v", err)
				continue
			}

			networkInfo.LastSeen = time.Now()
			log.Printf("🌐 Discovered network: %s (%s) from %s", 
				networkInfo.Name, networkInfo.PeerID, remoteAddr)

			nds.mu.Lock()
			nds.networks[networkInfo.PeerID] = &networkInfo
			nds.mu.Unlock()
		}
	}
}

// AnnounceNetwork broadcasts network information for wallets to discover
func (nds *NetworkDiscoveryService) AnnounceNetwork(bc *Blockchain) error {
	if bc.SecureP2PNode == nil {
		return fmt.Errorf("secure P2P node not available")
	}

	// Get network addresses
	var addresses []string
	for _, addr := range bc.SecureP2PNode.Host.Addrs() {
		addresses = append(addresses, fmt.Sprintf("%s/p2p/%s", addr, bc.SecureP2PNode.Host.ID()))
	}

	networkInfo := &NetworkInfo{
		NetworkID:    "blackhole-mainnet", // Could be configurable
		ChainID:      "blackhole-1",
		Name:         "BlackHole Blockchain",
		Version:      "1.0.0",
		PeerID:       bc.SecureP2PNode.Host.ID().String(),
		Addresses:    addresses,
		BlockHeight:  uint64(len(bc.Blocks)),
		TotalSupply:  bc.TotalSupply,
		LastSeen:     time.Now(),
		HTTPEndpoint: "", // Will be set by the caller
	}

	data, err := json.Marshal(networkInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal network info: %v", err)
	}

	// Broadcast to discovery port
	conn, err := net.Dial("udp", nds.broadcastAddr)
	if err != nil {
		return fmt.Errorf("failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to broadcast network info: %v", err)
	}

	log.Printf("📡 Announced network %s to discovery service", networkInfo.Name)
	return nil
}

// GetAvailableNetworks returns all discovered networks
func (nds *NetworkDiscoveryService) GetAvailableNetworks() []*NetworkInfo {
	nds.mu.RLock()
	defer nds.mu.RUnlock()

	var networks []*NetworkInfo
	now := time.Now()

	for _, network := range nds.networks {
		// Only return networks seen in the last 30 seconds
		if now.Sub(network.LastSeen) < 30*time.Second {
			networks = append(networks, network)
		}
	}

	return networks
}

// FindNetwork finds a specific network by peer ID
func (nds *NetworkDiscoveryService) FindNetwork(peerID string) (*NetworkInfo, bool) {
	nds.mu.RLock()
	defer nds.mu.RUnlock()

	network, exists := nds.networks[peerID]
	if !exists {
		return nil, false
	}

	// Check if network is still active
	if time.Since(network.LastSeen) > 30*time.Second {
		return nil, false
	}

	return network, true
}

// WalletNetworkConnector helps wallets connect to discovered networks
type WalletNetworkConnector struct {
	discoveryService *NetworkDiscoveryService
	currentNetwork   *NetworkInfo
	mu               sync.RWMutex
}

// NewWalletNetworkConnector creates a wallet network connector
func NewWalletNetworkConnector() *WalletNetworkConnector {
	return &WalletNetworkConnector{
		discoveryService: NewNetworkDiscoveryService(8888),
	}
}

// Start starts network discovery for the wallet
func (wnc *WalletNetworkConnector) Start() error {
	return wnc.discoveryService.Start()
}

// Stop stops the network connector
func (wnc *WalletNetworkConnector) Stop() {
	wnc.discoveryService.Stop()
}

// GetAvailableNetworks returns networks the wallet can connect to
func (wnc *WalletNetworkConnector) GetAvailableNetworks() []*NetworkInfo {
	return wnc.discoveryService.GetAvailableNetworks()
}

// ConnectToNetwork connects the wallet to a specific network
func (wnc *WalletNetworkConnector) ConnectToNetwork(peerID string) error {
	network, exists := wnc.discoveryService.FindNetwork(peerID)
	if !exists {
		return fmt.Errorf("network with peer ID %s not found", peerID)
	}

	wnc.mu.Lock()
	wnc.currentNetwork = network
	wnc.mu.Unlock()

	log.Printf("🔗 Wallet connected to network: %s (%s)", network.Name, network.PeerID)
	return nil
}

// GetCurrentNetwork returns the currently connected network
func (wnc *WalletNetworkConnector) GetCurrentNetwork() *NetworkInfo {
	wnc.mu.RLock()
	defer wnc.mu.RUnlock()
	return wnc.currentNetwork
}

// RefreshNetworks triggers a refresh of available networks
func (wnc *WalletNetworkConnector) RefreshNetworks() []*NetworkInfo {
	// Wait a moment for any recent announcements
	time.Sleep(100 * time.Millisecond)
	return wnc.GetAvailableNetworks()
}