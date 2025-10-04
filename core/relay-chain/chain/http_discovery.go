package chain

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// HTTPNetworkDiscovery discovers blockchain networks via HTTP API endpoints
type HTTPNetworkDiscovery struct {
	commonPorts []int
	timeout     time.Duration
}

// NewHTTPNetworkDiscovery creates a new HTTP-based network discovery
func NewHTTPNetworkDiscovery() *HTTPNetworkDiscovery {
	return &HTTPNetworkDiscovery{
		commonPorts: []int{8080, 8081, 8082, 8083, 8084},
		timeout:     3 * time.Second,
	}
}

// DiscoverLocalNetworks discovers blockchain networks on localhost
func (hnd *HTTPNetworkDiscovery) DiscoverLocalNetworks() []*NetworkInfo {
	var networks []*NetworkInfo
	
	log.Printf("🔍 Scanning localhost ports for blockchain nodes...")
	
	for _, port := range hnd.commonPorts {
		nodeInfo, err := hnd.fetchNodeInfo("127.0.0.1", port)
		if err != nil {
			log.Printf("🔍 Port %d: %v", port, err)
			continue
		}
		
		if nodeInfo != nil {
			log.Printf("✅ Found blockchain node on port %d", port)
			networks = append(networks, nodeInfo)
		}
	}
	
	log.Printf("🌐 Discovery complete. Found %d blockchain nodes", len(networks))
	return networks
}

// fetchNodeInfo fetches node information from HTTP API
func (hnd *HTTPNetworkDiscovery) fetchNodeInfo(host string, port int) (*NetworkInfo, error) {
	url := fmt.Sprintf("http://%s:%d/api/node/info", host, port)
	
	client := &http.Client{
		Timeout: hnd.timeout,
	}
	
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("no response from %s:%d", host, port)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s:%d", resp.StatusCode, host, port)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	var apiResponse struct {
		NetworkInfo struct {
			NetworkID string `json:"network_id"`
			ChainID   string `json:"chain_id"`
			Name      string `json:"name"`
			Version   string `json:"version"`
		} `json:"network_info"`
		SecureP2P struct {
			PeerID    string   `json:"peer_id"`
			Addresses []string `json:"addresses"`
			Status    string   `json:"status"`
		} `json:"secure_p2p"`
		LegacyP2P struct {
			PeerID    string   `json:"peer_id"`
			Addresses []string `json:"addresses"`
			Status    string   `json:"status"`
		} `json:"legacy_p2p"`
	}
	
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}
	
	// Prefer secure P2P, fallback to legacy
	var peerID string
	var addresses []string
	
	if apiResponse.SecureP2P.Status == "active" && apiResponse.SecureP2P.PeerID != "" {
		peerID = apiResponse.SecureP2P.PeerID
		addresses = apiResponse.SecureP2P.Addresses
	} else if apiResponse.LegacyP2P.Status == "active" && apiResponse.LegacyP2P.PeerID != "" {
		peerID = apiResponse.LegacyP2P.PeerID
		addresses = apiResponse.LegacyP2P.Addresses
	} else {
		return nil, fmt.Errorf("no active P2P nodes found")
	}
	
	networkInfo := &NetworkInfo{
		NetworkID:    apiResponse.NetworkInfo.NetworkID,
		ChainID:      apiResponse.NetworkInfo.ChainID,
		Name:         apiResponse.NetworkInfo.Name,
		Version:      apiResponse.NetworkInfo.Version,
		PeerID:       peerID,
		Addresses:    addresses,
		BlockHeight:  0, // Could fetch from blockchain/info endpoint
		TotalSupply:  0, // Could fetch from blockchain/info endpoint
		LastSeen:     time.Now(),
		HTTPEndpoint: fmt.Sprintf("http://%s:%d", host, port),
	}
	
	return networkInfo, nil
}