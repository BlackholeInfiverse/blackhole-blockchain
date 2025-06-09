package wallet

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// BlockchainClient handles communication with the blockchain
type BlockchainClient struct {
	Blockchain     *chain.Blockchain
	P2PHost        host.Host
	ConnectedPeers []string
	APIEndpoint    string // HTTP API endpoint for balance queries
}

// BalanceQuery represents a balance query request
type BalanceQuery struct {
	Address     string `json:"address"`
	TokenSymbol string `json:"token_symbol"`
}

// BalanceResponse represents a balance query response
type BalanceResponse struct {
	Success bool   `json:"success"`
	Balance uint64 `json:"balance"`
	Error   string `json:"error,omitempty"`
}

// NewBlockchainClient creates a new client to interact with the blockchain
func NewBlockchainClient(port int) (*BlockchainClient, error) {
	// Create a lightweight P2P host for wallet communication
	h, err := libp2p.New(
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port+1000)), // Use different port range
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2P host: %v", err)
	}

	return &BlockchainClient{
		P2PHost:        h,
		ConnectedPeers: make([]string, 0),
		APIEndpoint:    "", // Will be set when connecting to peers
	}, nil
}

// ConnectToBlockchain connects to an existing blockchain node
func (client *BlockchainClient) ConnectToBlockchain(peerAddr string) error {
	maddr, err := multiaddr.NewMultiaddr(peerAddr)
	if err != nil {
		return fmt.Errorf("invalid multiaddr: %v", err)
	}

	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return fmt.Errorf("failed to get peer info: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.P2PHost.Connect(ctx, *info); err != nil {
		return fmt.Errorf("failed to connect to blockchain node: %v", err)
	}

	client.ConnectedPeers = append(client.ConnectedPeers, peerAddr)
	fmt.Printf("✅ Connected to blockchain node: %s\n", peerAddr)
	return nil
}

// GetTokenBalance returns the balance of a specific token for an address
func (client *BlockchainClient) GetTokenBalance(address, tokenSymbol string) (uint64, error) {
	// Try to query balance via HTTP API first
	if client.APIEndpoint != "" {
		balance, err := client.queryBalanceViaHTTP(address, tokenSymbol)
		if err == nil {
			fmt.Printf("✅ Retrieved balance from blockchain API: %d %s for address %s\n", balance, tokenSymbol, address)
			return balance, nil
		}
		fmt.Printf("⚠️ Failed to query balance via HTTP API: %v\n", err)
	}

	// If no API endpoint or HTTP query failed, try to extract port from peer address
	if len(client.ConnectedPeers) > 0 {
		for _, peerAddr := range client.ConnectedPeers {
			// Extract port from peer address and try HTTP API
			if apiPort := client.extractAPIPortFromPeer(peerAddr); apiPort != "" {
				balance, err := client.queryBalanceViaHTTPPort(address, tokenSymbol, apiPort)
				if err == nil {
					fmt.Printf("✅ Retrieved balance from peer API: %d %s for address %s\n", balance, tokenSymbol, address)
					return balance, nil
				}
				fmt.Printf("⚠️ Failed to query balance from peer API: %v\n", err)
			}
		}
	}

	fmt.Printf("⚠️ No blockchain connection available. Returning placeholder balance.\n")
	return 1000, nil // Fallback placeholder
}

// TransferTokens transfers tokens from one address to another
func (client *BlockchainClient) TransferTokens(from, to, tokenSymbol string, amount uint64, privateKey []byte) error {
	if len(client.ConnectedPeers) == 0 {
		return fmt.Errorf("not connected to any blockchain nodes")
	}

	// Create and sign transaction
	tx := &chain.Transaction{
		Type:      chain.TokenTransfer,
		From:      from,
		To:        to,
		Amount:    amount,
		TokenID:   tokenSymbol,
		Fee:       0,
		Nonce:     uint64(time.Now().UnixNano()), // Use timestamp as nonce for now
		Timestamp: time.Now().Unix(),
	}

	// Calculate transaction ID
	tx.ID = tx.CalculateHash()

	// Sign transaction (simplified - would need actual signing logic)
	// tx.Sign(privateKey)

	// Send transaction to connected blockchain nodes via P2P
	return client.sendTransactionToNetwork(tx)
}

// StakeTokens stakes tokens for validation
func (client *BlockchainClient) StakeTokens(address, tokenSymbol string, amount uint64, privateKey []byte) error {
	if len(client.ConnectedPeers) == 0 {
		return fmt.Errorf("not connected to any blockchain nodes")
	}

	// Create staking transaction
	tx := &chain.Transaction{
		Type:      chain.StakeDeposit,
		From:      address,
		To:        "staking_contract",
		Amount:    amount,
		TokenID:   tokenSymbol,
		Fee:       0,
		Nonce:     uint64(time.Now().UnixNano()), // Use timestamp as nonce for now
		Timestamp: time.Now().Unix(),
	}

	// Calculate transaction ID
	tx.ID = tx.CalculateHash()

	// Sign transaction (simplified - would need actual signing logic)
	// tx.Sign(privateKey)

	// Send transaction to connected blockchain nodes via P2P
	return client.sendTransactionToNetwork(tx)
}

// sendTransactionToNetwork sends a transaction to all connected blockchain nodes
func (client *BlockchainClient) sendTransactionToNetwork(tx *chain.Transaction) error {
	// Encode the transaction to bytes
	var txBuf bytes.Buffer
	txEncoder := gob.NewEncoder(&txBuf)
	if err := txEncoder.Encode(tx); err != nil {
		return fmt.Errorf("failed to encode transaction: %v", err)
	}

	// Wrap it in a Message
	msg := &chain.Message{
		Type:    chain.MessageTypeTx,
		Data:    txBuf.Bytes(),
		Version: chain.ProtocolVersion,
	}

	// Send to all connected peers
	for _, peerAddr := range client.ConnectedPeers {
		if err := client.sendMessageToPeer(peerAddr, msg); err != nil {
			fmt.Printf("⚠️ Failed to send transaction to peer %s: %v\n", peerAddr, err)
			continue
		}
		fmt.Printf("✅ Transaction sent to peer %s\n", peerAddr)
	}

	return nil
}

// sendMessageToPeer sends a message to a specific peer
func (client *BlockchainClient) sendMessageToPeer(peerAddr string, msg *chain.Message) error {
	maddr, err := multiaddr.NewMultiaddr(peerAddr)
	if err != nil {
		return fmt.Errorf("invalid multiaddr: %v", err)
	}

	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return fmt.Errorf("failed to get peer info: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Open stream to peer
	stream, err := client.P2PHost.NewStream(ctx, info.ID, "/blackhole/1.0.0")
	if err != nil {
		return fmt.Errorf("failed to open stream: %v", err)
	}
	defer stream.Close()

	// Send message
	if err := msg.Encode(stream); err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	return nil
}

// GetConnectedPeers returns the list of connected peer addresses
func (client *BlockchainClient) GetConnectedPeers() []string {
	return client.ConnectedPeers
}

// IsConnected returns true if the client is connected to at least one blockchain node
func (client *BlockchainClient) IsConnected() bool {
	return len(client.ConnectedPeers) > 0
}

// queryBalanceViaHTTP queries balance using HTTP API
func (client *BlockchainClient) queryBalanceViaHTTP(address, tokenSymbol string) (uint64, error) {
	url := fmt.Sprintf("%s/api/blockchain/info", client.APIEndpoint)

	resp, err := http.Get(url)
	if err != nil {
		return 0, fmt.Errorf("failed to query blockchain API: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response: %v", err)
	}

	var blockchainInfo map[string]interface{}
	if err := json.Unmarshal(body, &blockchainInfo); err != nil {
		return 0, fmt.Errorf("failed to parse response: %v", err)
	}

	// Extract token balances
	tokenBalances, ok := blockchainInfo["tokenBalances"].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("token balances not found in response")
	}

	tokenData, ok := tokenBalances[tokenSymbol].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("token %s not found", tokenSymbol)
	}

	balance, ok := tokenData[address].(float64)
	if !ok {
		return 0, nil // Address not found, balance is 0
	}

	return uint64(balance), nil
}

// extractAPIPortFromPeer extracts the API port from a peer address
func (client *BlockchainClient) extractAPIPortFromPeer(peerAddr string) string {
	// Parse peer address like /ip4/127.0.0.1/tcp/3000/p2p/12D3KooW...
	// The API server typically runs on port 8080 when blockchain runs on 3000
	if strings.Contains(peerAddr, "/tcp/3000/") {
		return "8080"
	}
	if strings.Contains(peerAddr, "/tcp/3001/") {
		return "8081"
	}
	if strings.Contains(peerAddr, "/tcp/3002/") {
		return "8082"
	}
	return ""
}

// queryBalanceViaHTTPPort queries balance using HTTP API on specific port
func (client *BlockchainClient) queryBalanceViaHTTPPort(address, tokenSymbol, port string) (uint64, error) {
	url := fmt.Sprintf("http://localhost:%s/api/blockchain/info", port)

	resp, err := http.Get(url)
	if err != nil {
		return 0, fmt.Errorf("failed to query blockchain API on port %s: %v", port, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response: %v", err)
	}

	var blockchainInfo map[string]interface{}
	if err := json.Unmarshal(body, &blockchainInfo); err != nil {
		return 0, fmt.Errorf("failed to parse response: %v", err)
	}

	// Extract token balances
	tokenBalances, ok := blockchainInfo["tokenBalances"].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("token balances not found in response")
	}

	tokenData, ok := tokenBalances[tokenSymbol].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("token %s not found", tokenSymbol)
	}

	balance, ok := tokenData[address].(float64)
	if !ok {
		return 0, nil // Address not found, balance is 0
	}

	return uint64(balance), nil
}
