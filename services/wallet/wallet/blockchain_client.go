package wallet

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
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
	// For now, return a placeholder balance since we don't have direct access to blockchain state
	// In a real implementation, this would query the blockchain node via RPC
	fmt.Printf("⚠️ GetTokenBalance not fully implemented for P2P client. Returning placeholder balance.\n")
	return 1000, nil // Placeholder balance
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
