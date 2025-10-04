package chain

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/multiformats/go-multiaddr"
)

// SecureP2PNode represents an enhanced P2P node with security and proper discovery
type SecureP2PNode struct {
	Host         host.Host
	PubSub       *pubsub.PubSub
	ctx          context.Context
	chain        *Blockchain
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	
	// Peer management
	peers        map[peer.ID]*PeerInfo
	peersLock    sync.RWMutex
	
	// Topics for different message types
	blockTopic   *pubsub.Topic
	txTopic      *pubsub.Topic
	
	// Bootstrap peers
	bootstrapPeers []string
}

// PeerInfo holds information about connected peers
type PeerInfo struct {
	ID          peer.ID
	ConnectedAt time.Time
	LastSeen    time.Time
	MessageCount int64
	IsBootstrap bool
}

// SignedMessage represents a cryptographically signed P2P message
type SignedMessage struct {
	Type      MessageType `json:"type"`
	Data      []byte      `json:"data"`
	Signature []byte      `json:"signature"`
	PublicKey []byte      `json:"public_key"`
	Timestamp int64       `json:"timestamp"`
	Version   uint32      `json:"version"`
}

// NewSecureP2PNode creates a new secure P2P node with enhanced features
func NewSecureP2PNode(ctx context.Context, port int, bootstrapPeers []string) (*SecureP2PNode, error) {
	// Generate or load identity keys
	privateKey, publicKey, err := loadOrGenerateKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to load/generate keys: %v", err)
	}

	// Create libp2p private key from ed25519 key
	libp2pPrivKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate libp2p key: %v", err)
	}

	// Determine listen address - use port+1 to avoid conflict with legacy P2P
	listenAddr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port+1)
	
	// Create libp2p host with security settings
	// Create connection manager
	cm, err := connmgr.NewConnManager(10, 100, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %v", err)
	}
	
	h, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
		libp2p.Identity(libp2pPrivKey),
		libp2p.DefaultSecurity,
		libp2p.DefaultTransports,
		libp2p.NATPortMap(),
		// Add connection manager for better peer management
		libp2p.ConnectionManager(cm),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %v", err)
	}

	// Create pub-sub instance
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub: %v", err)
	}

	node := &SecureP2PNode{
		Host:           h,
		PubSub:         ps,
		ctx:            ctx,
		privateKey:     privateKey,
		publicKey:      publicKey,
		peers:          make(map[peer.ID]*PeerInfo),
		bootstrapPeers: bootstrapPeers,
	}

	// Initialize pub-sub topics
	if err := node.initializeTopics(); err != nil {
		return nil, fmt.Errorf("failed to initialize topics: %v", err)
	}

	// Set up stream handlers for different protocols
	h.SetStreamHandler("/blackhole/secure/1.0.0", node.handleSecureStream)
	h.SetStreamHandler("/blackhole/transaction/1.0.0", node.handleTransactionStream)
	h.SetStreamHandler("/blackhole/wallet/1.0.0", node.handleWalletStream)

	// Start peer discovery
	go node.startDiscovery()

	// Connect to bootstrap peers
	go node.connectToBootstrapPeers()

	// Start periodic peer maintenance
	go node.maintainPeers()

	log.Printf("🔐 Secure P2P node started")
	log.Printf("🆔 Peer ID: %s", h.ID())
	log.Printf("🔑 Public Key: %s", hex.EncodeToString(publicKey))
	
	// Print listening addresses
	for _, addr := range h.Addrs() {
		log.Printf("🌐 Listening on: %s/p2p/%s", addr, h.ID())
	}

	return node, nil
}

// loadOrGenerateKeys loads existing keys or generates new ones
func loadOrGenerateKeys() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	keyFile := "node_identity.key"
	
	// Try to load existing key
	if data, err := os.ReadFile(keyFile); err == nil {
		if len(data) == ed25519.PrivateKeySize {
			privateKey := ed25519.PrivateKey(data)
			publicKey := privateKey.Public().(ed25519.PublicKey)
			log.Printf("🔑 Loaded existing identity key")
			return privateKey, publicKey, nil
		}
	}
	
	// Generate new key
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	
	// Save key to file
	if err := os.WriteFile(keyFile, privateKey, 0600); err != nil {
		log.Printf("⚠️ Failed to save key file: %v", err)
	} else {
		log.Printf("🔑 Generated and saved new identity key")
	}
	
	return privateKey, publicKey, nil
}

// initializeTopics creates pub-sub topics for different message types
func (n *SecureP2PNode) initializeTopics() error {
	var err error
	
	// Block propagation topic
	n.blockTopic, err = n.PubSub.Join("blackhole-blocks")
	if err != nil {
		return fmt.Errorf("failed to join block topic: %v", err)
	}
	
	// Transaction propagation topic
	n.txTopic, err = n.PubSub.Join("blackhole-transactions")
	if err != nil {
		return fmt.Errorf("failed to join transaction topic: %v", err)
	}
	
	// Subscribe to topics
	go n.handleBlockMessages()
	go n.handleTransactionMessages()
	
	log.Printf("📡 Initialized pub-sub topics")
	return nil
}

// SetBlockchain sets the blockchain reference
func (n *SecureP2PNode) SetBlockchain(bc *Blockchain) {
	n.chain = bc
}

// signMessage creates a cryptographic signature for a message
func (n *SecureP2PNode) signMessage(msgType MessageType, data []byte) (*SignedMessage, error) {
	msg := &SignedMessage{
		Type:      msgType,
		Data:      data,
		PublicKey: n.publicKey,
		Timestamp: time.Now().Unix(),
		Version:   ProtocolVersion,
	}
	
	// Create signature payload
	payload := fmt.Sprintf("%d:%s:%d:%d", msg.Type, hex.EncodeToString(msg.Data), msg.Timestamp, msg.Version)
	signature := ed25519.Sign(n.privateKey, []byte(payload))
	msg.Signature = signature
	
	return msg, nil
}

// verifyMessage verifies the cryptographic signature of a message
func (n *SecureP2PNode) verifyMessage(msg *SignedMessage) bool {
	// Basic checks
	if msg.Version != ProtocolVersion {
		log.Printf("⚠️ Version mismatch: got %d, expected %d", msg.Version, ProtocolVersion)
		return false
	}
	
	// Check timestamp (reject messages older than 5 minutes)
	msgTime := time.Unix(msg.Timestamp, 0)
	if time.Since(msgTime) > 5*time.Minute {
		log.Printf("⚠️ Message too old: %v", msgTime)
		return false
	}
	
	// Verify signature
	payload := fmt.Sprintf("%d:%s:%d:%d", msg.Type, hex.EncodeToString(msg.Data), msg.Timestamp, msg.Version)
	return ed25519.Verify(msg.PublicKey, []byte(payload), msg.Signature)
}

// BroadcastBlockBytes broadcasts raw block bytes to all peers using pub-sub
func (n *SecureP2PNode) BroadcastBlockBytes(data []byte) error {
	if n.blockTopic == nil {
		return fmt.Errorf("block topic not initialized")
	}
	
	// Sign the message
	signedMsg, err := n.signMessage(MessageTypeBlock, data)
	if err != nil {
		return fmt.Errorf("failed to sign block message: %v", err)
	}
	
	// Serialize signed message
	msgData, err := json.Marshal(signedMsg)
	if err != nil {
		return fmt.Errorf("failed to serialize signed message: %v", err)
	}
	
	// Publish to topic
	err = n.blockTopic.Publish(n.ctx, msgData)
	if err != nil {
		return fmt.Errorf("failed to publish block: %v", err)
	}
	
	log.Printf("📤 Broadcast block bytes to network")
	return nil
}

// BroadcastBlock broadcasts a block to all peers using pub-sub
func (n *SecureP2PNode) BroadcastBlock(block *Block) error {
	if n.blockTopic == nil {
		return fmt.Errorf("block topic not initialized")
	}
	
	// Serialize block
	data := block.Serialize()
	
	// Sign the message
	signedMsg, err := n.signMessage(MessageTypeBlock, data)
	if err != nil {
		return fmt.Errorf("failed to sign block message: %v", err)
	}
	
	// Serialize signed message
	msgData, err := json.Marshal(signedMsg)
	if err != nil {
		return fmt.Errorf("failed to serialize signed message: %v", err)
	}
	
	// Publish to topic
	err = n.blockTopic.Publish(n.ctx, msgData)
	if err != nil {
		return fmt.Errorf("failed to publish block: %v", err)
	}
	
	log.Printf("📤 Broadcast block %d to network", block.Header.Index)
	return nil
}

// BroadcastTransactionBytes broadcasts raw transaction bytes to all peers using pub-sub
func (n *SecureP2PNode) BroadcastTransactionBytes(data []byte) error {
	if n.txTopic == nil {
		return fmt.Errorf("transaction topic not initialized")
	}
	
	// Sign the message
	signedMsg, err := n.signMessage(MessageTypeTx, data)
	if err != nil {
		return fmt.Errorf("failed to sign transaction message: %v", err)
	}
	
	// Serialize signed message
	msgData, err := json.Marshal(signedMsg)
	if err != nil {
		return fmt.Errorf("failed to serialize signed message: %v", err)
	}
	
	// Publish to topic
	err = n.txTopic.Publish(n.ctx, msgData)
	if err != nil {
		return fmt.Errorf("failed to publish transaction: %v", err)
	}
	
	log.Printf("📤 Broadcast transaction bytes to network")
	return nil
}

// BroadcastTransaction broadcasts a transaction to all peers using pub-sub
func (n *SecureP2PNode) BroadcastTransaction(tx *Transaction) error {
	if n.txTopic == nil {
		return fmt.Errorf("transaction topic not initialized")
	}
	
	// Serialize transaction
	wrapper := &TransactionWrapper{Transaction: tx}
	data, err := wrapper.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize transaction: %v", err)
	}
	
	// Sign the message
	signedMsg, err := n.signMessage(MessageTypeTx, data)
	if err != nil {
		return fmt.Errorf("failed to sign transaction message: %v", err)
	}
	
	// Serialize signed message
	msgData, err := json.Marshal(signedMsg)
	if err != nil {
		return fmt.Errorf("failed to serialize signed message: %v", err)
	}
	
	// Publish to topic
	err = n.txTopic.Publish(n.ctx, msgData)
	if err != nil {
		return fmt.Errorf("failed to publish transaction: %v", err)
	}
	
	log.Printf("📤 Broadcast transaction %s to network", tx.ID)
	return nil
}

// handleBlockMessages processes incoming block messages from pub-sub
func (n *SecureP2PNode) handleBlockMessages() {
	sub, err := n.blockTopic.Subscribe()
	if err != nil {
		log.Printf("❌ Failed to subscribe to block topic: %v", err)
		return
	}
	defer sub.Cancel()
	
	for {
		msg, err := sub.Next(n.ctx)
		if err != nil {
			log.Printf("❌ Error reading block message: %v", err)
			return
		}
		
		// Skip our own messages
		if msg.ReceivedFrom == n.Host.ID() {
			continue
		}
		
		// Deserialize signed message
		var signedMsg SignedMessage
		if err := json.Unmarshal(msg.Data, &signedMsg); err != nil {
			log.Printf("❌ Failed to deserialize signed block message: %v", err)
			continue
		}
		
		// Verify signature
		if !n.verifyMessage(&signedMsg) {
			log.Printf("❌ Invalid signature for block message from %s", msg.ReceivedFrom)
			continue
		}
		
		// Deserialize block
		block, err := DeserializeBlock(signedMsg.Data)
		if err != nil {
			log.Printf("❌ Failed to deserialize block: %v", err)
			continue
		}
		
		// Process block
		if n.chain != nil {
			if n.chain.AddBlock(block) {
				log.Printf("🧱 Added block %d from peer %s", block.Header.Index, msg.ReceivedFrom)
			} else {
				log.Printf("⚠️ Failed to add block %d from peer %s", block.Header.Index, msg.ReceivedFrom)
			}
		}
	}
}

// handleTransactionMessages processes incoming transaction messages from pub-sub
func (n *SecureP2PNode) handleTransactionMessages() {
	sub, err := n.txTopic.Subscribe()
	if err != nil {
		log.Printf("❌ Failed to subscribe to transaction topic: %v", err)
		return
	}
	defer sub.Cancel()
	
	for {
		msg, err := sub.Next(n.ctx)
		if err != nil {
			log.Printf("❌ Error reading transaction message: %v", err)
			return
		}
		
		// Skip our own messages
		if msg.ReceivedFrom == n.Host.ID() {
			continue
		}
		
		// Deserialize signed message
		var signedMsg SignedMessage
		if err := json.Unmarshal(msg.Data, &signedMsg); err != nil {
			log.Printf("❌ Failed to deserialize signed transaction message: %v", err)
			continue
		}
		
		// Verify signature
		if !n.verifyMessage(&signedMsg) {
			log.Printf("❌ Invalid signature for transaction message from %s", msg.ReceivedFrom)
			continue
		}
		
		// Deserialize transaction
		tx, err := DeserializeTransaction(signedMsg.Data)
		if err != nil {
			log.Printf("❌ Failed to deserialize transaction: %v", err)
			continue
		}
		
		// Add to pending transactions
		if n.chain != nil {
			n.chain.mu.Lock()
			n.chain.PendingTxs = append(n.chain.PendingTxs, tx)
			n.chain.mu.Unlock()
			log.Printf("📥 Added transaction %s from peer %s to pending", tx.ID, msg.ReceivedFrom)
		}
	}
}

// handleSecureStream handles direct peer-to-peer streams
func (n *SecureP2PNode) handleSecureStream(s network.Stream) {
	defer s.Close()
	peerID := s.Conn().RemotePeer()
	log.Printf("🔒 Secure stream from peer: %s", peerID)
	
	// Handle secure direct messages if needed
	// This can be used for sync requests, peer discovery, etc.
}

// handleTransactionStream handles transaction submissions from wallets
func (n *SecureP2PNode) handleTransactionStream(s network.Stream) {
	defer s.Close()
	peerID := s.Conn().RemotePeer()
	log.Printf("💸 Transaction stream from wallet: %s", peerID)
	
	// Add peer to our list if not already present
	n.addPeer(peerID, false)
	
	// Read transaction data
	buf := make([]byte, 4096)
	bytesRead, err := s.Read(buf)
	if err != nil {
		log.Printf("❌ Failed to read transaction data: %v", err)
		return
	}
	
	txData := string(buf[:bytesRead])
	log.Printf("📥 Received transaction data: %s", txData)
	
	// Parse transaction (expecting format: TX:{"from":"...","to":"...","amount":...})
	if len(txData) > 3 && txData[:3] == "TX:" {
		jsonData := txData[3:] // Remove "TX:" prefix
		
		// Parse JSON transaction
		var txReq struct {
			From      string  `json:"from"`
			To        string  `json:"to"`
			Amount    float64 `json:"amount"`
			Timestamp int64   `json:"timestamp"`
		}
		
		if err := json.Unmarshal([]byte(jsonData), &txReq); err != nil {
			log.Printf("❌ Failed to parse transaction JSON: %v", err)
			// Send error response
			s.Write([]byte("ERROR: Invalid transaction format"))
			return
		}
		
		// Create blockchain transaction
		tx := &Transaction{
			ID:        fmt.Sprintf("tx_%d_%s", time.Now().Unix(), peerID.String()[:8]),
			From:      txReq.From,
			To:        txReq.To,
			Amount:    uint64(txReq.Amount * 100), // Convert to reasonable decimal units (2 decimal places)
			Timestamp: time.Now().Unix(),
			Nonce:     uint64(time.Now().UnixNano()),
		}
		
		// Add to blockchain's pending transactions
		if n.chain != nil {
			n.chain.mu.Lock()
			n.chain.PendingTxs = append(n.chain.PendingTxs, tx)
			n.chain.mu.Unlock()
			
			log.Printf("✅ Added transaction %s to pending pool (From: %s, To: %s, Amount: %.6f)", 
				tx.ID, tx.From, tx.To, tx.Amount)
			
			// Send transaction hash back to wallet
			txHash := fmt.Sprintf("hash_%x", tx.ID)
			s.Write([]byte(txHash))
		} else {
			log.Printf("❌ Blockchain not initialized")
			s.Write([]byte("ERROR: Blockchain not initialized"))
		}
	} else {
		log.Printf("❌ Invalid transaction format, expected TX: prefix")
		s.Write([]byte("ERROR: Expected TX: prefix"))
	}
}

// handleWalletStream handles general wallet connections and requests
func (n *SecureP2PNode) handleWalletStream(s network.Stream) {
	defer s.Close()
	peerID := s.Conn().RemotePeer()
	log.Printf("👛 Wallet stream from: %s", peerID)
	
	// Add peer to our list
	n.addPeer(peerID, false)
	
	// Handle wallet-specific requests (balance queries, transaction history, etc.)
	// For now, just acknowledge the connection
	response := fmt.Sprintf("CONNECTED:%s:%d", n.Host.ID(), time.Now().Unix())
	s.Write([]byte(response))
}

// startDiscovery starts mDNS peer discovery for local network
func (n *SecureP2PNode) startDiscovery() {
	discoveryService := mdns.NewMdnsService(n.Host, "blackhole-blockchain", &discoveryNotifee{node: n})
	if err := discoveryService.Start(); err != nil {
		log.Printf("❌ Failed to start mDNS discovery: %v", err)
	} else {
		log.Printf("🔍 Started mDNS peer discovery")
	}
}

// connectToBootstrapPeers connects to configured bootstrap peers
func (n *SecureP2PNode) connectToBootstrapPeers() {
	for _, addrStr := range n.bootstrapPeers {
		maddr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			log.Printf("❌ Invalid bootstrap address %s: %v", addrStr, err)
			continue
		}
		
		info, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			log.Printf("❌ Failed to parse bootstrap address %s: %v", addrStr, err)
			continue
		}
		
		// Connect to bootstrap peer
		ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
		if err := n.Host.Connect(ctx, *info); err != nil {
			log.Printf("❌ Failed to connect to bootstrap peer %s: %v", info.ID, err)
		} else {
			log.Printf("🌐 Connected to bootstrap peer: %s", info.ID)
			n.addPeer(info.ID, true)
		}
		cancel()
		
		time.Sleep(1 * time.Second) // Delay between connections
	}
}

// maintainPeers performs periodic peer maintenance
func (n *SecureP2PNode) maintainPeers() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.cleanupDisconnectedPeers()
			n.logPeerStats()
		}
	}
}

// addPeer adds a peer to our peer list
func (n *SecureP2PNode) addPeer(peerID peer.ID, isBootstrap bool) {
	n.peersLock.Lock()
	defer n.peersLock.Unlock()
	
	if _, exists := n.peers[peerID]; !exists {
		n.peers[peerID] = &PeerInfo{
			ID:          peerID,
			ConnectedAt: time.Now(),
			LastSeen:    time.Now(),
			IsBootstrap: isBootstrap,
		}
		log.Printf("➕ Added peer: %s (bootstrap: %v)", peerID, isBootstrap)
	}
}

// cleanupDisconnectedPeers removes peers that are no longer connected
func (n *SecureP2PNode) cleanupDisconnectedPeers() {
	n.peersLock.Lock()
	defer n.peersLock.Unlock()
	
	for peerID := range n.peers {
		if n.Host.Network().Connectedness(peerID) != network.Connected {
			delete(n.peers, peerID)
			log.Printf("➖ Removed disconnected peer: %s", peerID)
		}
	}
}

// logPeerStats logs current peer statistics
func (n *SecureP2PNode) logPeerStats() {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()
	
	connected := len(n.peers)
	if connected > 0 {
		log.Printf("📊 Connected peers: %d", connected)
	}
}

// GetConnectedPeers returns the list of connected peers
func (n *SecureP2PNode) GetConnectedPeers() []peer.ID {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()
	
	peers := make([]peer.ID, 0, len(n.peers))
	for peerID := range n.peers {
		if n.Host.Network().Connectedness(peerID) == network.Connected {
			peers = append(peers, peerID)
		}
	}
	return peers
}


// discoveryNotifee handles mDNS discovery notifications
type discoveryNotifee struct {
	node *SecureP2PNode
}

func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	log.Printf("🔍 Discovered peer: %s", pi.ID)
	
	// Connect to discovered peer
	ctx, cancel := context.WithTimeout(n.node.ctx, 10*time.Second)
	defer cancel()
	
	if err := n.node.Host.Connect(ctx, pi); err != nil {
		log.Printf("❌ Failed to connect to discovered peer %s: %v", pi.ID, err)
	} else {
		log.Printf("🌐 Connected to discovered peer: %s", pi.ID)
		n.node.addPeer(pi.ID, false)
	}
}

// Close shuts down the secure P2P node
func (n *SecureP2PNode) Close() error {
	log.Printf("🔒 Shutting down secure P2P node")
	return n.Host.Close()
}