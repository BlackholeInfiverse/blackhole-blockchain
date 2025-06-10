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
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/escrow"
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
	fmt.Printf("🔍 Querying balance for address %s, token %s\n", address, tokenSymbol)

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
		fmt.Printf("🔗 Trying to query balance from %d connected peers\n", len(client.ConnectedPeers))
		for _, peerAddr := range client.ConnectedPeers {
			fmt.Printf("   🔍 Checking peer: %s\n", peerAddr)
			// Extract port from peer address and try HTTP API
			if apiPort := client.extractAPIPortFromPeer(peerAddr); apiPort != "" {
				fmt.Printf("   📡 Extracted API port: %s\n", apiPort)
				balance, err := client.queryBalanceViaHTTPPort(address, tokenSymbol, apiPort)
				if err == nil {
					fmt.Printf("✅ Retrieved balance from peer API: %d %s for address %s\n", balance, tokenSymbol, address)
					return balance, nil
				}
				fmt.Printf("⚠️ Failed to query balance from peer API on port %s: %v\n", apiPort, err)
			} else {
				fmt.Printf("   ❌ Could not extract API port from peer address\n")
			}
		}
	} else {
		fmt.Printf("⚠️ No connected peers available\n")
	}

	// Try default blockchain API port (8080) with dedicated balance endpoint
	fmt.Printf("🔄 Trying dedicated balance query endpoint on port 8080...\n")
	balance, err := client.queryBalanceViaDedicatedEndpoint(address, tokenSymbol, "8080")
	if err == nil {
		fmt.Printf("✅ Retrieved balance from dedicated endpoint: %d %s for address %s\n", balance, tokenSymbol, address)
		return balance, nil
	}
	fmt.Printf("⚠️ Failed to query balance from dedicated endpoint: %v\n", err)

	// Fallback to general blockchain info endpoint
	fmt.Printf("🔄 Trying general blockchain info endpoint on port 8080...\n")
	balance, err = client.queryBalanceViaHTTPPort(address, tokenSymbol, "8080")
	if err == nil {
		fmt.Printf("✅ Retrieved balance from general endpoint: %d %s for address %s\n", balance, tokenSymbol, address)
		return balance, nil
	}
	fmt.Printf("⚠️ Failed to query balance from general endpoint: %v\n", err)

	fmt.Printf("❌ All balance query methods failed. Returning 0 balance.\n")
	return 0, fmt.Errorf("unable to query balance: no blockchain connection available")
}

// TransferTokens transfers tokens from one address to another with enhanced validation
func (client *BlockchainClient) TransferTokens(from, to, tokenSymbol string, amount uint64, privateKey []byte) error {
	if len(client.ConnectedPeers) == 0 {
		return fmt.Errorf("not connected to any blockchain nodes")
	}

	// ===== PRE-TRANSFER VALIDATION =====
	fmt.Printf("🔍 Starting pre-transfer validation...\n")

	// 1. Validate sender has sufficient balance
	fmt.Printf("   📊 Checking sender balance...\n")
	balance, err := client.GetTokenBalance(from, tokenSymbol)
	if err != nil {
		return fmt.Errorf("failed to check sender balance: %v", err)
	}

	if balance < amount {
		return fmt.Errorf("❌ Insufficient balance: sender has %d %s, needs %d %s", balance, tokenSymbol, amount, tokenSymbol)
	}
	fmt.Printf("   ✅ Sender balance sufficient: %d %s (transferring %d %s)\n", balance, tokenSymbol, amount, tokenSymbol)

	// 2. Validate receiver address exists (basic validation)
	if to == "" {
		return fmt.Errorf("❌ Receiver address cannot be empty")
	}

	// Additional validation: check if receiver address is valid format
	if len(to) < 10 {
		return fmt.Errorf("❌ Invalid receiver address format: %s", to)
	}
	fmt.Printf("   ✅ Receiver address validated: %s\n", to)

	// 3. Validate amount is positive
	if amount == 0 {
		return fmt.Errorf("❌ Transfer amount must be greater than 0")
	}
	fmt.Printf("   ✅ Transfer amount validated: %d %s\n", amount, tokenSymbol)

	// 4. Check if this is a self-transfer (optional warning)
	if from == to {
		fmt.Printf("   ⚠️ Warning: Self-transfer detected (from %s to %s)\n", from, to)
	}

	fmt.Printf("✅ Pre-transfer validation completed successfully\n")

	// ===== CREATE AND SEND TRANSACTION =====
	fmt.Printf("🚀 Creating transaction...\n")

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
	fmt.Printf("   📝 Transaction ID: %s\n", tx.ID)

	// Sign transaction (simplified - would need actual signing logic)
	// tx.Sign(privateKey)

	// Send transaction to connected blockchain nodes via P2P
	fmt.Printf("   📡 Sending transaction to blockchain network...\n")
	err = client.sendTransactionToNetwork(tx)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %v", err)
	}

	fmt.Printf("✅ Token transfer completed successfully: %d %s from %s to %s\n", amount, tokenSymbol, from, to)
	return nil
}

// TransferTokensWithEscrow transfers tokens using escrow for added security
func (client *BlockchainClient) TransferTokensWithEscrow(from, to, arbitrator, tokenSymbol string, amount uint64, expirationHours int, description string, privateKey []byte) (*escrow.EscrowContract, error) {
	fmt.Printf("🔒 Starting escrow transfer...\n")

	// Use the same pre-transfer validation as regular transfers
	if len(client.ConnectedPeers) == 0 {
		return nil, fmt.Errorf("not connected to any blockchain nodes")
	}

	// Validate inputs
	if from == "" || to == "" {
		return nil, fmt.Errorf("❌ Sender and receiver addresses cannot be empty")
	}

	if amount == 0 {
		return nil, fmt.Errorf("❌ Transfer amount must be greater than 0")
	}

	// Check sender balance
	balance, err := client.GetTokenBalance(from, tokenSymbol)
	if err != nil {
		return nil, fmt.Errorf("failed to check sender balance: %v", err)
	}

	if balance < amount {
		return nil, fmt.Errorf("❌ Insufficient balance: sender has %d %s, needs %d %s", balance, tokenSymbol, amount, tokenSymbol)
	}

	fmt.Printf("✅ Escrow pre-validation completed\n")

	// Create escrow contract
	contract, err := client.CreateEscrow(from, to, arbitrator, tokenSymbol, amount, expirationHours, description, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create escrow: %v", err)
	}

	fmt.Printf("✅ Escrow transfer initiated: %s\n", contract.ID)
	fmt.Printf("   📋 Escrow Details:\n")
	fmt.Printf("      - ID: %s\n", contract.ID)
	fmt.Printf("      - From: %s\n", contract.Sender)
	fmt.Printf("      - To: %s\n", contract.Receiver)
	fmt.Printf("      - Amount: %d %s\n", contract.Amount, contract.TokenSymbol)
	fmt.Printf("      - Status: %s\n", contract.Status.String())
	fmt.Printf("      - Expires: %s\n", time.Unix(contract.ExpiresAt, 0).Format("2006-01-02 15:04:05"))

	return contract, nil
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
	fmt.Printf("   📡 Querying: %s\n", url)

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

	fmt.Printf("   📊 Blockchain API response keys: %v\n", getMapKeys(blockchainInfo))

	// Extract token balances - fix the structure to match actual API response
	tokenBalances, ok := blockchainInfo["tokenBalances"].(map[string]interface{})
	if !ok {
		fmt.Printf("   ❌ tokenBalances not found in response\n")
		return 0, fmt.Errorf("token balances not found in response")
	}

	fmt.Printf("   🪙 Available tokens: %v\n", getMapKeys(tokenBalances))

	tokenData, ok := tokenBalances[tokenSymbol].(map[string]interface{})
	if !ok {
		fmt.Printf("   ❌ Token %s not found in tokenBalances\n", tokenSymbol)
		return 0, fmt.Errorf("token %s not found", tokenSymbol)
	}

	fmt.Printf("   📍 Addresses with %s balances: %v\n", tokenSymbol, getMapKeys(tokenData))

	balance, ok := tokenData[address].(float64)
	if !ok {
		fmt.Printf("   ℹ️ Address %s not found in %s balances, returning 0\n", address, tokenSymbol)
		return 0, nil // Address not found, balance is 0
	}

	fmt.Printf("   ✅ Found balance: %f\n", balance)
	return uint64(balance), nil
}

// getMapKeys returns the keys of a map[string]interface{} for debugging
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// queryBalanceViaDedicatedEndpoint queries balance using the dedicated balance endpoint
func (client *BlockchainClient) queryBalanceViaDedicatedEndpoint(address, tokenSymbol, port string) (uint64, error) {
	url := fmt.Sprintf("http://localhost:%s/api/balance/query", port)
	fmt.Printf("   📡 Querying dedicated endpoint: %s\n", url)

	// Create request payload
	requestData := map[string]string{
		"address":      address,
		"token_symbol": tokenSymbol,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Send POST request
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, fmt.Errorf("failed to query dedicated balance endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response: %v", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return 0, fmt.Errorf("failed to parse response: %v", err)
	}

	// Check if request was successful
	success, ok := response["success"].(bool)
	if !ok || !success {
		errorMsg := "unknown error"
		if msg, ok := response["error"].(string); ok {
			errorMsg = msg
		}
		return 0, fmt.Errorf("balance query failed: %s", errorMsg)
	}

	// Extract balance from response
	data, ok := response["data"].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid response format: missing data")
	}

	balance, ok := data["balance"].(float64)
	if !ok {
		return 0, fmt.Errorf("invalid response format: missing balance")
	}

	fmt.Printf("   ✅ Dedicated endpoint returned balance: %f\n", balance)
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

	fmt.Printf("   📊 Blockchain API response keys: %v\n", getMapKeys(blockchainInfo))

	// Extract token balances
	tokenBalances, ok := blockchainInfo["tokenBalances"].(map[string]interface{})
	if !ok {
		fmt.Printf("   ❌ tokenBalances not found in response\n")
		return 0, fmt.Errorf("token balances not found in response")
	}

	fmt.Printf("   🪙 Available tokens: %v\n", getMapKeys(tokenBalances))

	tokenData, ok := tokenBalances[tokenSymbol].(map[string]interface{})
	if !ok {
		fmt.Printf("   ❌ Token %s not found in tokenBalances\n", tokenSymbol)
		return 0, fmt.Errorf("token %s not found", tokenSymbol)
	}

	fmt.Printf("   📍 Addresses with %s balances: %v\n", tokenSymbol, getMapKeys(tokenData))

	balance, ok := tokenData[address].(float64)
	if !ok {
		fmt.Printf("   ℹ️ Address %s not found in %s balances, returning 0\n", address, tokenSymbol)
		return 0, nil // Address not found, balance is 0
	}

	fmt.Printf("   ✅ Found balance: %f\n", balance)
	return uint64(balance), nil
}

// ===== ESCROW OPERATIONS =====

// CreateEscrow creates a new escrow contract via blockchain
func (client *BlockchainClient) CreateEscrow(sender, receiver, arbitrator, tokenSymbol string, amount uint64, expirationHours int, description string, privateKey []byte) (*escrow.EscrowContract, error) {
	if len(client.ConnectedPeers) == 0 {
		return nil, fmt.Errorf("not connected to any blockchain nodes")
	}

	// First, validate that sender has sufficient balance
	balance, err := client.GetTokenBalance(sender, tokenSymbol)
	if err != nil {
		return nil, fmt.Errorf("failed to check balance: %v", err)
	}

	if balance < amount {
		return nil, fmt.Errorf("insufficient balance: has %d, needs %d", balance, amount)
	}

	// Validate receiver address (basic check)
	if receiver == "" {
		return nil, fmt.Errorf("receiver address cannot be empty")
	}

	// Create escrow creation message
	escrowData := map[string]interface{}{
		"action":           "create_escrow",
		"sender":           sender,
		"receiver":         receiver,
		"arbitrator":       arbitrator,
		"token_symbol":     tokenSymbol,
		"amount":           amount,
		"expiration_hours": expirationHours,
		"description":      description,
	}

	// Send escrow creation request to blockchain
	response, err := client.sendEscrowRequest(escrowData)
	if err != nil {
		return nil, fmt.Errorf("failed to create escrow: %v", err)
	}

	// Parse response to get escrow contract
	escrowID, ok := response["escrow_id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid response: missing escrow_id")
	}

	// Create and return escrow contract object
	contract := &escrow.EscrowContract{
		ID:           escrowID,
		Sender:       sender,
		Receiver:     receiver,
		Arbitrator:   arbitrator,
		TokenSymbol:  tokenSymbol,
		Amount:       amount,
		Status:       escrow.EscrowPending,
		Description:  description,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(time.Duration(expirationHours) * time.Hour).Unix(),
		Signatures:   make(map[string]bool),
		RequiredSigs: 2,
		Conditions:   make(map[string]interface{}),
	}

	if arbitrator != "" {
		contract.RequiredSigs = 2 // Any 2 of 3
	}

	fmt.Printf("✅ Escrow created successfully: %s\n", escrowID)
	return contract, nil
}

// ConfirmEscrow confirms an escrow contract
func (client *BlockchainClient) ConfirmEscrow(escrowID, confirmer string, privateKey []byte) error {
	if len(client.ConnectedPeers) == 0 {
		return fmt.Errorf("not connected to any blockchain nodes")
	}

	// Create escrow confirm message
	escrowData := map[string]interface{}{
		"action":    "confirm_escrow",
		"escrow_id": escrowID,
		"confirmer": confirmer,
	}

	// Send escrow confirm request to blockchain
	_, err := client.sendEscrowRequest(escrowData)
	if err != nil {
		return fmt.Errorf("failed to confirm escrow: %v", err)
	}

	fmt.Printf("✅ Escrow %s confirmed successfully\n", escrowID)
	return nil
}

// ReleaseEscrow releases funds from an escrow to the receiver
func (client *BlockchainClient) ReleaseEscrow(escrowID, releaser string, privateKey []byte) error {
	if len(client.ConnectedPeers) == 0 {
		return fmt.Errorf("not connected to any blockchain nodes")
	}

	// Create escrow release message
	escrowData := map[string]interface{}{
		"action":    "release_escrow",
		"escrow_id": escrowID,
		"releaser":  releaser,
	}

	// Send escrow release request to blockchain
	_, err := client.sendEscrowRequest(escrowData)
	if err != nil {
		return fmt.Errorf("failed to release escrow: %v", err)
	}

	fmt.Printf("✅ Escrow %s released successfully\n", escrowID)
	return nil
}

// CancelEscrow cancels an escrow and returns funds to sender
func (client *BlockchainClient) CancelEscrow(escrowID, canceller string, privateKey []byte) error {
	if len(client.ConnectedPeers) == 0 {
		return fmt.Errorf("not connected to any blockchain nodes")
	}

	// Create escrow cancel message
	escrowData := map[string]interface{}{
		"action":    "cancel_escrow",
		"escrow_id": escrowID,
		"canceller": canceller,
	}

	// Send escrow cancel request to blockchain
	_, err := client.sendEscrowRequest(escrowData)
	if err != nil {
		return fmt.Errorf("failed to cancel escrow: %v", err)
	}

	fmt.Printf("✅ Escrow %s cancelled successfully\n", escrowID)
	return nil
}

// GetEscrowDetails gets details of an escrow contract
func (client *BlockchainClient) GetEscrowDetails(escrowID string) (*escrow.EscrowContract, error) {
	if len(client.ConnectedPeers) == 0 {
		return nil, fmt.Errorf("not connected to any blockchain nodes")
	}

	// Create escrow details request
	escrowData := map[string]interface{}{
		"action":    "get_escrow",
		"escrow_id": escrowID,
	}

	// Send escrow details request to blockchain
	response, err := client.sendEscrowRequest(escrowData)
	if err != nil {
		return nil, fmt.Errorf("failed to get escrow details: %v", err)
	}

	// Parse response to create escrow contract
	contract := &escrow.EscrowContract{
		ID:           escrowID,
		Sender:       response["sender"].(string),
		Receiver:     response["receiver"].(string),
		Arbitrator:   response["arbitrator"].(string),
		TokenSymbol:  response["token_symbol"].(string),
		Amount:       uint64(response["amount"].(float64)),
		Status:       parseEscrowStatus(response["status"].(string)),
		Description:  response["description"].(string),
		CreatedAt:    int64(response["created_at"].(float64)),
		ExpiresAt:    int64(response["expires_at"].(float64)),
		Signatures:   make(map[string]bool),
		RequiredSigs: int(response["required_sigs"].(float64)),
		Conditions:   make(map[string]interface{}),
	}

	return contract, nil
}

// GetUserEscrows gets all escrows where the user is involved
func (client *BlockchainClient) GetUserEscrows(userAddress string) ([]*escrow.EscrowContract, error) {
	if len(client.ConnectedPeers) == 0 {
		return nil, fmt.Errorf("not connected to any blockchain nodes")
	}

	// Create user escrows request
	escrowData := map[string]interface{}{
		"action":       "get_user_escrows",
		"user_address": userAddress,
	}

	// Send user escrows request to blockchain
	response, err := client.sendEscrowRequest(escrowData)
	if err != nil {
		return nil, fmt.Errorf("failed to get user escrows: %v", err)
	}

	// Parse response to create escrow contracts list
	escrowsData, ok := response["escrows"].([]interface{})
	if !ok {
		return []*escrow.EscrowContract{}, nil // Return empty list if no escrows
	}

	var contracts []*escrow.EscrowContract
	for _, escrowData := range escrowsData {
		data := escrowData.(map[string]interface{})
		contract := &escrow.EscrowContract{
			ID:           data["id"].(string),
			Sender:       data["sender"].(string),
			Receiver:     data["receiver"].(string),
			Arbitrator:   data["arbitrator"].(string),
			TokenSymbol:  data["token_symbol"].(string),
			Amount:       uint64(data["amount"].(float64)),
			Status:       parseEscrowStatus(data["status"].(string)),
			Description:  data["description"].(string),
			CreatedAt:    int64(data["created_at"].(float64)),
			ExpiresAt:    int64(data["expires_at"].(float64)),
			Signatures:   make(map[string]bool),
			RequiredSigs: int(data["required_sigs"].(float64)),
			Conditions:   make(map[string]interface{}),
		}
		contracts = append(contracts, contract)
	}

	return contracts, nil
}

// sendEscrowRequest sends an escrow-related request to the blockchain
func (client *BlockchainClient) sendEscrowRequest(escrowData map[string]interface{}) (map[string]interface{}, error) {
	// For now, we'll use HTTP API to send escrow requests
	// In a full implementation, this would use P2P messaging

	if len(client.ConnectedPeers) == 0 {
		return nil, fmt.Errorf("not connected to any blockchain nodes")
	}

	// Try to send request via HTTP API
	for _, peerAddr := range client.ConnectedPeers {
		if apiPort := client.extractAPIPortFromPeer(peerAddr); apiPort != "" {
			response, err := client.sendEscrowRequestViaHTTP(escrowData, apiPort)
			if err == nil {
				return response, nil
			}
			fmt.Printf("⚠️ Failed to send escrow request via HTTP API on port %s: %v\n", apiPort, err)
		}
	}

	return nil, fmt.Errorf("failed to send escrow request to any connected peers")
}

// sendEscrowRequestViaHTTP sends escrow request via HTTP API
func (client *BlockchainClient) sendEscrowRequestViaHTTP(escrowData map[string]interface{}, port string) (map[string]interface{}, error) {
	url := fmt.Sprintf("http://localhost:%s/api/escrow/request", port)

	// Convert escrow data to JSON
	jsonData, err := json.Marshal(escrowData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal escrow data: %v", err)
	}

	// Send POST request
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse response
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Check if request was successful
	if success, ok := response["success"].(bool); !ok || !success {
		errorMsg := "unknown error"
		if msg, ok := response["error"].(string); ok {
			errorMsg = msg
		}
		return nil, fmt.Errorf("escrow request failed: %s", errorMsg)
	}

	return response, nil
}

// parseEscrowStatus converts string status to EscrowStatus
func parseEscrowStatus(status string) escrow.EscrowStatus {
	switch status {
	case "pending":
		return escrow.EscrowPending
	case "confirmed":
		return escrow.EscrowConfirmed
	case "released":
		return escrow.EscrowReleased
	case "cancelled":
		return escrow.EscrowCancelled
	case "disputed":
		return escrow.EscrowDisputed
	default:
		return escrow.EscrowPending
	}
}
