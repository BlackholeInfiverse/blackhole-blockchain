package grpc

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"google.golang.org/grpc"
)

// SimpleRelayServer provides a simplified gRPC server without protobuf dependencies
type SimpleRelayServer struct {
	blockchain *chain.Blockchain
	grpcServer *grpc.Server
	port       int
}

// NewSimpleRelayServer creates a new simplified gRPC relay server
func NewSimpleRelayServer(blockchain *chain.Blockchain, port int) *SimpleRelayServer {
	return &SimpleRelayServer{
		blockchain: blockchain,
		port:       port,
	}
}

// Start starts the gRPC server
func (s *SimpleRelayServer) Start() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", s.port, err)
	}

	s.grpcServer = grpc.NewServer()
	// Note: Service registration would happen here when protobuf is implemented

	fmt.Printf("🚀 Simple gRPC Relay Server starting on port %d\n", s.port)

	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the gRPC server
func (s *SimpleRelayServer) Stop() {
	if s.grpcServer != nil {
		fmt.Println("🛑 Stopping gRPC Relay Server...")
		s.grpcServer.GracefulStop()
	}
}

// GetBlockchainStatus returns basic blockchain status (for internal use)
func (s *SimpleRelayServer) GetBlockchainStatus() map[string]interface{} {
	latestBlock := s.blockchain.GetLatestBlock()
	if latestBlock == nil {
		return map[string]interface{}{
			"success": false,
			"error":   "no blocks found",
		}
	}

	// Get validator information
	allStakes := s.blockchain.StakeLedger.GetAllStakes()
	validatorCount := len(allStakes)

	// Get total supply
	totalSupply := uint64(0)
	if tokenSystem, exists := s.blockchain.TokenRegistry["BHX"]; exists {
		totalSupply = tokenSystem.TotalSupply()
	}

	return map[string]interface{}{
		"success":            true,
		"chain_id":           "blackhole-mainnet",
		"block_height":       latestBlock.Header.Index,
		"latest_block_hash":  latestBlock.CalculateHash(),
		"latest_block_time":  latestBlock.Header.Timestamp.Unix(),
		"total_supply":       totalSupply,
		"circulating_supply": totalSupply,
		"validator_count":    validatorCount,
		"pending_txs":        len(s.blockchain.PendingTxs),
	}
}

// SubmitTransactionSimple submits a transaction (simplified version)
func (s *SimpleRelayServer) SubmitTransactionSimple(from, to, tokenID string, amount uint64) (string, error) {
	tx := &chain.Transaction{
		From:      from,
		To:        to,
		Amount:    amount,
		TokenID:   tokenID,
		Timestamp: time.Now().Unix(),
	}

	// Calculate transaction hash
	tx.ID = tx.CalculateHash()

	// Add transaction to pending pool
	s.blockchain.PendingTxs = append(s.blockchain.PendingTxs, tx)

	fmt.Printf("📤 Transaction submitted: %s -> %s (%d %s)\n", from, to, amount, tokenID)
	return tx.ID, nil
}

// GetBalanceSimple gets balance for an address (simplified version)
func (s *SimpleRelayServer) GetBalanceSimple(address, tokenID string) (uint64, error) {
	if tokenID == "" {
		tokenID = "BHX" // Default token
	}

	if token, exists := s.blockchain.TokenRegistry[tokenID]; exists {
		balance, err := token.BalanceOf(address)
		if err != nil {
			return 0, fmt.Errorf("failed to get balance: %v", err)
		}
		return balance, nil
	}

	return 0, fmt.Errorf("token %s not found", tokenID)
}

// ValidateTransactionSimple validates a transaction (simplified version)
func (s *SimpleRelayServer) ValidateTransactionSimple(from, to, tokenID string, amount uint64) (bool, string, error) {
	// Basic validation
	if from == "" || to == "" {
		return false, "from and to addresses are required", nil
	}

	if amount == 0 {
		return false, "amount must be greater than 0", nil
	}

	// Check token exists
	if tokenID != "" {
		if _, exists := s.blockchain.TokenRegistry[tokenID]; !exists {
			return false, fmt.Sprintf("token %s not found", tokenID), nil
		}

		// Check balance
		if token, exists := s.blockchain.TokenRegistry[tokenID]; exists {
			balance, err := token.BalanceOf(from)
			if err != nil {
				return false, fmt.Sprintf("failed to check balance: %v", err), nil
			}

			if balance < amount {
				return false, "insufficient balance", nil
			}
		}
	}

	return true, "transaction is valid", nil
}

// GetValidatorsSimple returns validator information (simplified version)
func (s *SimpleRelayServer) GetValidatorsSimple() []map[string]interface{} {
	allStakes := s.blockchain.StakeLedger.GetAllStakes()
	validators := make([]map[string]interface{}, 0)

	for address, stake := range allStakes {
		validator := map[string]interface{}{
			"address": address,
			"stake":   stake,
			"status":  "active",
			"jailed":  false,
			"strikes": 0,
		}

		// Check if validator is jailed (if slashing manager is available)
		if s.blockchain.SlashingManager != nil {
			if s.blockchain.SlashingManager.IsValidatorJailed(address) {
				validator["status"] = "jailed"
				validator["jailed"] = true
				validator["strikes"] = s.blockchain.SlashingManager.GetValidatorStrikes(address)
			}
		}

		validators = append(validators, validator)
	}

	return validators
}

// GetPendingTransactionsSimple returns pending transactions (simplified version)
func (s *SimpleRelayServer) GetPendingTransactionsSimple() []map[string]interface{} {
	pendingTxs := make([]map[string]interface{}, 0)

	for _, tx := range s.blockchain.PendingTxs {
		txInfo := map[string]interface{}{
			"id":        tx.ID,
			"from":      tx.From,
			"to":        tx.To,
			"amount":    tx.Amount,
			"token_id":  tx.TokenID,
			"timestamp": tx.Timestamp,
		}
		pendingTxs = append(pendingTxs, txInfo)
	}

	return pendingTxs
}

// GetNetworkStatsSimple returns network statistics (simplified version)
func (s *SimpleRelayServer) GetNetworkStatsSimple() map[string]interface{} {
	stats := map[string]interface{}{
		"total_blocks":      len(s.blockchain.Blocks),
		"pending_txs":       len(s.blockchain.PendingTxs),
		"total_validators":  len(s.blockchain.StakeLedger.GetAllStakes()),
		"network_hash_rate": "1.5 TH/s", // Placeholder
		"avg_block_time":    "6s",       // Placeholder
		"last_block_time":   time.Now().Unix(),
	}

	// Add token statistics
	if tokenSystem, exists := s.blockchain.TokenRegistry["BHX"]; exists {
		stats["total_supply"] = tokenSystem.TotalSupply()
		stats["circulating_supply"] = tokenSystem.TotalSupply()
	}

	return stats
}

// HealthCheck returns server health status
func (s *SimpleRelayServer) HealthCheck() map[string]interface{} {
	return map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"uptime":    "running",
		"version":   "1.0.0",
		"services": map[string]bool{
			"blockchain": s.blockchain != nil,
			"grpc":       s.grpcServer != nil,
		},
	}
}

// LogActivity logs server activity
func (s *SimpleRelayServer) LogActivity(activity string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] gRPC Server: %s\n", timestamp, activity)
}
