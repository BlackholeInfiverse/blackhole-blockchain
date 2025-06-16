package grpc

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"google.golang.org/grpc"
)

// RelayServer implements the gRPC RelayService
type RelayServer struct {
	UnimplementedRelayServiceServer
	blockchain *chain.Blockchain
	grpcServer *grpc.Server
	port       int
}

// NewRelayServer creates a new gRPC relay server
func NewRelayServer(blockchain *chain.Blockchain, port int) *RelayServer {
	return &RelayServer{
		blockchain: blockchain,
		port:       port,
	}
}

// Start starts the gRPC server
func (s *RelayServer) Start() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", s.port, err)
	}

	s.grpcServer = grpc.NewServer()
	RegisterRelayServiceServer(s.grpcServer, s)

	fmt.Printf("🚀 gRPC Relay Server starting on port %d\n", s.port)
	
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	return nil
}

// Stop stops the gRPC server
func (s *RelayServer) Stop() {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
		fmt.Println("🛑 gRPC Relay Server stopped")
	}
}

// SubmitTransaction submits a transaction to the blockchain
func (s *RelayServer) SubmitTransaction(ctx context.Context, req *TransactionRequest) (*TransactionResponse, error) {
	// Convert gRPC request to blockchain transaction
	tx := &chain.Transaction{
		Type:      chain.TransactionType(req.Type),
		From:      req.From,
		To:        req.To,
		Amount:    req.Amount,
		TokenID:   req.TokenId,
		Fee:       req.Fee,
		Nonce:     req.Nonce,
		Timestamp: req.Timestamp,
		Signature: req.Signature,
		PublicKey: req.PublicKey,
	}

	// Generate transaction ID
	tx.ID = tx.CalculateHash()

	// Add transaction to pending pool
	err := s.blockchain.AddPendingTransaction(tx)
	if err != nil {
		return &TransactionResponse{
			Success:     false,
			Error:       err.Error(),
			SubmittedAt: time.Now().Unix(),
		}, nil
	}

	return &TransactionResponse{
		Success:       true,
		TransactionId: tx.ID,
		Hash:          tx.ID,
		Status:        "pending",
		SubmittedAt:   time.Now().Unix(),
	}, nil
}

// GetChainStatus returns the current blockchain status
func (s *RelayServer) GetChainStatus(ctx context.Context, req *StatusRequest) (*StatusResponse, error) {
	// Get latest block
	latestBlock := s.blockchain.GetLatestBlock()
	if latestBlock == nil {
		return &StatusResponse{
			Success: false,
		}, fmt.Errorf("no blocks found")
	}

	// Get validator information
	var validators []*ValidatorInfo
	if req.IncludeValidators {
		allStakes := s.blockchain.StakeLedger.GetAllStakes()
		for address, stake := range allStakes {
			validator := &ValidatorInfo{
				Address: address,
				Stake:   stake,
				Status:  "active",
			}

			// Check if validator is jailed
			if s.blockchain.SlashingManager.IsValidatorJailed(address) {
				validator.Status = "jailed"
				validator.Jailed = true
			}

			// Get validator strikes
			strikes := s.blockchain.SlashingManager.GetValidatorStrikes(address)
			validator.Strikes = uint32(strikes)

			validators = append(validators, validator)
		}
	}

	// Get pending transactions count
	pendingTxs := uint32(0)
	if req.IncludePendingTxs {
		pendingTxs = uint32(len(s.blockchain.GetPendingTransactions()))
	}

	// Calculate total and circulating supply
	totalSupply := uint64(0)
	circulatingSupply := uint64(0)
	if bhxToken, exists := s.blockchain.TokenRegistry["BHX"]; exists {
		totalSupply = bhxToken.TotalSupply()
		circulatingSupply = totalSupply // Simplified: all tokens are circulating
	}

	return &StatusResponse{
		Success:              true,
		ChainId:              "blackhole-mainnet",
		BlockHeight:          latestBlock.Header.Index,
		LatestBlockHash:      latestBlock.Header.Hash,
		LatestBlockTime:      latestBlock.Header.Timestamp,
		TotalSupply:          totalSupply,
		CirculatingSupply:    circulatingSupply,
		ValidatorCount:       uint32(len(validators)),
		ActiveValidators:     uint32(len(validators)), // Simplified
		PendingTransactions:  pendingTxs,
		NetworkHashRate:      "1.5 TH/s", // Placeholder
		Validators:           validators,
	}, nil
}

// GetBalance retrieves account balance
func (s *RelayServer) GetBalance(ctx context.Context, req *BalanceRequest) (*BalanceResponse, error) {
	balances := make(map[string]uint64)

	if req.TokenId != "" {
		// Get balance for specific token
		if token, exists := s.blockchain.TokenRegistry[req.TokenId]; exists {
			balance, err := token.BalanceOf(req.Address)
			if err != nil {
				return &BalanceResponse{
					Success: false,
					Error:   err.Error(),
				}, nil
			}
			balances[req.TokenId] = balance
		} else {
			return &BalanceResponse{
				Success: false,
				Error:   fmt.Sprintf("token %s not found", req.TokenId),
			}, nil
		}
	} else {
		// Get balances for all tokens
		for tokenId, token := range s.blockchain.TokenRegistry {
			balance, err := token.BalanceOf(req.Address)
			if err == nil && balance > 0 {
				balances[tokenId] = balance
			}
		}
	}

	return &BalanceResponse{
		Success:     true,
		Address:     req.Address,
		Balances:    balances,
		LastUpdated: time.Now().Unix(),
	}, nil
}

// ValidateTransaction validates a transaction before submission
func (s *RelayServer) ValidateTransaction(ctx context.Context, req *TransactionRequest) (*ValidationResponse, error) {
	// Basic validation
	if req.From == "" || req.To == "" {
		return &ValidationResponse{
			Valid: false,
			Error: "from and to addresses are required",
		}, nil
	}

	if req.Amount == 0 {
		return &ValidationResponse{
			Valid: false,
			Error: "amount must be greater than 0",
		}, nil
	}

	// Check token exists
	if req.TokenId != "" {
		if _, exists := s.blockchain.TokenRegistry[req.TokenId]; !exists {
			return &ValidationResponse{
				Valid: false,
				Error: fmt.Sprintf("token %s not found", req.TokenId),
			}, nil
		}
	}

	// Check balance (if token specified)
	if req.TokenId != "" {
		if token, exists := s.blockchain.TokenRegistry[req.TokenId]; exists {
			balance, err := token.BalanceOf(req.From)
			if err != nil {
				return &ValidationResponse{
					Valid: false,
					Error: fmt.Sprintf("failed to check balance: %v", err),
				}, nil
			}

			if balance < req.Amount {
				return &ValidationResponse{
					Valid: false,
					Error: "insufficient balance",
				}, nil
			}
		}
	}

	// Estimate fees
	estimatedFee := uint64(1000) // Base fee
	estimatedGas := uint64(21000) // Base gas

	return &ValidationResponse{
		Valid:               true,
		EstimatedFee:        estimatedFee,
		EstimatedGas:        estimatedGas,
		SuccessProbability:  0.95, // 95% success probability
	}, nil
}

// SubscribeToEvents provides real-time event streaming
func (s *RelayServer) SubscribeToEvents(req *EventSubscription, stream RelayService_SubscribeToEventsServer) error {
	fmt.Printf("📡 New event subscription: wallet=%s, types=%v\n", req.WalletAddress, req.EventTypes)

	// Create event channel
	eventChan := make(chan *Event, 100)
	defer close(eventChan)

	// Start event generator (simplified implementation)
	go s.generateEvents(eventChan, req)

	// Stream events to client
	for {
		select {
		case event := <-eventChan:
			if err := stream.Send(event); err != nil {
				fmt.Printf("⚠️ Failed to send event: %v\n", err)
				return err
			}
		case <-stream.Context().Done():
			fmt.Println("🔇 Event subscription cancelled")
			return nil
		}
	}
}

// generateEvents generates sample events for the subscription
func (s *RelayServer) generateEvents(eventChan chan<- *Event, req *EventSubscription) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	eventCounter := 0
	for {
		select {
		case <-ticker.C:
			eventCounter++
			
			// Generate sample event
			event := &Event{
				Id:        fmt.Sprintf("event_%d", eventCounter),
				Type:      "block_created",
				Timestamp: time.Now().Unix(),
				Data: map[string]string{
					"block_height": fmt.Sprintf("%d", s.blockchain.GetLatestBlock().Header.Index),
					"validator":    "sample_validator",
					"tx_count":     "5",
				},
				BlockHeight: s.blockchain.GetLatestBlock().Header.Index,
			}

			select {
			case eventChan <- event:
				// Event sent
			default:
				// Channel full, skip event
			}
		}
	}
}
