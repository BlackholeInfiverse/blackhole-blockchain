package otc

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
)

func setupTestOTC(t *testing.T) (*OTCManager, *chain.Blockchain) {
	// Generate unique port for each test to avoid conflicts
	var randBytes [4]byte
	rand.Read(randBytes[:])
	port := 3000 + int(binary.LittleEndian.Uint32(randBytes[:])%1000)
	blockchain, err := chain.NewBlockchain(port)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	// Create test tokens
	tokenA := token.NewToken("TokenA", "TA", 18, 1000000)
	tokenB := token.NewToken("TokenB", "TB", 18, 1000000)

	blockchain.TokenRegistry["TokenA"] = tokenA
	blockchain.TokenRegistry["TokenB"] = tokenB

	return NewOTCManager(blockchain), blockchain
}

func TestCreateOrder(t *testing.T) {
	otc, blockchain := setupTestOTC(t)

	// Test successful order creation
	creator := "user1"
	tokenA := blockchain.TokenRegistry["TokenA"]
	tokenA.Mint(creator, 5000) // Mint more tokens for testing

	order, err := otc.CreateOrder(creator, "TokenA", "TokenB", 2000, 3000, 24, false, nil)
	if err != nil {
		t.Errorf("Failed to create order: %v", err)
	}
	if order.Status != OrderStatusOpen {
		t.Errorf("Expected order status %s, got %s", OrderStatusOpen, order.Status)
	}

	// Test insufficient balance
	_, err = otc.CreateOrder(creator, "TokenA", "TokenB", 10000, 20000, 24, false, nil)
	if err == nil {
		t.Error("Expected error for insufficient balance")
	}

	// Test invalid token
	_, err = otc.CreateOrder(creator, "InvalidToken", "TokenB", 2000, 3000, 24, false, nil)
	if err == nil {
		t.Error("Expected error for invalid token")
	}
}

func TestMatchOrder(t *testing.T) {
	otc, blockchain := setupTestOTC(t)

	// Setup test accounts
	creator := "user1"
	counterparty := "user2"

	tokenA := blockchain.TokenRegistry["TokenA"]
	tokenB := blockchain.TokenRegistry["TokenB"]

	tokenA.Mint(creator, 5000)
	tokenB.Mint(counterparty, 7000)

	// Create order
	order, err := otc.CreateOrder(creator, "TokenA", "TokenB", 2000, 3000, 24, false, nil)
	if err != nil {
		t.Fatalf("Failed to create order: %v", err)
	}

	// Test successful match
	err = otc.MatchOrder(order.ID, counterparty)
	if err != nil {
		t.Errorf("Failed to match order: %v", err)
	}

	// Verify order status
	matchedOrder, err := otc.GetOrder(order.ID)
	if err != nil {
		t.Fatalf("Failed to get order: %v", err)
	}
	if matchedOrder.Status != OrderStatusCompleted {
		t.Errorf("Expected order status %s, got %s", OrderStatusCompleted, matchedOrder.Status)
	}

	// Test matching non-existent order
	err = otc.MatchOrder("invalid_id", counterparty)
	if err == nil {
		t.Error("Expected error for non-existent order")
	}
}

func TestMultiSigOrder(t *testing.T) {
	otc, blockchain := setupTestOTC(t)

	// Setup test accounts
	creator := "user1"
	counterparty := "user2"
	signer1 := "signer1"
	signer2 := "signer2"

	tokenA := blockchain.TokenRegistry["TokenA"]
	tokenB := blockchain.TokenRegistry["TokenB"]

	tokenA.Mint(creator, 5000)
	tokenB.Mint(counterparty, 7000)

	// Create multi-sig order
	requiredSigs := []string{signer1, signer2}
	order, err := otc.CreateOrder(creator, "TokenA", "TokenB", 2000, 3000, 24, true, requiredSigs)
	if err != nil {
		t.Fatalf("Failed to create multi-sig order: %v", err)
	}

	// Match order
	err = otc.MatchOrder(order.ID, counterparty)
	if err != nil {
		t.Errorf("Failed to match order: %v", err)
	}

	// Test signing
	err = otc.SignOrder(order.ID, signer1)
	if err != nil {
		t.Errorf("Failed to sign order: %v", err)
	}

	// Verify order still pending one signature
	order, _ = otc.GetOrder(order.ID)
	if order.Status == OrderStatusCompleted {
		t.Error("Order should not be completed with only one signature")
	}

	// Complete signing
	err = otc.SignOrder(order.ID, signer2)
	if err != nil {
		t.Errorf("Failed to sign order: %v", err)
	}

	// Verify order completed
	order, _ = otc.GetOrder(order.ID)
	if order.Status != OrderStatusCompleted {
		t.Errorf("Expected order status %s, got %s", OrderStatusCompleted, order.Status)
	}
}

func TestOrderExpiration(t *testing.T) {
	otc, blockchain := setupTestOTC(t)

	// Setup test account
	creator := "user1"
	tokenA := blockchain.TokenRegistry["TokenA"]
	tokenA.Mint(creator, 5000)

	// Create order with very short expiration (0 hours = expires immediately)
	order, err := otc.CreateOrder(creator, "TokenA", "TokenB", 2000, 3000, 0, false, nil)
	if err != nil {
		t.Fatalf("Failed to create order: %v", err)
	}

	// Wait a brief moment to ensure expiration time has passed
	time.Sleep(100 * time.Millisecond)

	// Process expired orders
	otc.ProcessExpiredOrders()

	// Verify order expired
	expiredOrder, err := otc.GetOrder(order.ID)
	if err != nil {
		t.Fatalf("Failed to get order: %v", err)
	}
	if expiredOrder.Status != OrderStatusExpired {
		t.Errorf("Expected order status %s, got %s", OrderStatusExpired, expiredOrder.Status)
	}
}

func TestGetOpenOrders(t *testing.T) {
	otc, blockchain := setupTestOTC(t)

	// Setup test account
	creator := "user1"
	tokenA := blockchain.TokenRegistry["TokenA"]
	tokenA.Mint(creator, 10000)

	// Create multiple orders
	order1, _ := otc.CreateOrder(creator, "TokenA", "TokenB", 2000, 3000, 24, false, nil)
	otc.CreateOrder(creator, "TokenA", "TokenB", 2500, 3500, 24, false, nil)
	otc.CreateOrder(creator, "TokenA", "TokenB", 3000, 4000, 24, false, nil)

	// Cancel one order
	otc.CancelOrder(order1.ID, creator)

	// Get open orders
	openOrders := otc.GetOpenOrders()
	if len(openOrders) != 2 {
		t.Errorf("Expected 2 open orders, got %d", len(openOrders))
	}
}
