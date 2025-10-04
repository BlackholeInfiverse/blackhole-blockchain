package relayer

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
)

func setupTestRelayer(t *testing.T) (*MetaTxRelayer, *chain.Blockchain) {
	// Generate unique port for each test
	var randBytes [4]byte
	rand.Read(randBytes[:])
	port := 4000 + int(binary.LittleEndian.Uint32(randBytes[:])%1000)
	blockchain, err := chain.NewBlockchain(port)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	// Create test tokens
	bhxToken := token.NewToken("BlackHole", "BHX", 18, 1000000)
	blockchain.TokenRegistry["BHX"] = bhxToken

	config := RelayerConfig{
		MaxGasPrice:     1000000,
		MinRelayerFee:   1000,
		SubsidyTreasury: "subsidy_treasury",
		MaxQueueSize:    100,
		ProcessInterval: 1, // 1 second for testing
	}

	relayer := NewMetaTxRelayer(blockchain, config)
	
	// Fund the subsidy treasury
	bhxToken.Mint("subsidy_treasury", 1000000)
	relayer.FundSubsidy(500000)

	return relayer, blockchain
}

func TestSubmitMetaTx(t *testing.T) {
	relayer, _ := setupTestRelayer(t)

	// Test successful submission
	userAddr := "user123"
	to := "recipient456"
	data := []byte("test_data")
	value := uint64(1000)
	gasLimit := uint64(21000)
	signature := []byte("test_signature")

	metaTx, err := relayer.SubmitMetaTx(userAddr, to, data, value, gasLimit, signature)
	if err != nil {
		t.Errorf("Failed to submit meta tx: %v", err)
	}

	if metaTx.Status != MetaTxPending {
		t.Errorf("Expected status %s, got %s", MetaTxPending, metaTx.Status)
	}

	if metaTx.UserAddress != userAddr {
		t.Errorf("Expected user address %s, got %s", userAddr, metaTx.UserAddress)
	}
}

func TestProcessMetaTx(t *testing.T) {
	relayer, _ := setupTestRelayer(t)

	// Submit a meta transaction
	userAddr := "user123"
	to := "recipient456"
	
	metaTx, err := relayer.SubmitMetaTx(userAddr, to, []byte("test"), 1000, 21000, []byte("sig"))
	if err != nil {
		t.Fatalf("Failed to submit meta tx: %v", err)
	}

	// Process the transaction
	err = relayer.ProcessMetaTx(metaTx.ID)
	if err != nil {
		t.Errorf("Failed to process meta tx: %v", err)
	}

	// Verify transaction was processed
	processedTx, err := relayer.GetMetaTx(metaTx.ID)
	if err != nil {
		t.Errorf("Failed to get processed tx: %v", err)
	}

	if processedTx.Status != MetaTxProcessed {
		t.Errorf("Expected status %s, got %s", MetaTxProcessed, processedTx.Status)
	}
}

func TestInsufficientSubsidyBalance(t *testing.T) {
	relayer, _ := setupTestRelayer(t)

	// Set low subsidy balance
	relayer.SubsidyBalance = 100

	// Submit a transaction that costs more than available balance
	userAddr := "user123"
	to := "recipient456"
	
	metaTx, err := relayer.SubmitMetaTx(userAddr, to, []byte("test"), 10000, 21000, []byte("sig"))
	if err != nil {
		t.Fatalf("Failed to submit meta tx: %v", err)
	}

	// Try to process - should fail due to insufficient balance
	err = relayer.ProcessMetaTx(metaTx.ID)
	if err == nil {
		t.Error("Expected error for insufficient subsidy balance")
	}

	// Verify transaction status is failed
	failedTx, _ := relayer.GetMetaTx(metaTx.ID)
	if failedTx.Status != MetaTxFailed {
		t.Errorf("Expected status %s, got %s", MetaTxFailed, failedTx.Status)
	}
}

func TestGetPendingTxs(t *testing.T) {
	relayer, _ := setupTestRelayer(t)

	// Submit multiple transactions
	for i := 0; i < 3; i++ {
		userAddr := fmt.Sprintf("user%d", i)
		relayer.SubmitMetaTx(userAddr, "recipient", []byte("test"), 1000, 21000, []byte("sig"))
	}

	pending := relayer.GetPendingTxs()
	if len(pending) != 3 {
		t.Errorf("Expected 3 pending transactions, got %d", len(pending))
	}

	for _, tx := range pending {
		if tx.Status != MetaTxPending {
			t.Errorf("Expected pending status, got %s", tx.Status)
		}
	}
}

func TestGetUserTxs(t *testing.T) {
	relayer, _ := setupTestRelayer(t)

	userAddr := "test_user"
	
	// Submit multiple transactions for the same user
	for i := 0; i < 2; i++ {
		relayer.SubmitMetaTx(userAddr, "recipient", []byte("test"), 1000, 21000, []byte("sig"))
	}

	// Submit one transaction for different user
	relayer.SubmitMetaTx("other_user", "recipient", []byte("test"), 1000, 21000, []byte("sig"))

	userTxs := relayer.GetUserTxs(userAddr)
	if len(userTxs) != 2 {
		t.Errorf("Expected 2 user transactions, got %d", len(userTxs))
	}

	for _, tx := range userTxs {
		if tx.UserAddress != userAddr {
			t.Errorf("Expected user address %s, got %s", userAddr, tx.UserAddress)
		}
	}
}

func TestFundSubsidy(t *testing.T) {
	relayer, _ := setupTestRelayer(t)

	initialBalance := relayer.SubsidyBalance
	fundAmount := uint64(10000)

	err := relayer.FundSubsidy(fundAmount)
	if err != nil {
		t.Errorf("Failed to fund subsidy: %v", err)
	}

	expectedBalance := initialBalance + fundAmount
	if relayer.SubsidyBalance != expectedBalance {
		t.Errorf("Expected balance %d, got %d", expectedBalance, relayer.SubsidyBalance)
	}
}

func TestQueueSizeLimit(t *testing.T) {
	relayer, _ := setupTestRelayer(t)
	
	// Set small queue size
	relayer.Config.MaxQueueSize = 2

	// Submit transactions up to limit
	for i := 0; i < 2; i++ {
		_, err := relayer.SubmitMetaTx(fmt.Sprintf("user%d", i), "recipient", []byte("test"), 1000, 21000, []byte("sig"))
		if err != nil {
			t.Errorf("Failed to submit tx %d: %v", i, err)
		}
	}

	// Try to submit one more - should fail
	_, err := relayer.SubmitMetaTx("user3", "recipient", []byte("test"), 1000, 21000, []byte("sig"))
	if err == nil {
		t.Error("Expected error when queue is full")
	}
}

func TestGetStats(t *testing.T) {
	relayer, _ := setupTestRelayer(t)

	// Submit and process some transactions
	for i := 0; i < 3; i++ {
		metaTx, _ := relayer.SubmitMetaTx(fmt.Sprintf("user%d", i), "recipient", []byte("test"), 1000, 21000, []byte("sig"))
		relayer.ProcessMetaTx(metaTx.ID)
	}

	stats := relayer.GetStats()
	
	if stats.ProcessedTxs != 3 {
		t.Errorf("Expected 3 processed transactions, got %d", stats.ProcessedTxs)
	}

	if stats.TotalFeesEarned == 0 {
		t.Error("Expected non-zero total fees earned")
	}

	if stats.SubsidyBalance == 0 {
		t.Error("Expected non-zero subsidy balance")
	}
}