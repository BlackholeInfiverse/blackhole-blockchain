package main

import (
	"fmt"
	"testing"
	"time"

	wallet "github.com/Shivam-Patel-G/blackhole-blockchain/wallet-backend/wallet_common"
)

// MockBlockchainAPI is a mock implementation of the BlockchainAPIInterface for testing purposes.
type MockBlockchainAPI struct{}

// GetBalance is a mock method for getting the balance of a wallet.
func (m *MockBlockchainAPI) GetBalance(address string) (float64, error) {
	// Returning a mock balance
	return 100.5, nil
}

// GetTransactionHistory is a mock method for getting the transaction history of a wallet.
func (m *MockBlockchainAPI) GetTransactionHistory(address string) ([]wallet.Transaction, error) {
	// Returning a mock transaction history
	return []wallet.Transaction{
		{
			From:      address,
			To:        "receiverAddress1",
			Value:     "50.0",
			Timestamp: time.Now().Add(-time.Hour),
		},
		{
			From:      address,
			To:        "receiverAddress2",
			Value:     "50.5",
			Timestamp: time.Now().Add(-2 * time.Hour),
		},
	}, nil
}

func TestWallet_SyncWallet(t *testing.T) {
	// Create a mock BlockchainAPI
	wallet.BlockchainAPI = &MockBlockchainAPI{}

	// Create a wallet with a test address
	wallet := &wallet.Wallet{
		Address: "testAddress",
	}

	// Sync the wallet
	if err := wallet.SyncWallet(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Print outputs to show the results of the sync
	fmt.Println("Balance after sync:", wallet.Balance)

	// Check if the balance is correct
	if wallet.Balance != 100.5 {
		t.Errorf("expected balance 100.5, got %f", wallet.Balance)
	}

	// Print the transaction history
	fmt.Println("Transaction history:", wallet.TransactionHistory)

	// Check if the transaction history is correct
	if len(wallet.TransactionHistory) != 2 {
		t.Errorf("expected 2 transactions, got %d", len(wallet.TransactionHistory))
	}

	// Check if the sync timestamp is set
	if wallet.LastSyncTimestamp.IsZero() {
		t.Errorf("expected last sync timestamp to be set")
	}

	// Print the first transaction details
	tx := wallet.TransactionHistory[0]
	fmt.Println("First transaction:", tx)

	// Check the details of the first transaction
	if tx.From != "testAddress" || tx.To != "receiverAddress1" {
		t.Errorf("expected transaction From 'testAddress' and To 'receiverAddress1', got From '%s' and To '%s'", tx.From, tx.To)
	}
}
