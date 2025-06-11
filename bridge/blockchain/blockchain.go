package internal

import (
	"fmt"
	"sync"
)

// Transaction represents a blockchain transaction with metadata.
type Transaction struct {
    Hash   string
    Amount string // or int/float64, depending on your use case
    // Add other fields as needed
}
// Blockchain represents a simple in-memory blockchain.
type Blockchain struct {
	transactions []Transaction
	mu           sync.Mutex
}


// NewBlockchain creates a new instance of Blockchain.
func NewBlockchain() *Blockchain {
	return &Blockchain{
		transactions: []Transaction{},
	}
}

// PushTransaction adds a new transaction to the blockchain.
func (bc *Blockchain) PushTransaction(tx Transaction) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.transactions = append(bc.transactions, tx)
	fmt.Printf("Transaction added: %+v\n", tx)
}

// GetTransactions returns all transactions in the blockchain.
func (bc *Blockchain) GetTransactions() []Transaction {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	return bc.transactions
}