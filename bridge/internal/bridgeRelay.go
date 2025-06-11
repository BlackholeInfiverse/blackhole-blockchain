package internal

import (
    "fmt"
    "sync"
    "time"
)

type BridgeRelay struct {
    mu           sync.Mutex
    transactions []Transaction
    nextIndex    int
    RelayHandler *RelayHandler // Added field
}

func (br *BridgeRelay) PushEvent(event TransactionEvent) {
    br.mu.Lock()
    defer br.mu.Unlock()

    // transaction := Transaction{
    //     SourceChain: event.SourceChain,
    //     TxHash:      event.TxHash,
    //     Amount:      event.Amount,
    // }

    if br.RelayHandler != nil {
        // CaptureTransaction creates the transaction with correct index/timestamp
        br.RelayHandler.CaptureTransaction(event.SourceChain, event.TxHash, event.Amount)
        transactions := br.RelayHandler.GetTransactions()
        if len(transactions) > 0 {
            br.RelayHandler.PushToBlockchain(transactions[len(transactions)-1])
        }
    } else {
        fmt.Println("RelayHandler is not set")
    }
}

// RelayHandler handles the relay of transaction events from different blockchains.
type RelayHandler struct {
    mu           sync.Mutex
    transactions []Transaction
    nextIndex    int // Added field
}

func NewRelayHandler() *RelayHandler {
    return &RelayHandler{
        transactions: make([]Transaction, 0),
        nextIndex:    1,
    }
}

func (rh *RelayHandler) CaptureTransaction(sourceChain, txHash string, amount float64) {
    rh.mu.Lock()
    defer rh.mu.Unlock()

    transaction := Transaction{
        Index:       rh.nextIndex,
        Timestamp:   time.Now().Unix(),
        SourceChain: sourceChain,
        TxHash:      txHash,
        Amount:      amount,
    }
    rh.nextIndex++
    rh.transactions = append(rh.transactions, transaction)
    fmt.Printf("Captured transaction: %+v\n", transaction)
}

func (rh *RelayHandler) GetTransactions() []Transaction {
    rh.mu.Lock()
    defer rh.mu.Unlock()

    return append([]Transaction(nil), rh.transactions...)
}

func (rh *RelayHandler) PushToBlockchain(transaction Transaction) {
    fmt.Printf("Pushing transaction to blockchain: %+v\n", transaction)
}