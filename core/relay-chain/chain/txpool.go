package chain

// TxPool manages the collection of pending transactions
type TxPool struct {
    Transactions []*Transaction
}