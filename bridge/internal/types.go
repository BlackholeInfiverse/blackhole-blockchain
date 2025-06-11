package internal

type Transaction struct {
    Index       int     `json:"index"`
    Timestamp   int64   `json:"timestamp"`
    SourceChain string  `json:"sourceChain"`
    TxHash      string  `json:"txHash"`
    Amount      float64 `json:"amount"`
}

type TransactionEvent struct {
    SourceChain string  `json:"sourceChain"`
    TxHash      string  `json:"txHash"`
    Amount      float64 `json:"amount"`
}

// type EthTransaction struct {
//     Hash   string  `json:"hash"`
//     Amount float64 `json:"amount"`
// }

type SolanaTransaction struct {
    Signature string  `json:"signature"`
    Amount    float64 `json:"amount"`
}