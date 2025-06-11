package internal

import (
    "log"
    "time"
)

type SolanaListener struct {
    relay *BridgeRelay
}

func NewSolanaListener(relay *BridgeRelay) *SolanaListener {
    return &SolanaListener{relay: relay}
}

func (sl *SolanaListener) Start() {
    for {
        tx := SolanaTransaction{
            Signature: "solana_tx_hash_123",
            Amount:    1.5,
        }

        event := TransactionEvent{
            SourceChain: "Solana",
            TxHash:      tx.Signature,
            Amount:      tx.Amount,
        }

        sl.relay.PushEvent(event)
        log.Printf("Captured Solana transaction: %+v\n", tx)
        time.Sleep(5 * time.Second)
    }
}