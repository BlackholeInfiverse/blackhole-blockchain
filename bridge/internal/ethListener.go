package internal

import (
    "context"
    "log"
      "math/big"
    "github.com/ethereum/go-ethereum/rpc"
    "encoding/json"
    // "strconv"
    "strings"
)

type EthTransaction struct {
    Hash  string `json:"hash"`
    Value string `json:"value"` // Value in hex string (wei)
    // ...other fields...
}

type EthListener struct {
    client *rpc.Client
    relay  *BridgeRelay
}

func NewEthListener(relay *BridgeRelay) (*EthListener, error) {
client, err := rpc.Dial("wss://mainnet.infura.io/ws/v3/688f2501b7114913a6b23a029bd43c9d")   
 if err != nil {
        return nil, err
    }
    return &EthListener{client: client, relay: relay}, nil
}

func (el *EthListener) Start() {
    pendingTxs := make(chan string)
    sub, err := el.client.EthSubscribe(context.Background(), pendingTxs, "newPendingTransactions")
    if err != nil {
        log.Fatalf("Failed to subscribe to pending transactions: %v", err)
    }
    defer sub.Unsubscribe()

    for {
        select {
        case txHash := <-pendingTxs:
            el.handleTransaction(txHash)
        }
    }
}

func (el *EthListener) handleTransaction(txHash string) {
    var raw json.RawMessage
    err := el.client.Call(&raw, "eth_getTransactionByHash", txHash)
    if err != nil {
        log.Printf("Failed to get transaction: %v", err)
        return
    }

    var tx EthTransaction
    if err := json.Unmarshal(raw, &tx); err != nil {
        log.Printf("Failed to unmarshal transaction: %v", err)
        return
    }

    // Convert value from hex (wei) to float64 (ether)
    amount := 0.0
    if tx.Value != "" {
        wei := new(big.Int)
        wei.SetString(strings.Replace(tx.Value, "0x", "", 1), 16)
        ether := new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18))
        amount, _ = ether.Float64()
    }

    event := TransactionEvent{
        SourceChain: "Ethereum",
        TxHash:      tx.Hash,
        Amount:      amount,
    }

    el.relay.PushEvent(event)
    log.Printf("Captured ETH transaction: %s amount: %f", txHash, amount)
}