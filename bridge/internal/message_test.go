package internal

import (
    "Projects/TTCont/backend/core/blockchain"
    "testing"
    "fmt"
)

func blockToBridgeMessage(block blockchain.Block) *BridgeMessage {
    return &BridgeMessage{
        Index:     block.Index,
        Timestamp: block.Timestamp,
        Data:      block.Data,
        PrevHash:  block.PrevHash,
        Hash:      block.Hash,
        Nonce:     block.Nonce,
    }
}

func TestBridgeMessagesFromBlockchain(t *testing.T) {
    store := NewBridgeMessageStore()
    type result struct {
        Index int
        Hash  string
        Status string
        Reason string
    }
    var results []result

    for _, block := range blockchain.Blockchain {
        msg := blockToBridgeMessage(block)
        r := result{Index: block.Index, Hash: block.Hash}
        if !store.AddIfNew(msg) {
            r.Status = "FAIL"
            r.Reason = "Duplicate/replay"
            t.Errorf("Duplicate/replay detected for block hash %s", block.Hash)
        } else if msg.ComputeChecksum() == "" {
            r.Status = "FAIL"
            r.Reason = "Empty checksum"
            t.Errorf("Checksum should not be empty for block hash %s", block.Hash)
        } else {
            r.Status = "PASS"
            r.Reason = ""
            t.Logf("Block %d (hash: %s) passed validation.", block.Index, block.Hash)
        }
        results = append(results, r)
    }

    fmt.Println("\n--- Block Validation Results ---")
    fmt.Println("Index\tHash\t\t\t\t\t\t\tStatus\tReason")
    for _, r := range results {
        fmt.Printf("%d\t%s\t%s\t%s\n", r.Index, r.Hash, r.Status, r.Reason)
    }
}