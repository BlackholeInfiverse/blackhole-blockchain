package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "Projects/TTCont/backend/core/blockchain"
    "bridge/internal"
    "html/template"
    "path/filepath"
)

type ValidationResult struct {
    Index  int    `json:"index"`
    Hash   string `json:"hash"`
    Status string `json:"status"`
    Reason string `json:"reason"`
}

var relayHandler *internal.RelayHandler

func BridgeValidationHandler(w http.ResponseWriter, r *http.Request) {
    store := internal.NewBridgeMessageStore()
    var results []ValidationResult

    for _, block := range blockchain.Blockchain {
        msg := internal.BridgeMessage{
            Index:     block.Index,
            Timestamp: block.Timestamp,
            Data:      block.Data,
            PrevHash:  block.PrevHash,
            Hash:      block.Hash,
            Nonce:     block.Nonce,
        }
        res := ValidationResult{Index: block.Index, Hash: block.Hash}
        if !store.AddIfNew(&msg) {
            res.Status = "FAIL"
            res.Reason = "Duplicate/replay"
        } else if msg.ComputeChecksum() == "" {
            res.Status = "FAIL"
            res.Reason = "Empty checksum"
        } else {
            res.Status = "PASS"
            res.Reason = ""
        }
        results = append(results, res)
    }
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(results)
}

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
    tmplPath := filepath.Join("..", "web", "templates", "index.html")
    tmpl, err := template.ParseFiles(tmplPath)
    if err != nil {
        http.Error(w, "Template error", http.StatusInternalServerError)
        return
    }

    // Get recent events and validation results
    // relayHandler := internal.NewRelayHandler() // Or use your existing instance if possible
    events := relayHandler.GetTransactions()

    // For validation, call the handler logic directly or refactor to a function
    store := internal.NewBridgeMessageStore()
    var results []ValidationResult
    for _, block := range blockchain.Blockchain {
        msg := internal.BridgeMessage{
            Index:     block.Index,
            Timestamp: block.Timestamp,
            Data:      block.Data,
            PrevHash:  block.PrevHash,
            Hash:      block.Hash,
            Nonce:     block.Nonce,
        }
        res := ValidationResult{Index: block.Index, Hash: block.Hash}
        if !store.AddIfNew(&msg) {
            res.Status = "FAIL"
            res.Reason = "Duplicate/replay"
        } else if msg.ComputeChecksum() == "" {
            res.Status = "FAIL"
            res.Reason = "Empty checksum"
        } else {
            res.Status = "PASS"
            res.Reason = ""
        }
        results = append(results, res)
    }

    data := struct {
        Events    interface{}
        Validations []ValidationResult
    }{
        Events: events,
        Validations: results,
    }

    tmpl.Execute(w, data)
}

func ValidationResultsHandler(w http.ResponseWriter, r *http.Request) {
    tmplPath := filepath.Join("..", "web", "templates", "validation.html")
    tmpl, err := template.ParseFiles(tmplPath)
    if err != nil {
        http.Error(w, "Template error", http.StatusInternalServerError)
        return
    }

    store := internal.NewBridgeMessageStore()
    var results []ValidationResult
    for _, block := range blockchain.Blockchain {
        msg := internal.BridgeMessage{
            Index:     block.Index,
            Timestamp: block.Timestamp,
            Data:      block.Data,
            PrevHash:  block.PrevHash,
            Hash:      block.Hash,
            Nonce:     block.Nonce,
        }
        res := ValidationResult{Index: block.Index, Hash: block.Hash}
        if !store.AddIfNew(&msg) {
            res.Status = "FAIL"
            res.Reason = "Duplicate/replay"
        } else if msg.ComputeChecksum() == "" {
            res.Status = "FAIL"
            res.Reason = "Empty checksum"
        } else {
            res.Status = "PASS"
            res.Reason = ""
        }
        results = append(results, res)
    }

    data := struct {
        Validations []ValidationResult
    }{
        Validations: results,
    }

    tmpl.Execute(w, data)
}

func main() {

    if len(blockchain.Blockchain) == 0 {
        genesis := blockchain.CreateGenesisBlock()
        blockchain.Blockchain = append(blockchain.Blockchain, genesis)
    }

    // Generate multiple test blocks for continuous transaction testing
    numTests := 100 // You can change this to any number of tests you want
    for i := 1; i <= numTests; i++ {
        data := fmt.Sprintf("Test Data %d", i)
        newBlock := blockchain.GenerateBlock(data)
        blockchain.Blockchain = append(blockchain.Blockchain, newBlock)
    }
    
    relayHandler = internal.NewRelayHandler()
    bridgeRelay := &internal.BridgeRelay{RelayHandler: relayHandler}

    ethListener, err := internal.NewEthListener(bridgeRelay)
    if err != nil {
        log.Fatal(err)
    }
    solanaListener := internal.NewSolanaListener(bridgeRelay)

    go ethListener.Start()
    go solanaListener.Start()

    // ...existing code...

    http.HandleFunc("/", DashboardHandler)
    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("../web/static"))))

// ...existing code...

    http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
        events := relayHandler.GetTransactions()
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(events)
    })

    http.HandleFunc("/api/bridge-validation", BridgeValidationHandler)
    http.HandleFunc("/validation", ValidationResultsHandler)

    log.Println("Starting web server on http://localhost:8083")
    if err := http.ListenAndServe(":8083", nil); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}