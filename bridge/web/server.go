package main

import (
    "encoding/json"
    "net/http"
    "sync"
)

type TransactionEvent struct {
    SourceChain string  `json:"sourceChain"`
    TxHash      string  `json:"txHash"`
    Amount      float64 `json:"amount"`
}

var (
    events []TransactionEvent
    mu     sync.Mutex
)

func main() {
    http.HandleFunc("/events", eventsHandler)
    go startEventListeners() // Start the ETH and Solana listeners
    http.ListenAndServe(":8083", nil)
}

func eventsHandler(w http.ResponseWriter, r *http.Request) {
    mu.Lock()
    defer mu.Unlock()

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(events)
}

func startEventListeners() {
  
    // go startEthListener()
    // go startSolanaListener()
}

func addEvent(event TransactionEvent) {
    mu.Lock()
    events = append(events, event)
    mu.Unlock()
    // Optionally print to console
    go printEvent(event)
}

func printEvent(event TransactionEvent) {
    // Print the event to the console
    // This could be enhanced to log to a file or other logging system
    fmt.Printf("New Event: %+v\n", event)
}