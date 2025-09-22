package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk/core"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: bridgectl stats [options]")
	}

	// Connect to bridge API
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "http://localhost:8080/stats", nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to get stats: %v", err)
	}
	defer resp.Body.Close()

	var stats map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&stats)

	// Print stats
	fmt.Println("Bridge Stats:")
	for k, v := range stats {
		fmt.Printf("  %s: %v\n", k, v)
	}
}