package main

import (
	"fmt"
	"log"

	"github.com/Shivam-Patel-G/blackhole-blockchain/wallet-backend/internal"
)

func main() {
	// Simple test without CLI``
	wallet, err := internal.NewWallet()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("=== Wallet Created ===")
	fmt.Printf("Public Key: %s\n", wallet.PublicKey)

	// If you implemented Save function
	if err := wallet.Save("wallet.json"); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Wallet saved to wallet.json")
}
