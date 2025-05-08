package main

import (
	"fmt"
	"log"

	"github.com/Shivam-Patel-G/blackhole-blockchain/wallet-backend/internal"
)

func main() {
	// Create and save
	wallet, err := internal.NewWallet()
	if err != nil {
		log.Fatal("Failed to create wallet:", err)
	}
	fmt.Println("=== Wallet Created ===")
	fmt.Println("Address:", wallet.Address)
	fmt.Println("Public Key:", wallet.PublicKey)

	if err := wallet.Save("wallet.json"); err != nil {
		log.Fatal("Failed to save wallet:", err)
	}
	fmt.Println("Wallet saved.")

	// Load
	loaded, err := internal.Load("wallet.json")
	if err != nil {
		log.Fatal("Failed to load wallet:", err)
	}
	fmt.Println("=== Wallet Loaded ===")
	fmt.Println("Address:", loaded.Address)
	fmt.Println("Public Key:", loaded.PublicKey)
}
