package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Shivam-Patel-G/blackhole-blockchain/wallet-backend/internal"
)

func main() {

	walletPath := "wallet.json"

	if _, err := os.Stat(walletPath); os.IsNotExist(err) {
		// Wallet doesn't exist → create new
		wallet, err := internal.NewWallet()
		if err != nil {
			log.Fatal(err)
		}
		wallet.Save(walletPath)
		fmt.Println("New wallet created:")
		fmt.Println(wallet)
	} else {
		// Wallet exists → load existing
		wallet, err := internal.Load(walletPath)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Existing wallet loaded:")
		fmt.Println(wallet)
	}

}
