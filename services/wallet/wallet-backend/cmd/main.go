package main

import (
	"fmt"
	"log"

	wallet_common "github.com/Shivam-Patel-G/blackhole-blockchain/wallet-backend/wallet_common"
)

func main() {
	const (
		password   = "strongpassword123"
		walletPath = "test_wallet.json"
	)

	// Step 1: Create a new wallet
	fmt.Println("🔐 Creating a new wallet...")
	wallet, err := wallet_common.NewWallet(password)
	if err != nil {
		log.Fatalf("❌ Failed to create wallet: %v", err)
	}
	fmt.Printf("✅ Wallet created!\nAddress: %s\nMnemonic: %s\n\n", wallet.Address, wallet.Mnemonic)

	// Step 2: Save wallet to disk
	fmt.Println("💾 Saving wallet to file...")
	if err := wallet.Save(walletPath); err != nil {
		log.Fatalf("❌ Failed to save wallet: %v", err)
	}
	fmt.Println("✅ Wallet saved.")

	// Step 3: Load wallet from file
	fmt.Println("📂 Loading wallet from file...")
	loadedWallet, err := wallet_common.Load(walletPath, password)
	if err != nil {
		log.Fatalf("❌ Failed to load wallet: %v", err)
	}
	fmt.Printf("✅ Wallet loaded!\nAddress: %s\n\n", loadedWallet.Address)

	// Step 4: Create and sign a transaction
	fmt.Println("✍️ Creating and signing transaction...")
	tx, err := wallet_common.CreateAndSignTransaction(wallet.Mnemonic, password, "receiver_address_123", "100", "transfer")
	if err != nil {
		log.Fatalf("❌ Failed to create/sign transaction: %v", err)
	}
	fmt.Printf("✅ Transaction signed!\nSignature: %x\n\n", tx.Signature)

	// Step 5: Verify the transaction
	fmt.Println("🔍 Verifying transaction signature...")
	valid, err := tx.Verify()
	if err != nil {
		log.Fatalf("❌ Failed to verify transaction: %v", err)
	}
	if valid {
		fmt.Println("✅ Transaction signature is valid!")
	} else {
		fmt.Println("❌ Transaction signature is INVALID!")
	}

	// Step 6: Restore wallet from mnemonic
	fmt.Println("\n🔁 Restoring wallet from mnemonic...")
	restoredWallet, err := wallet_common.RestoreWallet(wallet.Mnemonic, password)
	if err != nil {
		log.Fatalf("❌ Failed to restore wallet: %v", err)
	}
	if restoredWallet.Address == wallet.Address {
		fmt.Printf("✅ Restored wallet matches original address: %s\n", restoredWallet.Address)
	} else {
		fmt.Println("❌ Restored wallet address does not match original.")
	}

}
