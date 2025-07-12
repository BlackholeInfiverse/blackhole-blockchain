package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

func main() {
	fmt.Println("🧪 Testing Blockchain Persistence")
	fmt.Println("=================================")

	// Clean up any existing test database
	os.RemoveAll("blockchaindb_9999")

	// Test 1: Create fresh blockchain
	fmt.Println("\n1️⃣ Creating FRESH blockchain...")
	
	bc1, err := chain.NewBlockchain(9999)
	if err != nil {
		log.Fatal("❌ Failed to create blockchain:", err)
	}

	// Check initial balances
	bhxToken := bc1.TokenRegistry["BHX"]
	systemBalance1, _ := bhxToken.BalanceOf("system")
	testBalance1, _ := bhxToken.BalanceOf("03e2459b73c0c6522530f6b26e834d992dfc55d170bee35d0bcdc047fe0d61c25b")
	
	fmt.Printf("✅ Fresh blockchain created\n")
	fmt.Printf("   System BHX balance: %d\n", systemBalance1)
	fmt.Printf("   Test address BHX balance: %d\n", testBalance1)
	
	// Add some custom balance
	customAddress := "my_custom_wallet_address"
	err = bhxToken.Mint(customAddress, 5000)
	if err != nil {
		log.Fatal("❌ Failed to mint custom tokens:", err)
	}
	
	customBalance1, _ := bhxToken.BalanceOf(customAddress)
	fmt.Printf("   Custom address BHX balance: %d\n", customBalance1)
	
	// Save and shutdown
	bc1.Shutdown()
	fmt.Printf("✅ Blockchain 1 shutdown and saved\n")

	// Test 2: Restart blockchain (should load existing data)
	fmt.Println("\n2️⃣ Restarting blockchain (should load existing data)...")
	
	bc2, err := chain.NewBlockchain(9999)
	if err != nil {
		log.Fatal("❌ Failed to restart blockchain:", err)
	}

	// Check if balances persisted
	bhxToken2 := bc2.TokenRegistry["BHX"]
	systemBalance2, _ := bhxToken2.BalanceOf("system")
	testBalance2, _ := bhxToken2.BalanceOf("03e2459b73c0c6522530f6b26e834d992dfc55d170bee35d0bcdc047fe0d61c25b")
	customBalance2, _ := bhxToken2.BalanceOf(customAddress)
	
	fmt.Printf("✅ Blockchain restarted\n")
	fmt.Printf("   System BHX balance: %d\n", systemBalance2)
	fmt.Printf("   Test address BHX balance: %d\n", testBalance2)
	fmt.Printf("   Custom address BHX balance: %d\n", customBalance2)

	// Test 3: Verify persistence
	fmt.Println("\n3️⃣ Verifying persistence...")
	
	success := true
	
	if systemBalance1 != systemBalance2 {
		fmt.Printf("❌ System balance mismatch: %d vs %d\n", systemBalance1, systemBalance2)
		success = false
	}
	
	if testBalance1 != testBalance2 {
		fmt.Printf("❌ Test address balance mismatch: %d vs %d\n", testBalance1, testBalance2)
		success = false
	}
	
	if customBalance1 != customBalance2 {
		fmt.Printf("❌ Custom address balance mismatch: %d vs %d\n", customBalance1, customBalance2)
		success = false
	}
	
	if success {
		fmt.Printf("✅ SUCCESS: All balances persisted correctly!\n")
		fmt.Printf("   System: %d BHX\n", systemBalance2)
		fmt.Printf("   Test: %d BHX\n", testBalance2)
		fmt.Printf("   Custom: %d BHX\n", customBalance2)
	} else {
		fmt.Printf("❌ FAILURE: Balance persistence failed!\n")
	}

	// Test 4: Add more balance and restart again
	fmt.Println("\n4️⃣ Adding more balance and restarting again...")
	
	// Add more balance
	err = bhxToken2.Mint(customAddress, 3000)
	if err != nil {
		log.Fatal("❌ Failed to mint additional tokens:", err)
	}
	
	customBalance3, _ := bhxToken2.BalanceOf(customAddress)
	fmt.Printf("   Custom address balance after mint: %d\n", customBalance3)
	
	// Save and shutdown
	bc2.Shutdown()
	fmt.Printf("✅ Blockchain 2 shutdown and saved\n")
	
	// Restart again
	bc3, err := chain.NewBlockchain(9999)
	if err != nil {
		log.Fatal("❌ Failed to restart blockchain again:", err)
	}
	
	bhxToken3 := bc3.TokenRegistry["BHX"]
	customBalance4, _ := bhxToken3.BalanceOf(customAddress)
	fmt.Printf("   Custom address balance after restart: %d\n", customBalance4)
	
	if customBalance3 == customBalance4 {
		fmt.Printf("✅ SUCCESS: Additional balance persisted correctly!\n")
	} else {
		fmt.Printf("❌ FAILURE: Additional balance not persisted! %d vs %d\n", customBalance3, customBalance4)
	}
	
	// Clean up
	bc3.Shutdown()
	
	fmt.Println("\n🎉 Blockchain Persistence Test Complete!")
	fmt.Println("========================================")
	
	// Clean up test database
	os.RemoveAll("blockchaindb_9999")
	fmt.Println("🧹 Test database cleaned up")
}
