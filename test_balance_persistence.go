package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

func main() {
	fmt.Println("🧪 Testing Balance Persistence")
	fmt.Println("==============================")

	// Clean up any existing test database
	os.RemoveAll("test_persistence_db")

	// Test 1: Create blockchain and add balance
	fmt.Println("\n1️⃣ Creating blockchain and adding balance...")
	
	bc1, err := chain.NewBlockchain("test_persistence_db")
	if err != nil {
		log.Fatal("❌ Failed to create blockchain:", err)
	}

	// Add balance to a test address
	testAddress := "test_wallet_address_123"
	testAmount := uint64(5000)
	
	// Get BHX token and mint some balance
	bhxToken, exists := bc1.TokenRegistry["BHX"]
	if !exists {
		log.Fatal("❌ BHX token not found")
	}
	
	err = bhxToken.Mint(testAddress, testAmount)
	if err != nil {
		log.Fatal("❌ Failed to mint tokens:", err)
	}
	
	// Verify balance was added
	balance, err := bhxToken.BalanceOf(testAddress)
	if err != nil {
		log.Fatal("❌ Failed to get balance:", err)
	}
	
	fmt.Printf("✅ Added balance: %s = %d BHX\n", testAddress, balance)
	
	// Register the address in account registry
	if bc1.AccountRegistry != nil {
		bc1.AccountRegistry.RegisterAccount(testAddress, "test", false, "test_user", "test_wallet")
		fmt.Printf("✅ Registered address in account registry\n")
	}
	
	// Save balances manually
	bc1.Shutdown()
	fmt.Printf("✅ Blockchain shutdown and balances saved\n")

	// Test 2: Restart blockchain and check if balance persists
	fmt.Println("\n2️⃣ Restarting blockchain and checking balance...")
	
	bc2, err := chain.NewBlockchain("test_persistence_db")
	if err != nil {
		log.Fatal("❌ Failed to restart blockchain:", err)
	}
	
	// Check if balance was loaded
	bhxToken2, exists := bc2.TokenRegistry["BHX"]
	if !exists {
		log.Fatal("❌ BHX token not found after restart")
	}
	
	loadedBalance, err := bhxToken2.BalanceOf(testAddress)
	if err != nil {
		log.Fatal("❌ Failed to get balance after restart:", err)
	}
	
	fmt.Printf("📊 Loaded balance: %s = %d BHX\n", testAddress, loadedBalance)
	
	// Test 3: Verify balance persistence
	fmt.Println("\n3️⃣ Verifying balance persistence...")
	
	if loadedBalance == testAmount {
		fmt.Printf("✅ SUCCESS: Balance persisted correctly! (%d BHX)\n", loadedBalance)
	} else {
		fmt.Printf("❌ FAILURE: Balance not persisted correctly!\n")
		fmt.Printf("   Expected: %d BHX\n", testAmount)
		fmt.Printf("   Got: %d BHX\n", loadedBalance)
	}
	
	// Test 4: Test cache system with persistent data
	fmt.Println("\n4️⃣ Testing cache system with persistent data...")
	
	if bc2.BalanceCache != nil {
		// Try to get balance through cache system
		cachedBalance, err := bc2.GetTokenBalanceWithCache("test_user", testAddress, "BHX", false)
		if err != nil {
			fmt.Printf("❌ Cache system error: %v\n", err)
		} else {
			fmt.Printf("⚡ Cache balance: %s = %d BHX\n", testAddress, cachedBalance)
			
			if cachedBalance == testAmount {
				fmt.Printf("✅ Cache system working with persistent data!\n")
			} else {
				fmt.Printf("❌ Cache system not loading persistent data correctly\n")
			}
		}
	}
	
	// Test 5: Test preload functionality
	fmt.Println("\n5️⃣ Testing preload functionality...")
	
	err = bc2.PreloadUserBalances("test_user", []string{testAddress})
	if err != nil {
		fmt.Printf("❌ Preload error: %v\n", err)
	} else {
		fmt.Printf("✅ Preload completed successfully\n")
	}
	
	// Clean up
	bc2.Shutdown()
	
	fmt.Println("\n🎉 Balance Persistence Test Complete!")
	fmt.Println("=====================================")
	
	// Clean up test database
	os.RemoveAll("test_persistence_db")
	fmt.Println("🧹 Test database cleaned up")
}
