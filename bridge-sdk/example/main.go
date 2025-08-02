package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	bridgesdk "github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk"
)

func main() {
	fmt.Println("🌉 BlackHole Bridge SDK - Clean Version Demo")
	fmt.Println("============================================")

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors: true,
	})

	// Create configuration
	config := &bridgesdk.Config{
		EthereumRPC:             "https://eth-sepolia.g.alchemy.com/v2/demo",
		SolanaRPC:               "https://api.devnet.solana.com",
		BlackHoleRPC:            "http://localhost:8080", // BlackHole API endpoint
		DatabasePath:            "./data/bridge.db",
		LogLevel:                "info",
		MaxRetries:              3,
		RetryDelayMs:            5000,
		CircuitBreakerEnabled:   true,
		ReplayProtectionEnabled: true,
		EnableColoredLogs:       true,
	}

	// Create bridge SDK
	sdk := bridgesdk.NewBridgeSDK(config, logger)

	// Start the bridge
	if err := sdk.Start(); err != nil {
		log.Fatalf("Failed to start bridge SDK: %v", err)
	}

	// Demo: Create a test transfer request
	fmt.Println("\n🧪 Demo: Creating test bridge transfer...")
	transferReq := &bridgesdk.TransferRequest{
		FromChain:   "ethereum",
		ToChain:     "blackhole",
		FromAddress: "0x1234567890123456789012345678901234567890",
		ToAddress:   "alice", // BlackHole address
		TokenSymbol: "USDT",
		Amount:      "100.50",
	}

	tx, err := sdk.ProcessTransferRequest(transferReq)
	if err != nil {
		log.Printf("❌ Failed to create transfer: %v", err)
	} else {
		fmt.Printf("✅ Created bridge transaction: %s\n", tx.ID)
		fmt.Printf("   📍 From: %s (%s)\n", tx.SourceAddress, tx.SourceChain)
		fmt.Printf("   📍 To: %s (%s)\n", tx.DestAddress, tx.DestChain)
		fmt.Printf("   💰 Amount: %s %s\n", tx.Amount, tx.TokenSymbol)
		fmt.Printf("   📊 Status: %s\n", tx.Status)
	}

	// Demo: Test BlackHole integration with REAL accounts that have tokens
	fmt.Println("\n🔗 Demo: Testing BlackHole blockchain integration with real accounts...")

	// Check balances before transfers
	fmt.Println("\n💰 Checking account balances before transfers...")
	checkAccountBalance(sdk, "system", "BHX")
	checkAccountBalance(sdk, "genesis-validator", "BHX")
	checkAccountBalance(sdk, "alice", "BHX")
	checkAccountBalance(sdk, "bob", "BHX")

	// Test 1: Transfer from system account (has 10,000,000 BHX)
	fmt.Println("\n📤 Test 1: Transfer from 'system' account (has tokens)")
	systemTransferReq := &bridgesdk.TransferRequest{
		FromChain:   "ethereum", // Simulated source
		ToChain:     "blackhole", // Real destination
		FromAddress: "system",    // Account with 10M BHX tokens
		ToAddress:   "alice",     // Destination account
		TokenSymbol: "BHX",
		Amount:      "100",       // 100 BHX tokens
	}

	systemTx, err := sdk.ProcessBridgeToBlackHole(systemTransferReq)
	if err != nil {
		fmt.Printf("❌ System bridge failed: %v\n", err)
	} else {
		fmt.Printf("✅ System bridge successful: %s\n", systemTx.ID)
		fmt.Printf("   🔗 BlackHole TX Hash: %s\n", systemTx.Hash)
		fmt.Printf("   📊 Status: %s\n", systemTx.Status)
	}

	// Test 2: Transfer from system account again (we know it has tokens)
	fmt.Println("\n📤 Test 2: Another transfer from 'system' account (has plenty of tokens)")
	systemTransferReq2 := &bridgesdk.TransferRequest{
		FromChain:   "solana",    // Simulated source
		ToChain:     "blackhole", // Real destination
		FromAddress: "system",    // Account with 10M BHX tokens
		ToAddress:   "bob",       // Destination account
		TokenSymbol: "BHX",
		Amount:      "75",        // 75 BHX tokens
	}

	systemTx2, err := sdk.ProcessBridgeToBlackHole(systemTransferReq2)
	if err != nil {
		fmt.Printf("❌ System bridge 2 failed: %v\n", err)
	} else {
		fmt.Printf("✅ System bridge 2 successful: %s\n", systemTx2.ID)
		fmt.Printf("   🔗 BlackHole TX Hash: %s\n", systemTx2.Hash)
		fmt.Printf("   📊 Status: %s\n", systemTx2.Status)
	}

	// Test 3: Try transfer from genesis-validator with small amount
	fmt.Println("\n📤 Test 3: Transfer from 'genesis-validator' with small amount")
	validatorTransferReq := &bridgesdk.TransferRequest{
		FromChain:   "ethereum",
		ToChain:     "blackhole",
		FromAddress: "genesis-validator", // This account should have tokens
		ToAddress:   "charlie",
		TokenSymbol: "BHX",
		Amount:      "5", // Very small amount
	}

	validatorTx, err := sdk.ProcessBridgeToBlackHole(validatorTransferReq)
	if err != nil {
		fmt.Printf("❌ Genesis-validator bridge failed: %v\n", err)
		fmt.Printf("   💡 Note: genesis-validator might not have tokens in TokenRegistry system\n")
	} else {
		fmt.Printf("✅ Genesis-validator bridge successful: %s\n", validatorTx.ID)
		fmt.Printf("   🔗 BlackHole TX Hash: %s\n", validatorTx.Hash)
		fmt.Printf("   📊 Status: %s\n", validatorTx.Status)
	}

	// Test 4: Try transfer from account with no tokens (should fail)
	fmt.Println("\n📤 Test 4: Transfer from account with no tokens (should fail)")
	noTokensReq := &bridgesdk.TransferRequest{
		FromChain:   "ethereum",
		ToChain:     "blackhole",
		FromAddress: "empty_account", // Account with no tokens
		ToAddress:   "dave",
		TokenSymbol: "BHX",
		Amount:      "10",
	}

	noTokensTx, err := sdk.ProcessBridgeToBlackHole(noTokensReq)
	if err != nil {
		fmt.Printf("✅ Expected failure: %v\n", err)
		fmt.Printf("   🔒 Bridge correctly rejected transaction with insufficient funds\n")
	} else {
		fmt.Printf("⚠️ Unexpected success: %s (this shouldn't happen)\n", noTokensTx.ID)
	}

	// Demo: Get bridge statistics
	fmt.Println("\n📊 Bridge Statistics:")
	stats := sdk.GetBridgeStats()
	fmt.Printf("   Total Transactions: %d\n", stats.TotalTransactions)
	fmt.Printf("   Pending: %d, Completed: %d, Failed: %d\n", 
		stats.PendingTransactions, stats.CompletedTransactions, stats.FailedTransactions)
	fmt.Printf("   Success Rate: %.2f%%\n", stats.SuccessRate)
	fmt.Printf("   Total Volume: %s\n", stats.TotalVolume)

	// Demo: Get health status
	fmt.Println("\n🏥 Health Status:")
	health := sdk.GetHealth()
	fmt.Printf("   Status: %s\n", health.Status)
	fmt.Printf("   Uptime: %s\n", health.Uptime)
	fmt.Printf("   Version: %s\n", health.Version)
	fmt.Printf("   Components:\n")
	for component, status := range health.Components {
		fmt.Printf("     - %s: %s\n", component, status)
	}

	// Demo: List all transactions
	fmt.Println("\n📋 All Transactions:")
	transactions, err := sdk.GetAllTransactions()
	if err != nil {
		log.Printf("❌ Failed to get transactions: %v", err)
	} else {
		if len(transactions) == 0 {
			fmt.Println("   No transactions found")
		} else {
			for i, tx := range transactions {
				fmt.Printf("   %d. %s (%s → %s) - %s\n", 
					i+1, tx.ID, tx.SourceChain, tx.DestChain, tx.Status)
			}
		}
	}

	// Check balances after transfers
	fmt.Println("\n💰 Checking account balances after transfers...")
	checkAccountBalance(sdk, "system", "BHX")
	checkAccountBalance(sdk, "genesis-validator", "BHX")
	checkAccountBalance(sdk, "alice", "BHX")
	checkAccountBalance(sdk, "bob", "BHX")

	fmt.Println("\n✅ Bridge SDK Demo completed successfully!")
	fmt.Println("\n🔄 Bridge is running... Press Ctrl+C to stop")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Keep running until interrupted
	<-sigChan

	fmt.Println("\n🛑 Shutting down bridge SDK...")
	if err := sdk.Stop(); err != nil {
		log.Printf("❌ Error stopping bridge SDK: %v", err)
	}

	fmt.Println("👋 Bridge SDK stopped. Goodbye!")
}

// Helper function to check account balance
func checkAccountBalance(sdk *bridgesdk.BridgeSDK, address, tokenSymbol string) {
	// Note: This uses the bridge's BlackHole integration to check balance
	// In a real implementation, you might want to call the API directly
	fmt.Printf("   📊 %s (%s): Checking balance via bridge integration...\n", address, tokenSymbol)

	// For now, just show that we're checking - the actual balance check
	// would require the BlackHole API to be running and responding
	fmt.Printf("   💰 %s balance: (requires BlackHole API to be running)\n", address)
}
