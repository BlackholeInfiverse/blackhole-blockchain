package bridgesdk

import (
	"testing"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

func TestBridgeSDKInitialization(t *testing.T) {
	// Create a test blockchain
	blockchain, err := chain.NewBlockchain(3002)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.DB.Close()

	// Create SDK with default config
	sdk := NewBridgeSDK(blockchain, nil)

	// Test initialization
	err = sdk.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize SDK: %v", err)
	}

	// Verify SDK is initialized
	if !sdk.IsInitialized() {
		t.Error("SDK should be initialized")
	}

	// Test configuration
	config := sdk.GetConfig()
	if config == nil {
		t.Error("Config should not be nil")
	}

	// Test stats
	stats := sdk.GetStats()
	if stats == nil {
		t.Error("Stats should not be nil")
	}

	// Verify initial stats
	if stats["total_transactions"] != 0 {
		t.Error("Initial transaction count should be 0")
	}

	// Clean up
	sdk.Shutdown()
}

func TestListenerStartStop(t *testing.T) {
	// Create a test blockchain
	blockchain, err := chain.NewBlockchain(3003)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.DB.Close()

	// Create SDK
	sdk := NewBridgeSDK(blockchain, nil)
	err = sdk.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize SDK: %v", err)
	}

	// Test Solana listener (since it doesn't require external connection)
	err = sdk.StartSolanaListener()
	if err != nil {
		t.Fatalf("Failed to start Solana listener: %v", err)
	}

	// Wait a moment for listener to start
	time.Sleep(100 * time.Millisecond)

	// Check stats
	stats := sdk.GetStats()
	if !stats["solana_listener_running"].(bool) {
		t.Error("Solana listener should be running")
	}

	// Stop listener
	sdk.StopSolanaListener()

	// Wait a moment for listener to stop
	time.Sleep(100 * time.Millisecond)

	// Check stats again
	stats = sdk.GetStats()
	if stats["solana_listener_running"].(bool) {
		t.Error("Solana listener should be stopped")
	}

	// Clean up
	sdk.Shutdown()
}

func TestTransactionHandling(t *testing.T) {
	// Create a test blockchain
	blockchain, err := chain.NewBlockchain(3004)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.DB.Close()

	// Create SDK
	sdk := NewBridgeSDK(blockchain, nil)
	err = sdk.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize SDK: %v", err)
	}

	// Create a test transaction event
	event := &TransactionEvent{
		SourceChain: string(ChainTypeSolana),
		TxHash:      "test_tx_hash_123",
		Amount:      1.5,
		Timestamp:   time.Now().Unix(),
		FromAddress: "test_from_address",
		ToAddress:   "test_to_address",
		TokenSymbol: "SOL",
	}

	// Handle the event
	err = sdk.relay.HandleEvent(event)
	if err != nil {
		t.Fatalf("Failed to handle event: %v", err)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Check stats
	stats := sdk.GetStats()
	if stats["total_transactions"].(int) == 0 {
		t.Error("Should have at least one transaction")
	}

	// Get all transactions
	transactions := sdk.GetAllTransactions()
	if len(transactions) == 0 {
		t.Error("Should have at least one transaction")
	}

	// Verify transaction details
	tx := transactions[0]
	if tx.SourceChain != ChainTypeSolana {
		t.Errorf("Expected source chain %s, got %s", ChainTypeSolana, tx.SourceChain)
	}

	if tx.SourceTxHash != event.TxHash {
		t.Errorf("Expected source tx hash %s, got %s", event.TxHash, tx.SourceTxHash)
	}

	// Clean up
	sdk.Shutdown()
}

func TestConfigurationOptions(t *testing.T) {
	// Create a test blockchain
	blockchain, err := chain.NewBlockchain(3005)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	defer blockchain.DB.Close()

	// Create custom config (without initializing to avoid connection errors)
	config := &BridgeSDKConfig{
		Listeners: ListenerConfig{
			EthereumRPC: "wss://test-ethereum-rpc",
			SolanaRPC:   "wss://test-solana-rpc",
			PolkadotRPC: "wss://test-polkadot-rpc",
		},
		Relay: RelayConfig{
			MinConfirmations: 5,
			RelayTimeout:     60 * time.Second,
			MaxRetries:       10,
		},
	}

	// Create SDK with custom config (but don't initialize to avoid connection errors)
	sdk := NewBridgeSDK(blockchain, config)

	// Verify config without initializing
	retrievedConfig := sdk.GetConfig()
	if retrievedConfig.Relay.MinConfirmations != 5 {
		t.Errorf("Expected min confirmations 5, got %d", retrievedConfig.Relay.MinConfirmations)
	}

	if retrievedConfig.Relay.MaxRetries != 10 {
		t.Errorf("Expected max retries 10, got %d", retrievedConfig.Relay.MaxRetries)
	}

	if retrievedConfig.Listeners.EthereumRPC != "wss://test-ethereum-rpc" {
		t.Errorf("Expected Ethereum RPC wss://test-ethereum-rpc, got %s", retrievedConfig.Listeners.EthereumRPC)
	}

	// Test that SDK is not initialized
	if sdk.IsInitialized() {
		t.Error("SDK should not be initialized without calling Initialize()")
	}
}

func TestChainTypes(t *testing.T) {
	// Test chain type constants
	if ChainTypeBlackhole != "blackhole" {
		t.Errorf("Expected blackhole, got %s", ChainTypeBlackhole)
	}

	if ChainTypeEthereum != "ethereum" {
		t.Errorf("Expected ethereum, got %s", ChainTypeEthereum)
	}

	if ChainTypeSolana != "solana" {
		t.Errorf("Expected solana, got %s", ChainTypeSolana)
	}

	if ChainTypePolkadot != "polkadot" {
		t.Errorf("Expected polkadot, got %s", ChainTypePolkadot)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	
	if config == nil {
		t.Error("Default config should not be nil")
	}

	if config.Relay.MinConfirmations != 2 {
		t.Errorf("Expected default min confirmations 2, got %d", config.Relay.MinConfirmations)
	}

	if config.Relay.RelayTimeout != 30*time.Second {
		t.Errorf("Expected default relay timeout 30s, got %v", config.Relay.RelayTimeout)
	}

	if config.Listeners.EthereumRPC == "" {
		t.Error("Default Ethereum RPC should not be empty")
	}
}
