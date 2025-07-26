package bridge

import (
	"testing"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
	"github.com/stretchr/testify/assert"
)

func setupTestBridgeWithReplay(t *testing.T) (*Bridge, *BridgeTransaction) {
	// Create test blockchain
	port := 5001 + (int(time.Now().UnixNano()) % 1000)
	blockchain, err := chain.NewBlockchain(port)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	// Create test token
	testToken := token.NewToken("TestToken", "TT", 18, 1000000)
	blockchain.TokenRegistry["TT"] = testToken

	// Create bridge
	bridge := NewBridge(blockchain)
	
	// Set up token mappings
	bridge.TokenMappings[ChainTypeEthereum]["TT"] = "wTT"
	bridge.TokenMappings[ChainTypePolkadot]["TT"] = "pTT"

	// Create a test bridge transaction
	bridgeTx := &BridgeTransaction{
		ID:              "test_bridge_tx_123",
		SourceChain:     ChainTypeBlackhole,
		DestChain:       ChainTypeEthereum,
		SourceAddress:   "0xSourceUser",
		DestAddress:     "0xDestUser",
		TokenSymbol:     "TT",
		Amount:          1000,
		Status:          "completed",
		CreatedAt:       time.Now().Unix() - 300, // 5 minutes ago
		ConfirmedAt:     time.Now().Unix() - 240, // 4 minutes ago
		CompletedAt:     time.Now().Unix() - 180, // 3 minutes ago
		RelaySignatures: []string{"sig1", "sig2", "sig3"},
		SourceTxHash:    "0xsource123",
		DestTxHash:      "0xdest456",
	}

	// Add transaction to bridge
	bridge.Transactions[bridgeTx.ID] = bridgeTx

	// Setup user with tokens and approval
	testToken.Mint("0xSourceUser", 10000)
	testToken.Approve("0xSourceUser", "bridge_contract", 5000)

	return bridge, bridgeTx
}

func TestBridgeReplayManager(t *testing.T) {
	bridge, bridgeTx := setupTestBridgeWithReplay(t)
	defer bridge.Blockchain.DB.Close()

	replayMgr := bridge.ReplayManager
	assert.NotNil(t, replayMgr)

	t.Run("Dry run replay", func(t *testing.T) {
		result, err := replayMgr.ReplayBridgeTransaction(bridgeTx.ID, ReplayModeDryRun)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, ReplayModeDryRun, result.ReplayMode)
		assert.Equal(t, bridgeTx.ID, result.TransactionID)
		assert.NotNil(t, result.GasUsage)
		assert.Greater(t, result.GasUsage.TotalGas, uint64(0))
		assert.Greater(t, result.ExecutionTime, time.Duration(0))

		// Check state changes
		assert.Contains(t, result.StateChanges, "source_balance_check")
		assert.Contains(t, result.StateChanges, "approval_check")
		assert.Contains(t, result.StateChanges, "relay_signatures")
		assert.Contains(t, result.StateChanges, "token_mapping")

		// Verify balance check
		balanceCheck := result.StateChanges["source_balance_check"].(map[string]interface{})
		assert.Equal(t, "0xSourceUser", balanceCheck["address"])
		assert.Equal(t, uint64(10000), balanceCheck["balance"])
		assert.Equal(t, uint64(1000), balanceCheck["required"])
		assert.Equal(t, true, balanceCheck["sufficient"])

		// Verify approval check
		approvalCheck := result.StateChanges["approval_check"].(map[string]interface{})
		assert.Equal(t, "0xSourceUser", approvalCheck["owner"])
		assert.Equal(t, "bridge_contract", approvalCheck["spender"])
		assert.Equal(t, uint64(5000), approvalCheck["allowance"])
		assert.Equal(t, true, approvalCheck["sufficient"])
	})

	t.Run("Validation replay", func(t *testing.T) {
		result, err := replayMgr.ReplayBridgeTransaction(bridgeTx.ID, ReplayModeValidation)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, ReplayModeValidation, result.ReplayMode)
		assert.Empty(t, result.ValidationErrors)

		// Check metadata
		assert.Equal(t, "full_validation", result.Metadata["validation_type"])
		assert.Equal(t, 8, result.Metadata["total_checks"])
		assert.Equal(t, 0, result.Metadata["failed_checks"])
	})

	t.Run("Audit replay", func(t *testing.T) {
		result, err := replayMgr.ReplayBridgeTransaction(bridgeTx.ID, ReplayModeAudit)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, ReplayModeAudit, result.ReplayMode)

		// Check audit metadata
		assert.Equal(t, "comprehensive_audit", result.Metadata["audit_type"])
		assert.Contains(t, result.Metadata, "audit_findings")
		assert.Contains(t, result.Metadata, "audit_timestamp")

		// Should have both validation and dry run data
		assert.Contains(t, result.StateChanges, "source_balance_check")
		assert.NotNil(t, result.ValidationErrors)
	})

	t.Run("Execution replay", func(t *testing.T) {
		result, err := replayMgr.ReplayBridgeTransaction(bridgeTx.ID, ReplayModeExecution)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, ReplayModeExecution, result.ReplayMode)

		// Check execution metadata
		assert.Equal(t, "actual_execution", result.Metadata["execution_type"])
		assert.Contains(t, result.Metadata, "warning")
	})

	t.Run("Invalid transaction ID", func(t *testing.T) {
		result, err := replayMgr.ReplayBridgeTransaction("nonexistent", ReplayModeDryRun)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("Invalid replay mode", func(t *testing.T) {
		result, err := replayMgr.ReplayBridgeTransaction(bridgeTx.ID, ReplayMode("invalid"))
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Contains(t, result.Error, "unknown replay mode")
	})
}

func TestGasUsageTracking(t *testing.T) {
	bridge, bridgeTx := setupTestBridgeWithReplay(t)
	defer bridge.Blockchain.DB.Close()

	replayMgr := bridge.ReplayManager

	t.Run("Gas estimation accuracy", func(t *testing.T) {
		gasUsage, err := replayMgr.estimateGasUsage(bridgeTx)
		assert.NoError(t, err)
		assert.NotNil(t, gasUsage)

		// Check gas components
		assert.Greater(t, gasUsage.BaseGas, uint64(0))
		assert.Greater(t, gasUsage.TokenTransferGas, uint64(0))
		assert.Greater(t, gasUsage.BridgeContractGas, uint64(0))
		assert.Greater(t, gasUsage.RelayGas, uint64(0))
		assert.Greater(t, gasUsage.ValidationGas, uint64(0))

		// Total gas should be sum of components
		expectedTotal := gasUsage.BaseGas + gasUsage.TokenTransferGas + 
			gasUsage.BridgeContractGas + gasUsage.RelayGas + gasUsage.ValidationGas
		assert.Equal(t, expectedTotal, gasUsage.TotalGas)

		// Total cost should be gas * price
		expectedCost := gasUsage.TotalGas * gasUsage.GasPrice
		assert.Equal(t, expectedCost, gasUsage.TotalCost)

		// Check operation type and transaction hash
		assert.Equal(t, "bridge_transfer", gasUsage.OperationType)
		assert.Equal(t, bridgeTx.SourceTxHash, gasUsage.TransactionHash)
	})

	t.Run("Gas usage varies with relay signatures", func(t *testing.T) {
		// Create transaction with fewer signatures
		bridgeTxFewSigs := *bridgeTx
		bridgeTxFewSigs.RelaySignatures = []string{"sig1"}

		gasUsageFew, err := replayMgr.estimateGasUsage(&bridgeTxFewSigs)
		assert.NoError(t, err)

		// Create transaction with more signatures
		bridgeTxManySigs := *bridgeTx
		bridgeTxManySigs.RelaySignatures = []string{"sig1", "sig2", "sig3", "sig4", "sig5"}

		gasUsageMany, err := replayMgr.estimateGasUsage(&bridgeTxManySigs)
		assert.NoError(t, err)

		// More signatures should use more gas
		assert.Greater(t, gasUsageMany.RelayGas, gasUsageFew.RelayGas)
		assert.Greater(t, gasUsageMany.TotalGas, gasUsageFew.TotalGas)
	})
}

func TestReplayHistory(t *testing.T) {
	bridge, bridgeTx := setupTestBridgeWithReplay(t)
	defer bridge.Blockchain.DB.Close()

	replayMgr := bridge.ReplayManager

	t.Run("Replay history tracking", func(t *testing.T) {
		// Initially empty
		history := replayMgr.GetReplayHistory()
		assert.Empty(t, history)

		// Perform some replays
		replayMgr.ReplayBridgeTransaction(bridgeTx.ID, ReplayModeDryRun)
		replayMgr.ReplayBridgeTransaction(bridgeTx.ID, ReplayModeValidation)
		replayMgr.ReplayBridgeTransaction(bridgeTx.ID, ReplayModeAudit)

		// Check history
		history = replayMgr.GetReplayHistory()
		assert.Len(t, history, 3)

		// Verify history entries
		assert.Equal(t, ReplayModeDryRun, history[0].ReplayMode)
		assert.Equal(t, ReplayModeValidation, history[1].ReplayMode)
		assert.Equal(t, ReplayModeAudit, history[2].ReplayMode)

		// All should be for the same transaction
		for _, entry := range history {
			assert.Equal(t, bridgeTx.ID, entry.TransactionID)
		}
	})

	t.Run("Gas usage statistics", func(t *testing.T) {
		stats := replayMgr.GetGasUsageStats()
		
		assert.Equal(t, 3, stats["total_replays"])
		assert.Equal(t, 3, stats["successful_replays"])
		assert.Equal(t, 100.0, stats["success_rate"])
		assert.Greater(t, stats["average_gas"].(uint64), uint64(0))
		assert.Greater(t, stats["total_gas"].(uint64), uint64(0))
		assert.Greater(t, stats["total_cost"].(uint64), uint64(0))
		assert.Equal(t, uint64(20), stats["gas_price"])
	})
}

func TestReplayValidationFailures(t *testing.T) {
	bridge, _ := setupTestBridgeWithReplay(t)
	defer bridge.Blockchain.DB.Close()

	replayMgr := bridge.ReplayManager

	t.Run("Validation with invalid transaction", func(t *testing.T) {
		// Create invalid transaction
		invalidTx := &BridgeTransaction{
			ID:              "invalid_tx",
			SourceChain:     ChainType("INVALID"),
			DestChain:       ChainType("INVALID"),
			SourceAddress:   "",
			DestAddress:     "",
			TokenSymbol:     "",
			Amount:          0,
			RelaySignatures: []string{}, // No signatures
		}

		// Add to bridge
		bridge.Transactions[invalidTx.ID] = invalidTx

		// Replay with validation
		result, err := replayMgr.ReplayBridgeTransaction(invalidTx.ID, ReplayModeValidation)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.NotEmpty(t, result.ValidationErrors)

		// Check specific validation errors
		assert.Contains(t, result.ValidationErrors, "source address is empty")
		assert.Contains(t, result.ValidationErrors, "destination address is empty")
		assert.Contains(t, result.ValidationErrors, "token symbol is empty")
		assert.Contains(t, result.ValidationErrors, "amount is zero")
		assert.Contains(t, result.ValidationErrors, "insufficient relay signatures")
	})

	t.Run("Dry run with insufficient balance", func(t *testing.T) {
		// Create transaction with large amount
		largeTx := &BridgeTransaction{
			ID:            "large_tx",
			SourceChain:   ChainTypeBlackhole,
			DestChain:     ChainTypeEthereum,
			SourceAddress: "0xPoorUser",
			DestAddress:   "0xDestUser",
			TokenSymbol:   "TT",
			Amount:        1000000, // More than user has
			RelaySignatures: []string{"sig1", "sig2"},
		}

		// Add to bridge
		bridge.Transactions[largeTx.ID] = largeTx

		// User has no tokens
		// (0xPoorUser was never minted any tokens)

		// Replay with dry run
		result, err := replayMgr.ReplayBridgeTransaction(largeTx.ID, ReplayModeDryRun)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Contains(t, result.Error, "insufficient balance")
	})
}

func TestReplayPerformanceMetrics(t *testing.T) {
	bridge, bridgeTx := setupTestBridgeWithReplay(t)
	defer bridge.Blockchain.DB.Close()

	replayMgr := bridge.ReplayManager

	t.Run("Execution time tracking", func(t *testing.T) {
		result, err := replayMgr.ReplayBridgeTransaction(bridgeTx.ID, ReplayModeDryRun)
		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Execution time should be reasonable
		assert.Greater(t, result.ExecutionTime, time.Duration(0))
		assert.Less(t, result.ExecutionTime, 1*time.Second) // Should be fast
	})

	t.Run("Concurrent replays", func(t *testing.T) {
		// Clear history
		replayMgr.replayHistory = replayMgr.replayHistory[:0]

		// Perform concurrent replays
		done := make(chan bool, 5)
		for i := 0; i < 5; i++ {
			go func() {
				replayMgr.ReplayBridgeTransaction(bridgeTx.ID, ReplayModeDryRun)
				done <- true
			}()
		}

		// Wait for all to complete
		for i := 0; i < 5; i++ {
			<-done
		}

		// Check that all replays were recorded
		history := replayMgr.GetReplayHistory()
		assert.Len(t, history, 5)

		// All should be successful
		for _, entry := range history {
			assert.True(t, entry.Success)
		}
	})
}
