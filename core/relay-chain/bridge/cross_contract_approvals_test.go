package bridge

import (
	"testing"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
	"github.com/stretchr/testify/assert"
)

func setupTestCrossContractApprovals(t *testing.T) (*Bridge, *chain.Blockchain, *token.Token) {
	// Create test blockchain with unique port to avoid conflicts
	port := 3001 + (int(time.Now().UnixNano()) % 1000)
	blockchain, err := chain.NewBlockchain(port)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	// Create test token
	testToken := token.NewToken("TestToken", "TT", 18, 1000000)
	blockchain.TokenRegistry["TT"] = testToken

	// Create bridge with cross-contract approval support
	bridge := NewBridge(blockchain)
	
	// Set up token mappings for testing
	bridge.TokenMappings[ChainTypeEthereum]["TT"] = "wTT"
	bridge.TokenMappings[ChainTypePolkadot]["TT"] = "pTT"

	return bridge, blockchain, testToken
}

func TestCrossContractApprovalBasics(t *testing.T) {
	bridge, _, testToken := setupTestCrossContractApprovals(t)
	user := "0xTestUser"
	tokenSymbol := "TT"
	amount := uint64(1000)

	// Mint tokens to user
	err := testToken.Mint(user, 5000)
	assert.NoError(t, err)

	t.Run("Ensure bridge approval with no existing approval", func(t *testing.T) {
		// Check initial state - no approval
		allowance, err := testToken.Allowance(user, "bridge_contract")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), allowance)

		// Ensure bridge approval
		result, err := bridge.CrossContractApprovals.EnsureBridgeApproval(user, tokenSymbol, amount)
		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, user, result.Owner)
		assert.Equal(t, "bridge_contract", result.Spender)
		assert.Equal(t, tokenSymbol, result.TokenSymbol)
		assert.GreaterOrEqual(t, result.ApprovedAmount, amount)

		// Verify approval was actually set
		newAllowance, err := testToken.Allowance(user, "bridge_contract")
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, newAllowance, amount)
	})

	t.Run("Ensure bridge approval with sufficient existing approval", func(t *testing.T) {
		// Pre-approve more than needed
		err := testToken.Approve(user, "bridge_contract", 2000)
		assert.NoError(t, err)

		// Ensure bridge approval should use existing approval
		result, err := bridge.CrossContractApprovals.EnsureBridgeApproval(user, tokenSymbol, amount)
		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.Equal(t, uint64(2000), result.ApprovedAmount)
		assert.Equal(t, "existing_approval", result.Metadata["source"])
	})

	t.Run("Ensure bridge approval with insufficient existing approval", func(t *testing.T) {
		// Set insufficient approval
		err := testToken.Approve(user, "bridge_contract", 500)
		assert.NoError(t, err)

		// Ensure bridge approval should increase approval
		result, err := bridge.CrossContractApprovals.EnsureBridgeApproval(user, tokenSymbol, amount)
		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.GreaterOrEqual(t, result.ApprovedAmount, amount)
		assert.Equal(t, uint64(500), result.PreviousAmount)
		assert.Equal(t, "increase", result.Metadata["approval_type"])
	})
}

func TestCrossContractApprovalCaching(t *testing.T) {
	bridge, _, testToken := setupTestCrossContractApprovals(t)
	user := "0xCacheUser"
	tokenSymbol := "TT"
	amount := uint64(1000)

	// Mint tokens to user
	err := testToken.Mint(user, 5000)
	assert.NoError(t, err)

	t.Run("Approval caching works correctly", func(t *testing.T) {
		// First call should create approval and cache it
		result1, err := bridge.CrossContractApprovals.EnsureBridgeApproval(user, tokenSymbol, amount)
		assert.NoError(t, err)
		assert.True(t, result1.Success)

		// Second call should use cache
		result2, err := bridge.CrossContractApprovals.EnsureBridgeApproval(user, tokenSymbol, amount)
		assert.NoError(t, err)
		assert.True(t, result2.Success)
		assert.Equal(t, "cache", result2.Metadata["source"])
	})

	t.Run("Cache invalidation works", func(t *testing.T) {
		// Invalidate cache
		bridge.CrossContractApprovals.InvalidateApprovalCache(user, "bridge_contract", tokenSymbol)

		// Next call should not use cache
		result, err := bridge.CrossContractApprovals.EnsureBridgeApproval(user, tokenSymbol, amount)
		assert.NoError(t, err)
		assert.True(t, result.Success)
		assert.NotEqual(t, "cache", result.Metadata["source"])
	})
}

func TestBridgeTransferWithCrossContractApprovals(t *testing.T) {
	bridge, _, testToken := setupTestCrossContractApprovals(t)
	user := "0xBridgeUser"
	tokenSymbol := "TT"
	amount := uint64(1500)

	// Mint tokens to user
	err := testToken.Mint(user, 10000)
	assert.NoError(t, err)

	t.Run("Bridge transfer with automatic approval handling", func(t *testing.T) {
		// Check initial state - no approval
		allowance, err := testToken.Allowance(user, "bridge_contract")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), allowance)

		// Initiate bridge transfer - should automatically handle approvals
		bridgeTx, err := bridge.InitiateBridgeTransfer(
			ChainTypeBlackhole, ChainTypeEthereum,
			user, "0xDestUser",
			tokenSymbol, amount,
		)

		assert.NoError(t, err)
		assert.NotNil(t, bridgeTx)
		assert.Equal(t, "pending", bridgeTx.Status)

		// Verify that approval was automatically created
		finalAllowance, err := testToken.Allowance(user, "bridge_contract")
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, finalAllowance, amount)

		// Verify tokens were locked in bridge contract
		bridgeBalance, err := testToken.BalanceOf("bridge_contract")
		assert.NoError(t, err)
		assert.Equal(t, amount, bridgeBalance)

		// Verify user balance decreased
		userBalance, err := testToken.BalanceOf(user)
		assert.NoError(t, err)
		assert.Equal(t, uint64(10000-1500), userBalance)
	})

	t.Run("Bridge transfer with existing sufficient approval", func(t *testing.T) {
		// Pre-approve bridge contract
		err := testToken.Approve(user, "bridge_contract", 5000)
		assert.NoError(t, err)

		// Reset bridge balance for clean test
		bridgeBalance, _ := testToken.BalanceOf("bridge_contract")
		if bridgeBalance > 0 {
			// Transfer back to user for clean state
			testToken.Transfer("bridge_contract", user, bridgeBalance)
		}

		// Initiate another bridge transfer
		bridgeTx, err := bridge.InitiateBridgeTransfer(
			ChainTypeBlackhole, ChainTypeEthereum,
			user, "0xDestUser2",
			tokenSymbol, 1000,
		)

		assert.NoError(t, err)
		assert.NotNil(t, bridgeTx)

		// Verify approval wasn't changed (was sufficient)
		finalAllowance, err := testToken.Allowance(user, "bridge_contract")
		assert.NoError(t, err)
		assert.Equal(t, uint64(4000), finalAllowance) // 5000 - 1000 used
	})
}

func TestCrossContractApprovalValidation(t *testing.T) {
	bridge, _, testToken := setupTestCrossContractApprovals(t)
	user := "0xValidationUser"
	tokenSymbol := "TT"

	// Mint tokens to user
	err := testToken.Mint(user, 5000)
	assert.NoError(t, err)

	t.Run("Validate and fix approvals for bridge transaction", func(t *testing.T) {
		bridgeTx := &BridgeTransaction{
			ID:            "test_bridge_tx",
			SourceChain:   ChainTypeBlackhole,
			SourceAddress: user,
			TokenSymbol:   tokenSymbol,
			Amount:        1000,
		}

		// Initially no approval
		allowance, _ := testToken.Allowance(user, "bridge_contract")
		assert.Equal(t, uint64(0), allowance)

		// Validate and fix approvals
		err := bridge.CrossContractApprovals.ValidateAndFixApprovals(bridgeTx)
		assert.NoError(t, err)

		// Verify approval was created
		finalAllowance, err := testToken.Allowance(user, "bridge_contract")
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, finalAllowance, uint64(1000))
	})

	t.Run("Validation fails for non-existent token", func(t *testing.T) {
		bridgeTx := &BridgeTransaction{
			ID:            "test_bridge_tx_2",
			SourceChain:   ChainTypeBlackhole,
			SourceAddress: user,
			TokenSymbol:   "NONEXISTENT",
			Amount:        1000,
		}

		err := bridge.CrossContractApprovals.ValidateAndFixApprovals(bridgeTx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token NONEXISTENT not found")
	})

	t.Run("Validation skips external chains", func(t *testing.T) {
		bridgeTx := &BridgeTransaction{
			ID:            "test_bridge_tx_3",
			SourceChain:   ChainTypeEthereum, // External chain
			SourceAddress: user,
			TokenSymbol:   tokenSymbol,
			Amount:        1000,
		}

		// Should not error for external chains
		err := bridge.CrossContractApprovals.ValidateAndFixApprovals(bridgeTx)
		assert.NoError(t, err)
	})
}

func TestApprovalStatusQueries(t *testing.T) {
	bridge, _, testToken := setupTestCrossContractApprovals(t)
	user := "0xQueryUser"
	tokenSymbol := "TT"

	// Mint tokens and set approval
	err := testToken.Mint(user, 5000)
	assert.NoError(t, err)
	err = testToken.Approve(user, "bridge_contract", 2000)
	assert.NoError(t, err)

	t.Run("Get approval status", func(t *testing.T) {
		status, err := bridge.CrossContractApprovals.GetApprovalStatus(user, "bridge_contract", tokenSymbol)
		assert.NoError(t, err)
		assert.True(t, status.Success)
		assert.Equal(t, user, status.Owner)
		assert.Equal(t, "bridge_contract", status.Spender)
		assert.Equal(t, tokenSymbol, status.TokenSymbol)
		assert.Equal(t, uint64(2000), status.ApprovedAmount)
		assert.Equal(t, "live_query", status.Metadata["source"])
	})

	t.Run("Get approval status for non-existent token", func(t *testing.T) {
		_, err := bridge.CrossContractApprovals.GetApprovalStatus(user, "bridge_contract", "NONEXISTENT")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token NONEXISTENT not found")
	})
}

func TestApprovalBuffering(t *testing.T) {
	bridge, _, testToken := setupTestCrossContractApprovals(t)
	user := "0xBufferUser"
	tokenSymbol := "TT"
	amount := uint64(1000)

	// Mint tokens to user
	err := testToken.Mint(user, 10000)
	assert.NoError(t, err)

	t.Run("Approval includes buffer for gas optimization", func(t *testing.T) {
		// Ensure bridge approval
		result, err := bridge.CrossContractApprovals.EnsureBridgeApproval(user, tokenSymbol, amount)
		assert.NoError(t, err)
		assert.True(t, result.Success)

		// Should approve more than requested (with buffer)
		assert.Greater(t, result.ApprovedAmount, amount)
		
		// Buffer should be 20% of requested amount
		expectedBuffer := amount / 5
		expectedTotal := amount + expectedBuffer
		assert.Equal(t, expectedTotal, result.ApprovedAmount)
		assert.Equal(t, expectedBuffer, result.Metadata["buffer_added"])
	})
}
