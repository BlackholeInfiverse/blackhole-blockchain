package bridge

import (
	"testing"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
	"github.com/stretchr/testify/assert"
)

func setupTestBridgeWithApprovals(t *testing.T) (*Bridge, *chain.Blockchain) {
	// Create test blockchain
	blockchain, err := chain.NewBlockchain(3001)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	// Create test token
	testToken := token.NewToken("TestToken", "TT", 18, 1000000)
	blockchain.TokenRegistry["TT"] = testToken

	// Create bridge
	bridge := NewBridge(blockchain)

	// Set up token mappings for testing
	bridge.TokenMappings[ChainTypeEthereum]["TT"] = "wTT" // Wrapped TT on Ethereum
	bridge.TokenMappings[ChainTypePolkadot]["TT"] = "pTT" // Polkadot TT

	return bridge, blockchain
}

func TestBridgeApprovalSimulation(t *testing.T) {
	bridge, blockchain := setupTestBridgeWithApprovals(t)
	userAddr := "0xTestUser"
	tokenSymbol := "TT"
	amount := uint64(1000)

	// Mint tokens to user
	testToken := blockchain.TokenRegistry[tokenSymbol]
	err := testToken.Mint(userAddr, 5000)
	assert.NoError(t, err)

	t.Run("Successful approval simulation with sufficient balance", func(t *testing.T) {
		// Approve bridge contract to spend tokens
		err := testToken.Approve(userAddr, "bridge_contract", 2000)
		assert.NoError(t, err)

		// Request bridge approval
		approval, err := bridge.ApprovalManager.RequestBridgeApproval(
			userAddr, tokenSymbol, amount,
			ChainTypeBlackhole, ChainTypeEthereum,
		)

		assert.NoError(t, err)
		assert.NotNil(t, approval)
		assert.Equal(t, ApprovalSimulated, approval.Status)
		assert.NotNil(t, approval.SimulationData)
		assert.True(t, approval.SimulationData.Success)
		assert.Equal(t, uint64(5000), approval.SimulationData.TokenBalance)
		assert.Equal(t, uint64(2000), approval.SimulationData.CurrentAllowance)
		assert.Equal(t, amount, approval.SimulationData.AllowanceRequired)
		assert.Greater(t, approval.SimulationData.EstimatedGas, uint64(0))
		assert.Greater(t, approval.SimulationData.EstimatedFee, uint64(0))
		assert.NotEmpty(t, approval.SimulationData.EstimatedTime)
	})

	t.Run("Approval simulation fails with insufficient balance", func(t *testing.T) {
		// Request approval for more tokens than user has
		approval, err := bridge.ApprovalManager.RequestBridgeApproval(
			userAddr, tokenSymbol, 10000, // More than the 5000 minted
			ChainTypeBlackhole, ChainTypeEthereum,
		)

		assert.NoError(t, err)
		assert.NotNil(t, approval)
		assert.Equal(t, ApprovalRejected, approval.Status)
		assert.NotNil(t, approval.SimulationData)
		assert.False(t, approval.SimulationData.Success)
		assert.Contains(t, approval.SimulationData.Errors[0], "Insufficient balance")
	})

	t.Run("Approval simulation warns about insufficient allowance", func(t *testing.T) {
		// Reset allowance to less than required
		err := testToken.Approve(userAddr, "bridge_contract", 500)
		assert.NoError(t, err)

		// Request approval
		approval, err := bridge.ApprovalManager.RequestBridgeApproval(
			userAddr, tokenSymbol, amount,
			ChainTypeBlackhole, ChainTypeEthereum,
		)

		assert.NoError(t, err)
		assert.NotNil(t, approval)
		assert.Equal(t, ApprovalSimulated, approval.Status)
		assert.True(t, approval.SimulationData.Success)
		assert.Len(t, approval.SimulationData.Warnings, 1)
		if len(approval.SimulationData.Warnings) > 0 {
			assert.Contains(t, approval.SimulationData.Warnings[0], "Insufficient bridge allowance")
		}
		if allowanceNeeded, exists := approval.SimulationData.Metadata["allowance_needed"]; exists {
			assert.Equal(t, uint64(500), approval.SimulationData.AllowanceRequired-allowanceNeeded.(uint64))
		}
	})

	t.Run("Approval simulation fails for unsupported token", func(t *testing.T) {
		// Request approval for non-existent token
		approval, err := bridge.ApprovalManager.RequestBridgeApproval(
			userAddr, "NONEXISTENT", amount,
			ChainTypeBlackhole, ChainTypeEthereum,
		)

		assert.NoError(t, err)
		assert.NotNil(t, approval)
		assert.Equal(t, ApprovalRejected, approval.Status)
		assert.False(t, approval.SimulationData.Success)
		assert.Contains(t, approval.SimulationData.Errors[0], "Token NONEXISTENT not supported on destination chain")
	})
}

func TestBridgeApprovalWorkflow(t *testing.T) {
	bridge, blockchain := setupTestBridgeWithApprovals(t)
	userAddr := "0xApprovalUser"
	tokenSymbol := "TT"
	amount := uint64(1500)

	// Setup user with tokens and allowance
	testToken := blockchain.TokenRegistry[tokenSymbol]
	err := testToken.Mint(userAddr, 10000)
	assert.NoError(t, err)
	err = testToken.Approve(userAddr, "bridge_contract", 5000)
	assert.NoError(t, err)

	t.Run("Complete approval workflow", func(t *testing.T) {
		// Step 1: Request approval
		approval, err := bridge.ApprovalManager.RequestBridgeApproval(
			userAddr, tokenSymbol, amount,
			ChainTypeBlackhole, ChainTypeEthereum,
		)

		assert.NoError(t, err)
		assert.Equal(t, ApprovalSimulated, approval.Status)
		assert.True(t, approval.SimulationData.Success)

		// Step 2: First signature
		err = bridge.ApprovalManager.ApproveBridgeTransfer(approval.ID, "signature1")
		assert.NoError(t, err)

		// Check status (should still be simulated, need 2 sigs)
		updatedApproval, err := bridge.ApprovalManager.GetApproval(approval.ID)
		assert.NoError(t, err)
		assert.Equal(t, ApprovalSimulated, updatedApproval.Status)
		assert.Len(t, updatedApproval.CollectedSigs, 1)

		// Step 3: Second signature (should approve)
		err = bridge.ApprovalManager.ApproveBridgeTransfer(approval.ID, "signature2")
		assert.NoError(t, err)

		// Check final status
		finalApproval, err := bridge.ApprovalManager.GetApproval(approval.ID)
		assert.NoError(t, err)
		assert.Equal(t, ApprovalApproved, finalApproval.Status)
		assert.Len(t, finalApproval.CollectedSigs, 2)
		assert.NotEmpty(t, finalApproval.BridgeID)
		assert.Greater(t, finalApproval.ApprovedAt, int64(0))
	})

	t.Run("Approval fails after expiry", func(t *testing.T) {
		// Create approval with short expiry
		approval, err := bridge.ApprovalManager.RequestBridgeApproval(
			userAddr, tokenSymbol, amount,
			ChainTypeBlackhole, ChainTypeEthereum,
		)
		assert.NoError(t, err)

		// Manually set expiry to past
		approval.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()

		// Try to approve expired request
		err = bridge.ApprovalManager.ApproveBridgeTransfer(approval.ID, "signature1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "has expired")

		// Check status
		expiredApproval, err := bridge.ApprovalManager.GetApproval(approval.ID)
		assert.NoError(t, err)
		assert.Equal(t, ApprovalExpired, expiredApproval.Status)
	})
}

func TestBridgeApprovalQueries(t *testing.T) {
	bridge, blockchain := setupTestBridgeWithApprovals(t)
	user1 := "0xUser1"
	user2 := "0xUser2"
	tokenSymbol := "TT"

	// Setup users with tokens
	testToken := blockchain.TokenRegistry[tokenSymbol]
	testToken.Mint(user1, 10000)
	testToken.Mint(user2, 10000)
	testToken.Approve(user1, "bridge_contract", 5000)
	testToken.Approve(user2, "bridge_contract", 5000)

	t.Run("Get user approvals", func(t *testing.T) {
		// Create approvals for user1
		approval1, _ := bridge.ApprovalManager.RequestBridgeApproval(
			user1, tokenSymbol, 1000,
			ChainTypeBlackhole, ChainTypeEthereum,
		)
		approval2, _ := bridge.ApprovalManager.RequestBridgeApproval(
			user1, tokenSymbol, 2000,
			ChainTypeBlackhole, ChainTypePolkadot,
		)

		// Create approval for user2
		approval3, _ := bridge.ApprovalManager.RequestBridgeApproval(
			user2, tokenSymbol, 1500,
			ChainTypeBlackhole, ChainTypeEthereum,
		)

		// Get user1 approvals
		user1Approvals := bridge.ApprovalManager.GetUserApprovals(user1)
		assert.Len(t, user1Approvals, 2)

		// Verify approval IDs
		approvalIDs := make([]string, len(user1Approvals))
		for i, approval := range user1Approvals {
			approvalIDs[i] = approval.ID
		}
		assert.Contains(t, approvalIDs, approval1.ID)
		assert.Contains(t, approvalIDs, approval2.ID)
		assert.NotContains(t, approvalIDs, approval3.ID)

		// Get user2 approvals
		user2Approvals := bridge.ApprovalManager.GetUserApprovals(user2)
		assert.Len(t, user2Approvals, 1)
		assert.Equal(t, approval3.ID, user2Approvals[0].ID)
	})

	t.Run("Get specific approval", func(t *testing.T) {
		// Create approval
		originalApproval, _ := bridge.ApprovalManager.RequestBridgeApproval(
			user1, tokenSymbol, 3000,
			ChainTypeBlackhole, ChainTypeEthereum,
		)

		// Retrieve approval
		retrievedApproval, err := bridge.ApprovalManager.GetApproval(originalApproval.ID)
		assert.NoError(t, err)
		assert.Equal(t, originalApproval.ID, retrievedApproval.ID)
		assert.Equal(t, originalApproval.UserAddress, retrievedApproval.UserAddress)
		assert.Equal(t, originalApproval.Amount, retrievedApproval.Amount)

		// Try to get non-existent approval
		_, err = bridge.ApprovalManager.GetApproval("nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestBridgeApprovalCleanup(t *testing.T) {
	bridge, blockchain := setupTestBridgeWithApprovals(t)
	userAddr := "0xCleanupUser"
	tokenSymbol := "TT"

	// Setup user
	testToken := blockchain.TokenRegistry[tokenSymbol]
	testToken.Mint(userAddr, 10000)
	testToken.Approve(userAddr, "bridge_contract", 5000)

	t.Run("Cleanup expired approvals", func(t *testing.T) {
		// Create approval
		approval, _ := bridge.ApprovalManager.RequestBridgeApproval(
			userAddr, tokenSymbol, 1000,
			ChainTypeBlackhole, ChainTypeEthereum,
		)

		// Verify initial status
		assert.Equal(t, ApprovalSimulated, approval.Status)

		// Manually set expiry to past
		approval.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()

		// Run cleanup
		bridge.ApprovalManager.CleanupExpiredApprovals()

		// Check that approval is now expired
		expiredApproval, err := bridge.ApprovalManager.GetApproval(approval.ID)
		assert.NoError(t, err)
		assert.Equal(t, ApprovalExpired, expiredApproval.Status)
	})
}
