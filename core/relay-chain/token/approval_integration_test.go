package token

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// MockStakingContract simulates a staking contract that uses token approvals
type MockStakingContract struct {
	stakedBalances map[string]uint64
	mu             sync.RWMutex
}

func NewMockStakingContract() *MockStakingContract {
	return &MockStakingContract{
		stakedBalances: make(map[string]uint64),
	}
}

func (sc *MockStakingContract) StakeTokens(token *Token, user string, amount uint64) error {
	// Check if contract has allowance to transfer tokens
	allowance, err := token.Allowance(user, "staking_contract")
	if err != nil {
		return err
	}
	if allowance < amount {
		return assert.AnError
	}

	// Transfer tokens from user to staking contract
	err = token.TransferFrom(user, "staking_contract", "staking_contract", amount)
	if err != nil {
		return err
	}

	sc.mu.Lock()
	sc.stakedBalances[user] += amount
	sc.mu.Unlock()

	return nil
}

// MockDEXContract simulates a DEX contract that uses token approvals
type MockDEXContract struct {
	liquidityPools map[string]uint64
	mu             sync.RWMutex
}

func NewMockDEXContract() *MockDEXContract {
	return &MockDEXContract{
		liquidityPools: make(map[string]uint64),
	}
}

func (dex *MockDEXContract) AddLiquidity(token *Token, user string, amount uint64) error {
	// Check if contract has allowance to transfer tokens
	allowance, err := token.Allowance(user, "dex_contract")
	if err != nil {
		return err
	}
	if allowance < amount {
		return assert.AnError
	}

	// Transfer tokens from user to DEX contract
	err = token.TransferFrom(user, "dex_contract", "dex_contract", amount)
	if err != nil {
		return err
	}

	dex.mu.Lock()
	dex.liquidityPools[user] += amount
	dex.mu.Unlock()

	return nil
}

// MockOTCContract simulates an OTC contract that uses token approvals
type MockOTCContract struct {
	escrowBalances map[string]uint64
	mu             sync.RWMutex
}

func NewMockOTCContract() *MockOTCContract {
	return &MockOTCContract{
		escrowBalances: make(map[string]uint64),
	}
}

func (otc *MockOTCContract) CreateOrder(token *Token, user string, amount uint64) error {
	// Check if contract has allowance to transfer tokens
	allowance, err := token.Allowance(user, "otc_contract")
	if err != nil {
		return err
	}
	if allowance < amount {
		return assert.AnError
	}

	// Transfer tokens from user to OTC contract
	err = token.TransferFrom(user, "otc_contract", "otc_contract", amount)
	if err != nil {
		return err
	}

	otc.mu.Lock()
	otc.escrowBalances[user] += amount
	otc.mu.Unlock()

	return nil
}

// Test approval functionality for staking
func TestStakingApprovals(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 0)
	stakingContract := NewMockStakingContract()
	user := "0xUser1"

	// Mint tokens to user
	err := token.Mint(user, 1000)
	assert.NoError(t, err)

	t.Run("Successful staking with approval", func(t *testing.T) {
		// User approves staking contract to spend 500 tokens
		err := token.Approve(user, "staking_contract", 500)
		assert.NoError(t, err)

		// Verify approval
		allowance, err := token.Allowance(user, "staking_contract")
		assert.NoError(t, err)
		assert.Equal(t, uint64(500), allowance)

		// Stake 300 tokens
		err = stakingContract.StakeTokens(token, user, 300)
		assert.NoError(t, err)

		// Verify balances
		userBalance, _ := token.BalanceOf(user)
		contractBalance, _ := token.BalanceOf("staking_contract")
		assert.Equal(t, uint64(700), userBalance)
		assert.Equal(t, uint64(300), contractBalance)

		// Verify remaining allowance
		remainingAllowance, _ := token.Allowance(user, "staking_contract")
		assert.Equal(t, uint64(200), remainingAllowance)
	})

	t.Run("Staking fails without sufficient approval", func(t *testing.T) {
		// Try to stake more than approved
		err := stakingContract.StakeTokens(token, user, 300)
		assert.Error(t, err) // Should fail due to insufficient allowance
	})

	t.Run("Multiple approval updates", func(t *testing.T) {
		// Update approval to 100
		err := token.Approve(user, "staking_contract", 100)
		assert.NoError(t, err)

		// Verify updated approval
		allowance, _ := token.Allowance(user, "staking_contract")
		assert.Equal(t, uint64(100), allowance)

		// Stake 50 tokens
		err = stakingContract.StakeTokens(token, user, 50)
		assert.NoError(t, err)

		// Verify remaining allowance
		remainingAllowance, _ := token.Allowance(user, "staking_contract")
		assert.Equal(t, uint64(50), remainingAllowance)
	})
}

// Test approval functionality for DEX
func TestDEXApprovals(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 0)
	dexContract := NewMockDEXContract()
	user := "0xUser2"

	// Mint tokens to user
	err := token.Mint(user, 2000)
	assert.NoError(t, err)

	t.Run("Successful liquidity provision with approval", func(t *testing.T) {
		// User approves DEX contract to spend 1000 tokens
		err := token.Approve(user, "dex_contract", 1000)
		assert.NoError(t, err)

		// Add 800 tokens to liquidity pool
		err = dexContract.AddLiquidity(token, user, 800)
		assert.NoError(t, err)

		// Verify balances
		userBalance, _ := token.BalanceOf(user)
		contractBalance, _ := token.BalanceOf("dex_contract")
		assert.Equal(t, uint64(1200), userBalance)
		assert.Equal(t, uint64(800), contractBalance)
	})

	t.Run("DEX fails without approval", func(t *testing.T) {
		// Reset approval to 0
		err := token.Approve(user, "dex_contract", 0)
		assert.NoError(t, err)

		// Try to add liquidity without approval
		err = dexContract.AddLiquidity(token, user, 100)
		assert.Error(t, err)
	})
}

// Test approval functionality for OTC
func TestOTCApprovals(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 0)
	otcContract := NewMockOTCContract()
	user := "0xUser3"

	// Mint tokens to user
	err := token.Mint(user, 1500)
	assert.NoError(t, err)

	t.Run("Successful OTC order creation with approval", func(t *testing.T) {
		// User approves OTC contract to spend 600 tokens
		err := token.Approve(user, "otc_contract", 600)
		assert.NoError(t, err)

		// Create OTC order with 400 tokens
		err = otcContract.CreateOrder(token, user, 400)
		assert.NoError(t, err)

		// Verify balances
		userBalance, _ := token.BalanceOf(user)
		contractBalance, _ := token.BalanceOf("otc_contract")
		assert.Equal(t, uint64(1100), userBalance)
		assert.Equal(t, uint64(400), contractBalance)
	})

	t.Run("OTC order fails with insufficient approval", func(t *testing.T) {
		// Try to create order for more than remaining allowance
		err = otcContract.CreateOrder(token, user, 300)
		assert.Error(t, err) // Should fail due to insufficient allowance (200 remaining)
	})
}

// Test concurrent approvals across multiple contracts
func TestConcurrentApprovals(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 0)
	stakingContract := NewMockStakingContract()
	dexContract := NewMockDEXContract()
	otcContract := NewMockOTCContract()
	user := "0xConcurrentUser"

	// Mint tokens to user
	err := token.Mint(user, 10000)
	assert.NoError(t, err)

	t.Run("Multiple contract approvals", func(t *testing.T) {
		var wg sync.WaitGroup

		// Approve multiple contracts concurrently
		wg.Add(3)
		go func() {
			defer wg.Done()
			token.Approve(user, "staking_contract", 3000)
		}()
		go func() {
			defer wg.Done()
			token.Approve(user, "dex_contract", 3000)
		}()
		go func() {
			defer wg.Done()
			token.Approve(user, "otc_contract", 3000)
		}()

		wg.Wait()

		// Verify all approvals
		stakingAllowance, _ := token.Allowance(user, "staking_contract")
		dexAllowance, _ := token.Allowance(user, "dex_contract")
		otcAllowance, _ := token.Allowance(user, "otc_contract")

		assert.Equal(t, uint64(3000), stakingAllowance)
		assert.Equal(t, uint64(3000), dexAllowance)
		assert.Equal(t, uint64(3000), otcAllowance)
	})

	t.Run("Concurrent contract interactions", func(t *testing.T) {
		var wg sync.WaitGroup

		// Use contracts concurrently
		wg.Add(3)
		go func() {
			defer wg.Done()
			stakingContract.StakeTokens(token, user, 1000)
		}()
		go func() {
			defer wg.Done()
			dexContract.AddLiquidity(token, user, 1000)
		}()
		go func() {
			defer wg.Done()
			otcContract.CreateOrder(token, user, 1000)
		}()

		wg.Wait()

		// Verify final balances
		userBalance, _ := token.BalanceOf(user)
		stakingBalance, _ := token.BalanceOf("staking_contract")
		dexBalance, _ := token.BalanceOf("dex_contract")
		otcBalance, _ := token.BalanceOf("otc_contract")

		assert.Equal(t, uint64(7000), userBalance) // 10000 - 3000 used
		assert.Equal(t, uint64(1000), stakingBalance)
		assert.Equal(t, uint64(1000), dexBalance)
		assert.Equal(t, uint64(1000), otcBalance)
	})
}

// Test approval events
func TestApprovalEvents(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 0)
	user := "0xEventUser"

	t.Run("Approval events are emitted", func(t *testing.T) {
		// Clear existing events
		token.events = []Event{}

		// Make approval
		err := token.Approve(user, "test_contract", 500)
		assert.NoError(t, err)

		// Check events
		events := token.GetEvents()
		assert.Len(t, events, 1)
		assert.Equal(t, EventApproval, events[0].Type)
		assert.Equal(t, user, events[0].From)
		assert.Equal(t, "test_contract", events[0].To)
		assert.Equal(t, uint64(500), events[0].Amount)
		assert.NotEmpty(t, events[0].TxHash)
		assert.NotZero(t, events[0].Timestamp)
	})

	t.Run("Multiple approval events", func(t *testing.T) {
		// Clear existing events
		token.events = []Event{}

		// Make multiple approvals
		token.Approve(user, "contract1", 100)
		token.Approve(user, "contract2", 200)
		token.Approve(user, "contract3", 300)

		// Check events
		approvalEvents := token.GetEventsByType(EventApproval)
		assert.Len(t, approvalEvents, 3)

		// Verify event details
		assert.Equal(t, uint64(100), approvalEvents[0].Amount)
		assert.Equal(t, uint64(200), approvalEvents[1].Amount)
		assert.Equal(t, uint64(300), approvalEvents[2].Amount)
	})
}
