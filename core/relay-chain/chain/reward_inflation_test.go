package chain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setupTestBlockchainWithInflation(t *testing.T) *Blockchain {
	// Create test blockchain
	blockchain, err := NewBlockchain(4001)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	return blockchain
}

func TestRewardInflationManager(t *testing.T) {
	blockchain := setupTestBlockchainWithInflation(t)
	defer blockchain.DB.Close()

	rim := blockchain.RewardInflationMgr
	assert.NotNil(t, rim)

	t.Run("Initial configuration", func(t *testing.T) {
		stats := rim.GetInflationStats()
		
		assert.Equal(t, 7.0, stats["current_inflation_rate"])
		assert.Equal(t, 67.0, stats["target_staking_ratio"])
		assert.Greater(t, stats["total_supply"].(uint64), uint64(0))
		assert.GreaterOrEqual(t, stats["total_staked"].(uint64), uint64(0))
	})

	t.Run("Block reward calculation", func(t *testing.T) {
		// Test basic block reward calculation
		blockReward := rim.CalculateBlockReward()
		assert.Greater(t, blockReward, uint64(0))
		
		// Block reward should be reasonable (not too high or too low)
		assert.LessOrEqual(t, blockReward, uint64(1000)) // Should be less than 1000 tokens per block
		assert.GreaterOrEqual(t, blockReward, uint64(1)) // Should be at least 1 token per block
	})

	t.Run("Inflation rate adjustment", func(t *testing.T) {
		// Get initial inflation rate
		initialStats := rim.GetInflationStats()
		initialRate := initialStats["current_inflation_rate"].(float64)
		
		// Force an adjustment
		rim.AdjustInflationRate()
		
		// Get new stats
		newStats := rim.GetInflationStats()
		newRate := newStats["current_inflation_rate"].(float64)
		
		// Rate should be within bounds
		assert.GreaterOrEqual(t, newRate, rim.config.MinInflationRate)
		assert.LessOrEqual(t, newRate, rim.config.MaxInflationRate)
		
		// If staking ratio is different from target, rate should adjust
		stakingRatio := newStats["current_staking_ratio"].(float64)
		if stakingRatio < rim.config.TargetStakingRatio {
			// Low staking should tend to increase inflation (but may be capped)
			assert.GreaterOrEqual(t, newRate, initialRate-0.1) // Allow small decrease due to bounds
		}
	})

	t.Run("Reward distribution", func(t *testing.T) {
		validator := "test-validator"
		rewardAmount := uint64(100)
		
		// Get initial balances
		bhxToken := blockchain.TokenRegistry["BHX"]
		initialValidatorBalance, _ := bhxToken.BalanceOf(validator)
		initialSystemBalance, _ := bhxToken.BalanceOf("system")
		initialTotalSupply := bhxToken.TotalSupply()
		
		// Distribute rewards
		err := rim.DistributeRewards(validator, rewardAmount)
		assert.NoError(t, err)
		
		// Check balances after distribution
		finalValidatorBalance, _ := bhxToken.BalanceOf(validator)
		finalSystemBalance, _ := bhxToken.BalanceOf("system")
		finalTotalSupply := bhxToken.TotalSupply()
		
		// Validator should receive their portion
		expectedValidatorReward := uint64(float64(rewardAmount) * rim.config.ValidatorRewardPercentage / 100.0)
		expectedDelegatorReward := rewardAmount - expectedValidatorReward
		
		assert.Equal(t, initialValidatorBalance+expectedValidatorReward, finalValidatorBalance)
		assert.Equal(t, initialSystemBalance+expectedDelegatorReward, finalSystemBalance)
		assert.Equal(t, initialTotalSupply+rewardAmount, finalTotalSupply)
		
		// Check that total rewards issued is tracked
		stats := rim.GetInflationStats()
		assert.GreaterOrEqual(t, stats["total_rewards_issued"].(uint64), rewardAmount)
	})

	t.Run("Configuration update", func(t *testing.T) {
		newConfig := &InflationConfig{
			BaseInflationRate:         5.0,  // Changed from 7.0
			TargetStakingRatio:       70.0,  // Changed from 67.0
			MaxInflationRate:         15.0,  // Changed from 20.0
			MinInflationRate:         1.0,   // Changed from 2.0
			AdjustmentFactor:         0.2,   // Changed from 0.1
			BlockTimeSeconds:         5.0,   // Changed from 6.0
			ValidatorRewardPercentage: 15.0, // Changed from 10.0
		}
		
		rim.UpdateConfig(newConfig)
		
		// Verify config was updated
		stats := rim.GetInflationStats()
		config := stats["config"].(*InflationConfig)
		
		assert.Equal(t, 5.0, config.BaseInflationRate)
		assert.Equal(t, 70.0, config.TargetStakingRatio)
		assert.Equal(t, 15.0, config.MaxInflationRate)
		assert.Equal(t, 1.0, config.MinInflationRate)
		assert.Equal(t, 0.2, config.AdjustmentFactor)
		assert.Equal(t, 5.0, config.BlockTimeSeconds)
		assert.Equal(t, 15.0, config.ValidatorRewardPercentage)
	})

	t.Run("Staking ratio calculation", func(t *testing.T) {
		// Add some stake to test staking ratio calculation
		blockchain.StakeLedger.SetStake("validator1", 1000)
		blockchain.StakeLedger.SetStake("validator2", 2000)
		blockchain.StakeLedger.SetStake("validator3", 1500)
		
		stats := rim.GetInflationStats()
		stakingRatio := stats["current_staking_ratio"].(float64)
		totalStaked := stats["total_staked"].(uint64)
		totalSupply := stats["total_supply"].(uint64)
		
		// Verify staking ratio calculation
		expectedRatio := (float64(totalStaked) / float64(totalSupply)) * 100.0
		assert.InDelta(t, expectedRatio, stakingRatio, 0.01) // Allow small floating point differences
		
		// Total staked should include all validators
		assert.GreaterOrEqual(t, totalStaked, uint64(4500)) // At least the stakes we set
	})

	t.Run("Inflation bounds enforcement", func(t *testing.T) {
		// Test that inflation rate stays within bounds
		
		// Set extreme config to test bounds
		extremeConfig := &InflationConfig{
			BaseInflationRate:         50.0, // Very high
			TargetStakingRatio:       10.0,  // Very low target
			MaxInflationRate:         25.0,  // Max cap
			MinInflationRate:         5.0,   // Min floor
			AdjustmentFactor:         2.0,   // Very aggressive adjustment
			BlockTimeSeconds:         6.0,
			ValidatorRewardPercentage: 10.0,
		}
		
		rim.UpdateConfig(extremeConfig)
		
		// Force multiple adjustments
		for i := 0; i < 10; i++ {
			rim.AdjustInflationRate()
			time.Sleep(1 * time.Millisecond) // Small delay to ensure time passes
		}
		
		stats := rim.GetInflationStats()
		finalRate := stats["current_inflation_rate"].(float64)
		
		// Rate should be capped at max
		assert.LessOrEqual(t, finalRate, extremeConfig.MaxInflationRate)
		assert.GreaterOrEqual(t, finalRate, extremeConfig.MinInflationRate)
	})

	t.Run("Block reward consistency", func(t *testing.T) {
		// Test that block rewards are consistent for same conditions
		reward1 := rim.CalculateBlockReward()
		reward2 := rim.CalculateBlockReward()
		
		// Should be the same if no time has passed and conditions haven't changed
		assert.Equal(t, reward1, reward2)
		
		// Test that rewards change when inflation rate changes
		oldRate := rim.currentInflationRate
		rim.currentInflationRate = oldRate * 2 // Double the rate
		
		reward3 := rim.CalculateBlockReward()
		assert.Greater(t, reward3, reward1) // Should be higher with higher inflation
		
		// Restore original rate
		rim.currentInflationRate = oldRate
	})

	t.Run("Annual inflation calculation", func(t *testing.T) {
		stats := rim.GetInflationStats()
		totalSupply := stats["total_supply"].(uint64)
		inflationRate := stats["current_inflation_rate"].(float64)
		annualInflationAmount := stats["annual_inflation_amount"].(float64)
		
		// Verify annual inflation calculation
		expectedAnnual := float64(totalSupply) * (inflationRate / 100.0)
		assert.InDelta(t, expectedAnnual, annualInflationAmount, 0.01)
	})
}

func TestRewardInflationIntegration(t *testing.T) {
	blockchain := setupTestBlockchainWithInflation(t)
	defer blockchain.DB.Close()

	t.Run("Block creation with dynamic rewards", func(t *testing.T) {
		// Get initial state
		initialHeight := len(blockchain.Blocks)
		bhxToken := blockchain.TokenRegistry["BHX"]
		initialSupply := bhxToken.TotalSupply()
		
		// Create a new block
		validator := "test-validator"
		blockchain.StakeLedger.SetStake(validator, 1000)

		block := blockchain.MineBlock(validator)
		assert.NotNil(t, block)
		
		// Block should have reward transaction
		assert.Greater(t, len(block.Transactions), 0)
		
		rewardTx := block.Transactions[0] // First transaction should be reward
		assert.Equal(t, "system", rewardTx.From)
		assert.Equal(t, validator, rewardTx.To)
		assert.Equal(t, "BHX", rewardTx.TokenID)
		assert.Greater(t, rewardTx.Amount, uint64(0))
		
		// Add the block to the chain
		success := blockchain.AddBlock(block)
		assert.True(t, success)
		
		// Verify blockchain state
		assert.Equal(t, initialHeight+1, len(blockchain.Blocks))
		
		// Verify rewards were distributed
		finalSupply := bhxToken.TotalSupply()
		assert.Greater(t, finalSupply, initialSupply)
		
		// Validator should have received rewards
		validatorBalance, _ := bhxToken.BalanceOf(validator)
		assert.Greater(t, validatorBalance, uint64(0))
	})

	t.Run("Multiple blocks with inflation adjustment", func(t *testing.T) {
		validator := "multi-block-validator"
		blockchain.StakeLedger.SetStake(validator, 2000)
		
		rewards := make([]uint64, 0)
		
		// Create multiple blocks and track reward changes
		for i := 0; i < 5; i++ {
			block := blockchain.MineBlock(validator)
			assert.NotNil(t, block)
			
			// Get reward amount from first transaction
			if len(block.Transactions) > 0 {
				rewards = append(rewards, block.Transactions[0].Amount)
			}
			
			success := blockchain.AddBlock(block)
			assert.True(t, success)
			
			// Small delay to allow inflation adjustments
			time.Sleep(1 * time.Millisecond)
		}
		
		// Verify we collected rewards
		assert.Len(t, rewards, 5)
		
		// All rewards should be positive
		for _, reward := range rewards {
			assert.Greater(t, reward, uint64(0))
		}
	})
}
