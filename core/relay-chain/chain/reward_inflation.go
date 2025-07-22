package chain

import (
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// InflationConfig represents the inflation configuration parameters
type InflationConfig struct {
	// Base inflation rate (annual percentage)
	BaseInflationRate float64 `json:"base_inflation_rate"`
	
	// Target staking ratio (percentage of total supply that should be staked)
	TargetStakingRatio float64 `json:"target_staking_ratio"`
	
	// Maximum inflation rate cap
	MaxInflationRate float64 `json:"max_inflation_rate"`
	
	// Minimum inflation rate floor
	MinInflationRate float64 `json:"min_inflation_rate"`
	
	// Inflation adjustment factor (how quickly inflation adjusts to staking ratio)
	AdjustmentFactor float64 `json:"adjustment_factor"`
	
	// Block time in seconds (for calculating per-block rewards)
	BlockTimeSeconds float64 `json:"block_time_seconds"`
	
	// Validator reward percentage (rest goes to delegators)
	ValidatorRewardPercentage float64 `json:"validator_reward_percentage"`
}

// RewardInflationManager manages the dynamic inflation and reward system
type RewardInflationManager struct {
	config          *InflationConfig
	blockchain      *Blockchain
	mu              sync.RWMutex
	
	// Inflation tracking
	currentInflationRate float64
	lastAdjustmentTime   time.Time
	totalRewardsIssued   uint64
	
	// Performance metrics
	rewardHistory        []RewardEpoch
	stakingRatioHistory  []float64
	inflationHistory     []float64
	
	// Configuration
	epochDuration        time.Duration
	adjustmentInterval   time.Duration
}

// RewardEpoch represents reward data for a specific time period
type RewardEpoch struct {
	EpochNumber      uint64    `json:"epoch_number"`
	StartTime        time.Time `json:"start_time"`
	EndTime          time.Time `json:"end_time"`
	TotalRewards     uint64    `json:"total_rewards"`
	ValidatorRewards uint64    `json:"validator_rewards"`
	DelegatorRewards uint64    `json:"delegator_rewards"`
	InflationRate    float64   `json:"inflation_rate"`
	StakingRatio     float64   `json:"staking_ratio"`
	TotalStaked      uint64    `json:"total_staked"`
	TotalSupply      uint64    `json:"total_supply"`
	ParticipatingValidators int `json:"participating_validators"`
}

// NewRewardInflationManager creates a new reward inflation manager
func NewRewardInflationManager(blockchain *Blockchain) *RewardInflationManager {
	config := &InflationConfig{
		BaseInflationRate:         7.0,  // 7% annual inflation
		TargetStakingRatio:       67.0,  // 67% of tokens should be staked
		MaxInflationRate:         20.0,  // 20% maximum inflation
		MinInflationRate:         2.0,   // 2% minimum inflation
		AdjustmentFactor:         0.1,   // 10% adjustment factor
		BlockTimeSeconds:         6.0,   // 6 second block time
		ValidatorRewardPercentage: 10.0, // 10% to validator, 90% to delegators
	}

	return &RewardInflationManager{
		config:               config,
		blockchain:           blockchain,
		currentInflationRate: config.BaseInflationRate,
		lastAdjustmentTime:   time.Now(),
		rewardHistory:        make([]RewardEpoch, 0),
		stakingRatioHistory:  make([]float64, 0),
		inflationHistory:     make([]float64, 0),
		epochDuration:        24 * time.Hour, // 24 hour epochs
		adjustmentInterval:   1 * time.Hour,  // Adjust every hour
	}
}

// CalculateBlockReward calculates the reward for a single block based on current inflation
func (rim *RewardInflationManager) CalculateBlockReward() uint64 {
	rim.mu.RLock()
	defer rim.mu.RUnlock()

	// Get current total supply
	totalSupply := rim.getTotalSupply()
	if totalSupply == 0 {
		return rim.blockchain.BlockReward // Fallback to fixed reward
	}

	// Calculate annual reward based on inflation rate
	annualReward := float64(totalSupply) * (rim.currentInflationRate / 100.0)
	
	// Calculate blocks per year (assuming consistent block time)
	blocksPerYear := (365.25 * 24 * 3600) / rim.config.BlockTimeSeconds
	
	// Calculate per-block reward
	blockReward := annualReward / blocksPerYear
	
	// Ensure minimum reward
	if blockReward < 1.0 {
		blockReward = 1.0
	}

	return uint64(math.Round(blockReward))
}

// AdjustInflationRate adjusts the inflation rate based on current staking ratio
func (rim *RewardInflationManager) AdjustInflationRate() {
	rim.mu.Lock()
	defer rim.mu.Unlock()

	// Check if enough time has passed since last adjustment
	if time.Since(rim.lastAdjustmentTime) < rim.adjustmentInterval {
		return
	}

	// Calculate current staking ratio
	stakingRatio := rim.calculateStakingRatio()
	
	// Calculate target vs actual staking ratio difference
	stakingDifference := rim.config.TargetStakingRatio - stakingRatio
	
	// Adjust inflation rate based on staking difference
	// If staking is below target, increase inflation to incentivize staking
	// If staking is above target, decrease inflation
	adjustment := stakingDifference * rim.config.AdjustmentFactor
	newInflationRate := rim.currentInflationRate + adjustment
	
	// Apply bounds
	if newInflationRate > rim.config.MaxInflationRate {
		newInflationRate = rim.config.MaxInflationRate
	} else if newInflationRate < rim.config.MinInflationRate {
		newInflationRate = rim.config.MinInflationRate
	}

	// Update inflation rate
	oldRate := rim.currentInflationRate
	rim.currentInflationRate = newInflationRate
	rim.lastAdjustmentTime = time.Now()

	// Record history
	rim.stakingRatioHistory = append(rim.stakingRatioHistory, stakingRatio)
	rim.inflationHistory = append(rim.inflationHistory, newInflationRate)

	// Keep only last 100 entries
	if len(rim.stakingRatioHistory) > 100 {
		rim.stakingRatioHistory = rim.stakingRatioHistory[1:]
		rim.inflationHistory = rim.inflationHistory[1:]
	}

	log.Printf("🎯 Inflation rate adjusted: %.2f%% → %.2f%% (staking ratio: %.2f%%, target: %.2f%%)",
		oldRate, newInflationRate, stakingRatio, rim.config.TargetStakingRatio)
}

// DistributeRewards distributes block rewards to validator and delegators
func (rim *RewardInflationManager) DistributeRewards(validator string, blockReward uint64) error {
	rim.mu.Lock()
	defer rim.mu.Unlock()

	// Get BHX token
	bhxToken, exists := rim.blockchain.TokenRegistry["BHX"]
	if !exists {
		return fmt.Errorf("BHX token not found")
	}

	// Calculate validator and delegator portions
	validatorReward := uint64(float64(blockReward) * rim.config.ValidatorRewardPercentage / 100.0)
	delegatorReward := blockReward - validatorReward

	// Mint validator reward
	if validatorReward > 0 {
		err := bhxToken.Mint(validator, validatorReward)
		if err != nil {
			return fmt.Errorf("failed to mint validator reward: %v", err)
		}
	}

	// Distribute delegator rewards (simplified - in practice would distribute to actual delegators)
	if delegatorReward > 0 {
		// For now, mint to system for later distribution
		err := bhxToken.Mint("system", delegatorReward)
		if err != nil {
			return fmt.Errorf("failed to mint delegator reward: %v", err)
		}
	}

	// Update total rewards issued
	rim.totalRewardsIssued += blockReward

	log.Printf("💰 Rewards distributed: %d total (%d validator, %d delegators) to %s",
		blockReward, validatorReward, delegatorReward, validator)

	return nil
}

// calculateStakingRatio calculates the current staking ratio
func (rim *RewardInflationManager) calculateStakingRatio() float64 {
	totalSupply := rim.getTotalSupply()
	if totalSupply == 0 {
		return 0.0
	}

	totalStaked := rim.getTotalStaked()
	return (float64(totalStaked) / float64(totalSupply)) * 100.0
}

// getTotalSupply gets the current total supply of BHX tokens
func (rim *RewardInflationManager) getTotalSupply() uint64 {
	bhxToken, exists := rim.blockchain.TokenRegistry["BHX"]
	if !exists {
		return 0
	}
	return bhxToken.TotalSupply()
}

// getTotalStaked gets the total amount of staked tokens
func (rim *RewardInflationManager) getTotalStaked() uint64 {
	totalStaked := uint64(0)
	stakes := rim.blockchain.StakeLedger.ToMap()
	for _, stake := range stakes {
		totalStaked += stake
	}
	return totalStaked
}

// GetInflationStats returns current inflation statistics
func (rim *RewardInflationManager) GetInflationStats() map[string]interface{} {
	rim.mu.RLock()
	defer rim.mu.RUnlock()

	stakingRatio := rim.calculateStakingRatio()
	totalSupply := rim.getTotalSupply()
	totalStaked := rim.getTotalStaked()

	return map[string]interface{}{
		"current_inflation_rate":    rim.currentInflationRate,
		"target_staking_ratio":      rim.config.TargetStakingRatio,
		"current_staking_ratio":     stakingRatio,
		"total_supply":              totalSupply,
		"total_staked":              totalStaked,
		"total_rewards_issued":      rim.totalRewardsIssued,
		"last_adjustment_time":      rim.lastAdjustmentTime,
		"block_reward":              rim.CalculateBlockReward(),
		"annual_inflation_amount":   float64(totalSupply) * (rim.currentInflationRate / 100.0),
		"config":                    rim.config,
	}
}

// UpdateConfig updates the inflation configuration
func (rim *RewardInflationManager) UpdateConfig(newConfig *InflationConfig) {
	rim.mu.Lock()
	defer rim.mu.Unlock()

	rim.config = newConfig
	log.Printf("📊 Inflation config updated: base=%.2f%%, target_staking=%.2f%%, max=%.2f%%, min=%.2f%%",
		newConfig.BaseInflationRate, newConfig.TargetStakingRatio, 
		newConfig.MaxInflationRate, newConfig.MinInflationRate)
}

// StartInflationAdjustment starts the automatic inflation adjustment process
func (rim *RewardInflationManager) StartInflationAdjustment() {
	go func() {
		ticker := time.NewTicker(rim.adjustmentInterval)
		defer ticker.Stop()

		for range ticker.C {
			rim.AdjustInflationRate()
		}
	}()

	log.Printf("🚀 Inflation adjustment process started (interval: %v)", rim.adjustmentInterval)
}
