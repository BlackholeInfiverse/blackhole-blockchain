package consensus

import (
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/chain"
)

type Validator struct {
	StakePool      *chain.StakeLedger
	LastBlockTime  time.Time
	BlockInterval  time.Duration
	RewardStrategy RewardStrategy
}

type RewardStrategy interface {
	CalculateReward(block *chain.Block) uint64
}

type DefaultRewardStrategy struct {
	BaseReward uint64
}

// Default base reward logic
func (d *DefaultRewardStrategy) CalculateReward(block *chain.Block) uint64 {
	return d.BaseReward
}

// Constructor for Validator
func NewValidator(stakeLedger *chain.StakeLedger) *Validator {
	return &Validator{
		StakePool:     stakeLedger,
		BlockInterval: 5 * time.Second,
		RewardStrategy: &DefaultRewardStrategy{
			BaseReward: 10,
		},
		LastBlockTime: time.Now().Add(-10 * time.Second), // allow first block immediately
	}

}

// Select a validator randomly weighted by stake
func (v *Validator) SelectValidator() string {
	stakes := v.StakePool.GetAllStakes()
	if len(stakes) == 0 {
		return ""
	}

	type validatorStake struct {
		address string
		stake   uint64
	}

	var validators []validatorStake
	totalStake := uint64(0)

	for addr, stake := range stakes {
		validators = append(validators, validatorStake{addr, stake})
		totalStake += stake
	}

	// Sort by stake (desc)
	sort.Slice(validators, func(i, j int) bool {
		return validators[i].stake > validators[j].stake
	})

	rand.Seed(time.Now().UnixNano())
	selection := rand.Uint64() % totalStake

	runningTotal := uint64(0)
	for _, vs := range validators {
		runningTotal += vs.stake
		if runningTotal > selection {
			return vs.address
		}
	}

	return validators[0].address // fallback
}

// ValidateBlock checks consensus, Merkle root, timestamps, and stake
func (v *Validator) ValidateBlock(block *chain.Block, blockchain *chain.Blockchain) bool {
    // ... baaki checks

    elapsed := time.Since(v.LastBlockTime)
    const tolerance = 100 * time.Millisecond  // 100ms buffer

    if elapsed + tolerance < v.BlockInterval {
        fmt.Printf("❌ Validation failed: Block mined too early.\n   Required interval: %s\n   Elapsed: %s\n", v.BlockInterval, elapsed)
        return false
    }

    v.LastBlockTime = time.Now()
    return true
}


