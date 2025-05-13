package consensus

import (
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

func (d *DefaultRewardStrategy) CalculateReward(block *chain.Block) uint64 {
	return d.BaseReward
}

func NewValidator(stakeLedger *chain.StakeLedger) *Validator {
	return &Validator{
		StakePool:     stakeLedger,
		BlockInterval: 5 * time.Second,
		RewardStrategy: &DefaultRewardStrategy{
			BaseReward: 10,
		},
	}
}

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

	// Sort by stake (descending)
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

	return validators[0].address // Fallback to highest staker
}

func (v *Validator) ValidateBlock(block *chain.Block, chain *chain.Blockchain) bool {
	// Check previous block hash
	if len(chain.Blocks) > 0 {
		lastBlock := chain.Blocks[len(chain.Blocks)-1]
		if block.Header.PreviousHash != lastBlock.CalculateHash() {
			return false
		}
	}

	// Check index
	if block.Header.Index != uint64(len(chain.Blocks)) {
		return false
	}

	// Check validator is in stake pool
	if v.StakePool.GetStake(block.Header.Validator) == 0 {
		return false
	}

	// Check block time
	if time.Since(v.LastBlockTime) < v.BlockInterval {
		return false
	}

	// Check transactions
	for _, tx := range block.Transactions {
		if !tx.Verify() {
			return false
		}
	}

	// Check merkle root
	if block.Header.MerkleRoot != block.CalculateMerkleRoot() {
		return false
	}

	v.LastBlockTime = time.Now()
	return true
}