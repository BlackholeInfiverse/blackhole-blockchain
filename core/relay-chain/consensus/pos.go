package consensus

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
)

type Stake struct {
	Address string // User or validator address
	Amount  uint64 // Staked TokenX amount
	Type    string // "validator" or "delegator"
	Target  string // Validator address (for delegators)
}

type Validator struct {
	Address     string        // Validator address
	TotalStake  uint64        // Own stake + delegated stake
	Delegators  []Stake       // List of delegator stakes
	Commission  float64       // Commission rate (e.g., 10%)
	Active      bool          // Active in consensus
	LastActive  int64         // Last block validated
	StakePool   *chain.StakeLedger // Stake ledger for consensus
	BlockInterval time.Duration // Block interval
	RewardStrategy RewardStrategy // Reward calculation
}

type Reward struct {
	Address string // Recipient address
	Amount  uint64 // Reward in TokenX
	Epoch   int64  // Epoch number
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

var (
	Validators map[string]*Validator // Address -> Validator
	Stakes     map[string]*Stake     // Address -> Stake
	Rewards    []Reward              // List of all rewards
)

// NewValidator creates a validator with stake ledger and reward strategy
func NewValidator(stakeLedger *chain.StakeLedger) *Validator {
	return &Validator{
		StakePool:     stakeLedger,
		BlockInterval: 5 * time.Second,
		RewardStrategy: &DefaultRewardStrategy{BaseReward: 10},
		Active:        true,
		Commission:    0.1, // 10% commission
	}
}

// SelectValidator picks a validator weighted by stake
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
		if v, exists := Validators[addr]; exists && v.Active {
			validators = append(validators, validatorStake{addr, stake})
			totalStake += stake
		}
	}

	if len(validators) == 0 {
		return ""
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

	return validators[0].address
}

// ValidateBlock checks block validity and chain rules
func (v *Validator) ValidateBlock(block *chain.Block, blockchain *chain.Blockchain) bool {
	// Time interval check
	elapsed := time.Since(blockchain.GetLatestBlockTime())
	const tolerance = 100 * time.Millisecond
	if elapsed+tolerance < v.BlockInterval {
		fmt.Printf("❌ Validation failed: Block mined too early.\n")
		return false
	}

	// Validate block structure
	if !block.IsValid() {
		fmt.Printf("❌ Validation failed: Invalid block structure\n")
		return false
	}

	// Longest chain rule
	currentTip := blockchain.GetLatestBlock()
	if currentTip != nil && block.Header.PreviousHash == currentTip.CalculateHash() {
		Validators[block.Header.Validator].LastActive = time.Now().Unix()
		return true
	}

	// Check for longer competing chain
	competingChain := blockchain.GetChainEndingWith(block)
	if competingChain != nil && len(competingChain) > len(blockchain.Blocks) {
		if blockchain.Reorganize(competingChain) {
			Validators[block.Header.Validator].LastActive = time.Now().Unix()
			fmt.Printf("✅ Reorganized to longer chain\n")
			return true
		}
	}

	fmt.Printf("❌ Validation failed: Block doesn't extend any known chain\n")
	return false
}

// StakeTokens locks TokenX for staking
func StakeTokens(address, target string, amount uint64, stakeType string) error {
	if amount == 0 {
		return errors.New("stake amount must be positive")
	}
	if stakeType == "validator" && amount < 1000 {
		return errors.New("minimum validator stake is 1000 TokenX")
	}

	stake := &Stake{
		Address: address,
		Amount:  amount,
		Type:    stakeType,
		Target:  target,
	}
	Stakes[address] = stake

	if stakeType == "validator" {
		Validators[address] = &Validator{
			Address:    address,
			TotalStake: amount,
			Delegators: []Stake{},
			Commission: 0.1,
			Active:     true,
			StakePool:  Validators[address].StakePool, // Preserve if exists
			LastActive: time.Now().Unix(),
		}
	} else {
		validator, exists := Validators[target]
		if !exists {
			return errors.New("validator not found")
		}
		validator.Delegators = append(validator.Delegators, *stake)
		validator.TotalStake += amount
	}

	// Update stake ledger
	if Validators[address] != nil {
		Validators[address].StakePool.AddStake(address, amount)
	} else if Validators[target] != nil {
		Validators[target].StakePool.AddStake(address, amount)
	}

	return nil
}

// SelectValidators picks top validators by stake
func SelectValidators() []*Validator {
	var validatorList []*Validator
	for _, v := range Validators {
		if v.Active {
			validatorList = append(validatorList, v)
		}
	}
	sort.Slice(validatorList, func(i, j int) bool {
		return validatorList[i].TotalStake > validatorList[j].TotalStake
	})
	if len(validatorList) > 100 {
		return validatorList[:100]
	}
	return validatorList
}

// SlashValidator penalizes validators for offenses
func SlashValidator(address string, offense string) error {
	validator, exists := Validators[address]
	if !exists {
		return errors.New("validator not found")
	}
	var penalty float64
	switch offense {
	case "downtime":
		penalty = 0.01 // 1%
	case "double-signing":
		penalty = 0.05 // 5%
	default:
		return errors.New("unknown offense")
	}
	slashAmount := uint64(float64(validator.TotalStake) * penalty)
	validator.TotalStake -= slashAmount
	validator.StakePool.RemoveStake(address, slashAmount)
	if validator.TotalStake == 0 {
		validator.Active = false
	}
	return nil
}

// DistributeRewards mints TokenX rewards
func DistributeRewards(epoch int64, token *token.Token) []Reward {
	totalStake := uint64(0)
	for _, v := range Validators {
		totalStake += v.TotalStake
	}
	inflationRate := 0.05
	newTokens := uint64(float64(totalStake) * inflationRate)

	var epochRewards []Reward
	for _, v := range Validators {
		validatorReward := uint64(float64(newTokens) * float64(v.TotalStake) / float64(totalStake) * (1 - v.Commission))
		if validatorReward > 0 {
			if err := token.Mint(v.Address, validatorReward); err != nil {
				log.Printf("Mint failed for validator %s: %v", v.Address, err)
			} else {
				reward := Reward{v.Address, validatorReward, epoch}
				epochRewards = append(epochRewards, reward)
			}
		}
		for _, d := range v.Delegators {
			delegatorReward := uint64(float64(newTokens) * float64(d.Amount) / float64(totalStake) * v.Commission)
			if delegatorReward > 0 {
				if err := token.Mint(d.Address, delegatorReward); err != nil {
					log.Printf("Mint failed for delegator %s: %v", d.Address, err)
				} else {
					reward := Reward{d.Address, delegatorReward, epoch}
					epochRewards = append(epochRewards, reward)
				}
			}
		}
	}
	Rewards = append(Rewards, epochRewards...)
	return epochRewards
}

// UnstakeTokens releases staked TokenX
func UnstakeTokens(address string, amount uint64) error {
	stake, exists := Stakes[address]
	if !exists || stake.Amount < amount {
		return errors.New("insufficient stake")
	}
	stake.Amount -= amount
	if stake.Type == "delegator" {
		validator := Validators[stake.Target]
		validator.TotalStake -= amount
		validator.StakePool.RemoveStake(address, amount)
	} else {
		validator := Validators[address]
		validator.TotalStake -= amount
		validator.StakePool.RemoveStake(address, amount)
		if validator.TotalStake == 0 {
			validator.Active = false
		}
	}
	if stake.Amount == 0 {
		delete(Stakes, address)
	}
	return nil
}

// ClaimRewards retrieves user rewards
func ClaimRewards(address string) ([]Reward, error) {
	var userRewards []Reward
	for _, reward := range Rewards {
		if reward.Address == address {
			userRewards = append(userRewards, reward)
		}
	}
	if len(userRewards) == 0 {
		return nil, errors.New("no rewards available")
	}
	var remaining []Reward
	for _, reward := range Rewards {
		if reward.Address != address {
			remaining = append(remaining, reward)
		}
	}
	Rewards = remaining
	return userRewards, nil
}