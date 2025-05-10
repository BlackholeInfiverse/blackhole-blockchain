package consensus

import (
	"errors"
	"log"
	"sort"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
)

type Stake struct {
	Address string // User or validator address
	Amount  uint64 // Staked TokenX amount
	Type    string // "validator" or "delegator"
	Target  string // Validator address (for delegators)
}

type Validator struct {
	Address    string  // Validator address
	TotalStake uint64  // Own stake + delegated stake
	Delegators []Stake // List of delegator stakes
	Commission float64 // Commission rate (e.g., 10%)
	Active     bool    // Active in consensus
	LastActive int64   // Last block validated (for downtime detection)
}

type Reward struct {
	Address string // Recipient address
	Amount  uint64 // Reward in TokenX
	Epoch   int64  // Epoch number
}

var (
	Validators map[string]*Validator // Address -> Validator
	Stakes     map[string]*Stake     // Address -> Stake
	Rewards    []Reward              // List of all rewards
)

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
			Commission: 0.1, // 10% commission
			Active:     true,
		}
	} else {
		validator, exists := Validators[target]
		if !exists {
			return errors.New("validator not found")
		}
		validator.Delegators = append(validator.Delegators, *stake)
		validator.TotalStake += amount
	}
	return nil
}

func SelectValidators() []*Validator {
	var validatorList []*Validator
	for _, v := range Validators {
		validatorList = append(validatorList, v)
	}
	sort.Slice(validatorList, func(i, j int) bool {
		return validatorList[i].TotalStake > validatorList[j].TotalStake
	})
	if len(validatorList) > 100 {
		return validatorList[:100]
	}
	return validatorList
}

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
	if validator.TotalStake == 0 {
		validator.Active = false
	}
	return nil
}

func DistributeRewards(epoch int64, token *token.Token) []Reward {
	totalStake := uint64(0)
	for _, v := range Validators {
		totalStake += v.TotalStake
	}
	inflationRate := 0.05
	newTokens := uint64(float64(totalStake) * inflationRate)
	log.Printf("Total Stake: %d, New Tokens: %d", totalStake, newTokens)

	var epochRewards []Reward
	for _, v := range Validators {
		validatorReward := uint64(float64(newTokens) * float64(v.TotalStake) / float64(totalStake) * (1 - v.Commission))
		log.Printf("Validator %s: TotalStake=%d, Reward=%d", v.Address, v.TotalStake, validatorReward)
		if validatorReward > 0 {
			if err := token.Mint(v.Address, validatorReward); err != nil {
				log.Printf("Mint failed for validator %s: %v", v.Address, err)
				// For debugging: Append reward even if mint fails
				reward := Reward{v.Address, validatorReward, epoch}
				epochRewards = append(epochRewards, reward)
				log.Printf("Appended reward despite mint failure for validator %s: %+v", v.Address, reward)
				continue
			}
			reward := Reward{v.Address, validatorReward, epoch}
			epochRewards = append(epochRewards, reward)
			log.Printf("Added reward for validator %s: %+v", v.Address, reward)
		}
		for _, d := range v.Delegators {
			delegatorReward := uint64(float64(newTokens) * float64(d.Amount) / float64(totalStake) * v.Commission)
			log.Printf("Delegator %s: Amount=%d, Reward=%d", d.Address, d.Amount, delegatorReward)
			if delegatorReward > 0 {
				if err := token.Mint(d.Address, delegatorReward); err != nil {
					log.Printf("Mint failed for delegator %s: %v", d.Address, err)
					// For debugging: Append reward even if mint fails
					reward := Reward{d.Address, delegatorReward, epoch}
					epochRewards = append(epochRewards, reward)
					log.Printf("Appended reward despite mint failure for delegator %s: %+v", d.Address, reward)
					continue
				}
				reward := Reward{d.Address, delegatorReward, epoch}
				epochRewards = append(epochRewards, reward)
				log.Printf("Added reward for delegator %s: %+v", d.Address, reward)
			}
		}
	}
	log.Printf("Epoch Rewards: %+v", epochRewards)
	Rewards = append(Rewards, epochRewards...)
	log.Printf("Global Rewards: %+v", Rewards)
	return epochRewards
}

func UnstakeTokens(address string, amount uint64) error {
	stake, exists := Stakes[address]
	if !exists || stake.Amount < amount {
		return errors.New("insufficient stake")
	}
	stake.Amount -= amount
	if stake.Type == "delegator" {
		validator := Validators[stake.Target]
		validator.TotalStake -= amount
	} else {
		validator := Validators[address]
		validator.TotalStake -= amount
		if validator.TotalStake == 0 {
			validator.Active = false
		}
	}
	if stake.Amount == 0 {
		delete(Stakes, address)
	}
	return nil
}

func ClaimRewards(address string) ([]Reward, error) {
	var userRewards []Reward
	for _, reward := range Rewards {
		if reward.Address == address {
			userRewards = append(userRewards, reward)
		}
	}
	log.Printf("Claiming rewards for %s: %+v", address, userRewards)
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
	log.Printf("Remaining rewards after claim: %+v", Rewards)
	return userRewards, nil
}
