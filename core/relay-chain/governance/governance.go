package governance

import (
	"fmt"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// Governance manages the blockchain governance system
type Governance struct {
	proposals   map[string]*Proposal
	validators  map[string]*Validator
	params      *GovernanceParams
	stakingPool *StakingPool
	blockchain  *chain.Blockchain
	mu          sync.RWMutex
}

// StakingPool manages validator staking
type StakingPool struct {
	TotalStake      uint64                  `json:"total_stake"`
	ValidatorStakes map[string]uint64       `json:"validator_stakes"`
	DelegatorStakes map[string][]Delegation `json:"delegator_stakes"`
	MinStake        uint64                  `json:"min_stake"`
	MaxValidators   int                     `json:"max_validators"`
	mu              sync.RWMutex
}

// Delegation represents a delegation from a delegator to a validator
type Delegation struct {
	Delegator string `json:"delegator"`
	Amount    uint64 `json:"amount"`
	Since     int64  `json:"since"`
}

// NewGovernance creates a new governance instance
func NewGovernance(blockchain *chain.Blockchain) *Governance {
	gov := &Governance{
		proposals:  make(map[string]*Proposal),
		validators: make(map[string]*Validator),
		params: &GovernanceParams{
			VotingPeriod:     7 * 24 * time.Hour, // 7 days
			MinDeposit:       10000,              // 10,000 BHX
			QuorumThreshold:  0.334,              // 33.4%
			PassThreshold:    0.5,                // 50%
			VetoThreshold:    0.334,              // 33.4%
			MaxProposalSize:  10000,              // 10KB
			ProposalCooldown: 24 * time.Hour,     // 1 day
		},
		stakingPool: &StakingPool{
			ValidatorStakes: make(map[string]uint64),
			DelegatorStakes: make(map[string][]Delegation),
			MinStake:        100000, // 100,000 BHX
			MaxValidators:   100,    // Maximum 100 validators
		},
		blockchain: blockchain,
	}

	// Start background processes
	go gov.processProposals()
	go gov.updateValidatorSet()

	return gov
}

// RegisterValidator registers a new validator
func (g *Governance) RegisterValidator(address, name string, stake uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Check minimum stake
	if stake < g.stakingPool.MinStake {
		return fmt.Errorf("stake amount %d is below minimum required %d", stake, g.stakingPool.MinStake)
	}

	// Check if validator slots are available
	if len(g.validators) >= g.stakingPool.MaxValidators {
		return fmt.Errorf("maximum validator limit reached")
	}

	// Check if validator already exists
	if _, exists := g.validators[address]; exists {
		return fmt.Errorf("validator %s already registered", address)
	}

	// Check if validator has sufficient balance
	token := g.blockchain.TokenRegistry["BHX"]
	balance, err := token.BalanceOf(address)
	if err != nil {
		return fmt.Errorf("failed to check balance: %v", err)
	}
	if balance < stake {
		return fmt.Errorf("insufficient balance: has %d, needs %d", balance, stake)
	}

	// Lock stake in governance contract
	err = token.Transfer(address, "governance_contract", stake)
	if err != nil {
		return fmt.Errorf("failed to lock stake: %v", err)
	}

	// Create validator
	validator := &Validator{
		Address:     address,
		Name:        name,
		VotingPower: stake,
		Stake:       stake,
		Active:      true,
		Reputation:  1.0,
	}

	g.validators[address] = validator
	g.stakingPool.ValidatorStakes[address] = stake
	g.stakingPool.TotalStake += stake

	fmt.Printf("✅ Validator registered: %s (stake: %d)\n", address, stake)
	return nil
}

// DelegateStake delegates stake to a validator
func (g *Governance) DelegateStake(delegator, validator string, amount uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Check if validator exists and is active
	v, exists := g.validators[validator]
	if !exists || !v.Active {
		return fmt.Errorf("validator %s not found or inactive", validator)
	}

	// Check delegator's balance
	token := g.blockchain.TokenRegistry["BHX"]
	balance, err := token.BalanceOf(delegator)
	if err != nil {
		return fmt.Errorf("failed to check balance: %v", err)
	}
	if balance < amount {
		return fmt.Errorf("insufficient balance: has %d, needs %d", balance, amount)
	}

	// Lock delegation in governance contract
	err = token.Transfer(delegator, "governance_contract", amount)
	if err != nil {
		return fmt.Errorf("failed to lock delegation: %v", err)
	}

	// Add delegation
	delegation := Delegation{
		Delegator: delegator,
		Amount:    amount,
		Since:     time.Now().Unix(),
	}

	if g.stakingPool.DelegatorStakes[validator] == nil {
		g.stakingPool.DelegatorStakes[validator] = make([]Delegation, 0)
	}
	g.stakingPool.DelegatorStakes[validator] = append(g.stakingPool.DelegatorStakes[validator], delegation)

	// Update validator's voting power
	v.VotingPower += amount
	g.stakingPool.TotalStake += amount

	fmt.Printf("✅ Stake delegated: %s -> %s (amount: %d)\n", delegator, validator, amount)
	return nil
}

// SubmitProposal submits a new governance proposal
func (g *Governance) SubmitProposal(proposalType ProposalType, title, description, proposer string, metadata map[string]any) (*Proposal, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Check if proposer is a validator
	if _, exists := g.validators[proposer]; !exists {
		return nil, fmt.Errorf("only validators can submit proposals")
	}

	// Check proposal deposit
	token := g.blockchain.TokenRegistry["BHX"]
	balance, err := token.BalanceOf(proposer)
	if err != nil {
		return nil, fmt.Errorf("failed to check balance: %v", err)
	}
	if balance < g.params.MinDeposit {
		return nil, fmt.Errorf("insufficient deposit: has %d, needs %d", balance, g.params.MinDeposit)
	}

	// Lock proposal deposit
	err = token.Transfer(proposer, "governance_contract", g.params.MinDeposit)
	if err != nil {
		return nil, fmt.Errorf("failed to lock deposit: %v", err)
	}

	// Create proposal
	proposal := &Proposal{
		ID:          fmt.Sprintf("prop_%d", time.Now().UnixNano()),
		Type:        proposalType,
		Title:       title,
		Description: description,
		Proposer:    proposer,
		Status:      StatusPending,
		SubmitTime:  time.Now(),
		VotingStart: time.Now().Add(24 * time.Hour), // Start voting after 24 hours
		VotingEnd:   time.Now().Add(24*time.Hour + g.params.VotingPeriod),
		Votes:       make(map[string]*Vote),
		Metadata:    metadata,
	}

	g.proposals[proposal.ID] = proposal
	fmt.Printf("✅ Proposal submitted: %s\n", proposal.ID)
	return proposal, nil
}

// CastVote casts a vote on a proposal
func (g *Governance) CastVote(proposalID, voter string, option VoteOption) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Get proposal
	proposal, exists := g.proposals[proposalID]
	if !exists {
		return fmt.Errorf("proposal %s not found", proposalID)
	}

	// Check if proposal is active
	if proposal.Status != StatusActive {
		return fmt.Errorf("proposal is not active")
	}

	// Check if voting period is valid
	now := time.Now()
	if now.Before(proposal.VotingStart) || now.After(proposal.VotingEnd) {
		return fmt.Errorf("voting period is not active")
	}

	// Get voter's voting power
	var votingPower uint64
	if validator, exists := g.validators[voter]; exists {
		votingPower = validator.VotingPower
	} else {
		// Check if voter is a delegator
		for _, validator := range g.validators {
			for _, delegation := range g.stakingPool.DelegatorStakes[validator.Address] {
				if delegation.Delegator == voter {
					votingPower += delegation.Amount
				}
			}
		}
	}

	if votingPower == 0 {
		return fmt.Errorf("voter has no voting power")
	}

	// Record vote
	vote := &Vote{
		Voter:     voter,
		Option:    option,
		Power:     votingPower,
		Timestamp: now,
	}

	proposal.Votes[voter] = vote
	proposal.TotalPower += votingPower

	fmt.Printf("✅ Vote cast on proposal %s: %s (%s, power: %d)\n",
		proposalID, voter, option, votingPower)
	return nil
}

// processProposals processes proposals in the background
func (g *Governance) processProposals() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		g.mu.Lock()
		now := time.Now()

		for _, proposal := range g.proposals {
			switch proposal.Status {
			case StatusPending:
				if now.After(proposal.VotingStart) {
					proposal.Status = StatusActive
				}
			case StatusActive:
				if now.After(proposal.VotingEnd) {
					result, err := g.tallyVotes(proposal.ID)
					if err != nil {
						fmt.Printf("Error tallying votes for proposal %s: %v\n", proposal.ID, err)
						continue
					}

					if result.Outcome == "passed" {
						proposal.Status = StatusPassed
						g.executeProposal(proposal)
					} else {
						proposal.Status = StatusRejected
					}
				}
			}
		}

		g.mu.Unlock()
	}
}

// tallyVotes tallies the votes for a proposal
func (g *Governance) tallyVotes(proposalID string) (*ProposalResult, error) {
	proposal, exists := g.proposals[proposalID]
	if !exists {
		return nil, fmt.Errorf("proposal not found")
	}

	result := &ProposalResult{
		ProposalID:       proposalID,
		TotalVotingPower: g.stakingPool.TotalStake,
	}

	for _, vote := range proposal.Votes {
		switch vote.Option {
		case VoteYes:
			result.YesVotes += vote.Power
		case VoteNo:
			result.NoVotes += vote.Power
		case VoteAbstain:
			result.AbstainVotes += vote.Power
		case VoteNoWithVeto:
			result.VetoVotes += vote.Power
		}
		result.TotalPower += vote.Power
	}

	// Calculate rates
	if result.TotalVotingPower > 0 {
		result.Quorum = float64(result.TotalPower) / float64(result.TotalVotingPower)
	}
	if result.TotalPower > 0 {
		result.PassRate = float64(result.YesVotes) / float64(result.TotalPower)
		result.VetoRate = float64(result.VetoVotes) / float64(result.TotalPower)
	}

	// Determine outcome
	if result.Quorum >= g.params.QuorumThreshold {
		if result.VetoRate >= g.params.VetoThreshold {
			result.Outcome = "rejected_veto"
		} else if result.PassRate >= g.params.PassThreshold {
			result.Outcome = "passed"
		} else {
			result.Outcome = "rejected"
		}
	} else {
		result.Outcome = "rejected_quorum"
	}

	return result, nil
}

// executeProposal executes a passed proposal
func (g *Governance) executeProposal(proposal *Proposal) error {
	switch proposal.Type {
	case ProposalParameterChange:
		return g.executeParameterChange(proposal)
	case ProposalUpgrade:
		return g.executeUpgrade(proposal)
	case ProposalTreasury:
		return g.executeTreasuryProposal(proposal)
	case ProposalValidator:
		return g.executeValidatorProposal(proposal)
	case ProposalEmergency:
		return g.executeEmergencyProposal(proposal)
	default:
		return fmt.Errorf("unknown proposal type")
	}
}

// updateValidatorSet updates the validator set periodically
func (g *Governance) updateValidatorSet() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		g.mu.Lock()

		// Sort validators by stake
		type validatorStake struct {
			address string
			stake   uint64
		}
		validatorStakes := make([]validatorStake, 0, len(g.validators))
		for addr, validator := range g.validators {
			if validator.Active {
				validatorStakes = append(validatorStakes, validatorStake{addr, validator.Stake})
			}
		}

		// Sort by stake (descending)
		for i := 0; i < len(validatorStakes)-1; i++ {
			for j := i + 1; j < len(validatorStakes); j++ {
				if validatorStakes[j].stake > validatorStakes[i].stake {
					validatorStakes[i], validatorStakes[j] = validatorStakes[j], validatorStakes[i]
				}
			}
		}

		// Update active status
		for i, vs := range validatorStakes {
			validator := g.validators[vs.address]
			validator.Active = i < g.stakingPool.MaxValidators
		}

		g.mu.Unlock()
	}
}

// executeParameterChange executes a parameter change proposal
func (g *Governance) executeParameterChange(proposal *Proposal) error {
	params, ok := proposal.Metadata["params"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid parameter change metadata")
	}

	// Update parameters
	if minDeposit, ok := params["min_deposit"].(float64); ok {
		g.params.MinDeposit = uint64(minDeposit)
	}
	if quorumThreshold, ok := params["quorum_threshold"].(float64); ok {
		g.params.QuorumThreshold = quorumThreshold
	}
	if passThreshold, ok := params["pass_threshold"].(float64); ok {
		g.params.PassThreshold = passThreshold
	}
	if vetoThreshold, ok := params["veto_threshold"].(float64); ok {
		g.params.VetoThreshold = vetoThreshold
	}

	return nil
}

// executeUpgrade executes an upgrade proposal
func (g *Governance) executeUpgrade(proposal *Proposal) error {
	// Implementation would handle blockchain upgrade process
	return fmt.Errorf("upgrade proposals not implemented")
}

// executeTreasuryProposal executes a treasury proposal
func (g *Governance) executeTreasuryProposal(proposal *Proposal) error {
	params, ok := proposal.Metadata["treasury"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid treasury proposal metadata")
	}

	recipient, ok := params["recipient"].(string)
	if !ok {
		return fmt.Errorf("invalid recipient")
	}

	amount, ok := params["amount"].(float64)
	if !ok {
		return fmt.Errorf("invalid amount")
	}

	// Transfer funds from treasury
	token := g.blockchain.TokenRegistry["BHX"]
	return token.Transfer("treasury_contract", recipient, uint64(amount))
}

// executeValidatorProposal executes a validator-related proposal
func (g *Governance) executeValidatorProposal(proposal *Proposal) error {
	params, ok := proposal.Metadata["validator"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid validator proposal metadata")
	}

	action, ok := params["action"].(string)
	if !ok {
		return fmt.Errorf("invalid action")
	}

	address, ok := params["address"].(string)
	if !ok {
		return fmt.Errorf("invalid validator address")
	}

	validator, exists := g.validators[address]
	if !exists {
		return fmt.Errorf("validator not found")
	}

	switch action {
	case "remove":
		validator.Active = false
		// Return stake to validator
		token := g.blockchain.TokenRegistry["BHX"]
		return token.Transfer("governance_contract", address, validator.Stake)
	case "slash":
		slashAmount, ok := params["slash_amount"].(float64)
		if !ok {
			return fmt.Errorf("invalid slash amount")
		}
		validator.Stake -= uint64(slashAmount)
		validator.VotingPower -= uint64(slashAmount)
		g.stakingPool.TotalStake -= uint64(slashAmount)
	default:
		return fmt.Errorf("unknown validator action")
	}

	return nil
}

// executeEmergencyProposal executes an emergency proposal
func (g *Governance) executeEmergencyProposal(proposal *Proposal) error {
	// Implementation would handle emergency actions
	return fmt.Errorf("emergency proposals not implemented")
}
