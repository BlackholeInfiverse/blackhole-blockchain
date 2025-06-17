package governance

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// ProposalType represents different types of governance proposals
type ProposalType string

const (
	ProposalParameterChange ProposalType = "parameter_change"
	ProposalUpgrade         ProposalType = "upgrade"
	ProposalTreasury        ProposalType = "treasury"
	ProposalValidator       ProposalType = "validator"
	ProposalEmergency       ProposalType = "emergency"
)

// ProposalStatus represents the status of a proposal
type ProposalStatus string

const (
	StatusPending   ProposalStatus = "pending"
	StatusActive    ProposalStatus = "active"
	StatusPassed    ProposalStatus = "passed"
	StatusRejected  ProposalStatus = "rejected"
	StatusExecuted  ProposalStatus = "executed"
	StatusCancelled ProposalStatus = "cancelled"
)

// VoteOption represents voting options
type VoteOption string

const (
	VoteYes        VoteOption = "yes"
	VoteNo         VoteOption = "no"
	VoteAbstain    VoteOption = "abstain"
	VoteNoWithVeto VoteOption = "no_with_veto"
)

// Proposal represents a governance proposal
type Proposal struct {
	ID          string           `json:"id"`
	Type        ProposalType     `json:"type"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Proposer    string           `json:"proposer"`
	Status      ProposalStatus   `json:"status"`
	SubmitTime  time.Time        `json:"submit_time"`
	VotingStart time.Time        `json:"voting_start"`
	VotingEnd   time.Time        `json:"voting_end"`
	Votes       map[string]*Vote `json:"votes"`
	TotalPower  uint64           `json:"total_power"`
	Metadata    map[string]any   `json:"metadata"`
}

// Vote represents a single vote on a proposal
type Vote struct {
	Voter     string     `json:"voter"`
	Option    VoteOption `json:"option"`
	Power     uint64     `json:"power"`
	Timestamp time.Time  `json:"timestamp"`
}

// Validator represents a validator in the governance system
type Validator struct {
	Address     string    `json:"address"`
	Name        string    `json:"name"`
	VotingPower uint64    `json:"voting_power"`
	Stake       uint64    `json:"stake"`
	Active      bool      `json:"active"`
	LastVoted   time.Time `json:"last_voted"`
	Reputation  float64   `json:"reputation"`
}

// GovernanceParams represents governance parameters
type GovernanceParams struct {
	VotingPeriod     time.Duration `json:"voting_period"`
	MinDeposit       uint64        `json:"min_deposit"`
	QuorumThreshold  float64       `json:"quorum_threshold"`
	PassThreshold    float64       `json:"pass_threshold"`
	VetoThreshold    float64       `json:"veto_threshold"`
	MaxProposalSize  int           `json:"max_proposal_size"`
	ProposalCooldown time.Duration `json:"proposal_cooldown"`
}

// GovernanceSimulator simulates governance operations
type GovernanceSimulator struct {
	proposals  map[string]*Proposal
	validators map[string]*Validator
	params     *GovernanceParams
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	enabled    bool
	eventLog   []string
}

// NewGovernanceSimulator creates a new governance simulator
func NewGovernanceSimulator() *GovernanceSimulator {
	ctx, cancel := context.WithCancel(context.Background())

	simulator := &GovernanceSimulator{
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
		ctx:      ctx,
		cancel:   cancel,
		enabled:  true,
		eventLog: make([]string, 0),
	}

	// Initialize with mock validators
	simulator.initializeMockValidators()

	return simulator
}

// initializeMockValidators creates mock validators for simulation
func (gs *GovernanceSimulator) initializeMockValidators() {
	validators := []*Validator{
		{
			Address:     "validator_1",
			Name:        "Genesis Validator",
			VotingPower: 1000000,
			Stake:       1000000,
			Active:      true,
			Reputation:  0.95,
		},
		{
			Address:     "validator_2",
			Name:        "Community Validator",
			VotingPower: 750000,
			Stake:       750000,
			Active:      true,
			Reputation:  0.88,
		},
		{
			Address:     "validator_3",
			Name:        "Enterprise Validator",
			VotingPower: 500000,
			Stake:       500000,
			Active:      true,
			Reputation:  0.92,
		},
		{
			Address:     "validator_4",
			Name:        "Institutional Validator",
			VotingPower: 300000,
			Stake:       300000,
			Active:      true,
			Reputation:  0.85,
		},
	}

	for _, validator := range validators {
		gs.validators[validator.Address] = validator
	}

	gs.logEvent(fmt.Sprintf("Initialized %d validators with total power: %d",
		len(validators), gs.getTotalVotingPower()))
}

// Start begins the governance simulation
func (gs *GovernanceSimulator) Start() error {
	if !gs.enabled {
		return fmt.Errorf("governance simulator is disabled")
	}

	// Start background processes
	go gs.backgroundProcessing()

	fmt.Println("✅ Governance simulator started")
	gs.logEvent("Governance simulator started")
	return nil
}

// Stop stops the governance simulation
func (gs *GovernanceSimulator) Stop() error {
	gs.cancel()
	fmt.Println("🛑 Governance simulator stopped")
	gs.logEvent("Governance simulator stopped")
	return nil
}

// SubmitProposal submits a new governance proposal
func (gs *GovernanceSimulator) SubmitProposal(proposalType ProposalType, title, description, proposer string, metadata map[string]any) (*Proposal, error) {
	if !gs.enabled {
		return nil, fmt.Errorf("governance simulator is disabled")
	}

	gs.mu.Lock()
	defer gs.mu.Unlock()

	proposalID := fmt.Sprintf("prop_%d", time.Now().Unix())

	proposal := &Proposal{
		ID:          proposalID,
		Type:        proposalType,
		Title:       title,
		Description: description,
		Proposer:    proposer,
		Status:      StatusPending,
		SubmitTime:  time.Now(),
		VotingStart: time.Now().Add(24 * time.Hour), // 1 day delay
		VotingEnd:   time.Now().Add(24*time.Hour + gs.params.VotingPeriod),
		Votes:       make(map[string]*Vote),
		TotalPower:  gs.getTotalVotingPower(),
		Metadata:    metadata,
	}

	gs.proposals[proposalID] = proposal

	message := fmt.Sprintf("Proposal submitted: %s (%s)", title, proposalType)
	fmt.Printf("📝 %s\n", message)
	gs.logEvent(message)

	return proposal, nil
}

// CastVote casts a vote on a proposal
func (gs *GovernanceSimulator) CastVote(proposalID, voterAddress string, option VoteOption) error {
	if !gs.enabled {
		return fmt.Errorf("governance simulator is disabled")
	}

	gs.mu.Lock()
	defer gs.mu.Unlock()

	proposal, exists := gs.proposals[proposalID]
	if !exists {
		return fmt.Errorf("proposal not found: %s", proposalID)
	}

	validator, exists := gs.validators[voterAddress]
	if !exists {
		return fmt.Errorf("validator not found: %s", voterAddress)
	}

	if !validator.Active {
		return fmt.Errorf("validator is not active: %s", voterAddress)
	}

	now := time.Now()
	if now.Before(proposal.VotingStart) {
		return fmt.Errorf("voting has not started yet")
	}

	if now.After(proposal.VotingEnd) {
		return fmt.Errorf("voting period has ended")
	}

	vote := &Vote{
		Voter:     voterAddress,
		Option:    option,
		Power:     validator.VotingPower,
		Timestamp: now,
	}

	proposal.Votes[voterAddress] = vote
	validator.LastVoted = now

	message := fmt.Sprintf("Vote cast: %s voted %s on %s", validator.Name, option, proposal.Title)
	fmt.Printf("🗳️ %s\n", message)
	gs.logEvent(message)

	return nil
}

// SimulateVoting simulates voting behavior for all validators
func (gs *GovernanceSimulator) SimulateVoting(proposalID string) error {
	if !gs.enabled {
		return fmt.Errorf("governance simulator is disabled")
	}

	proposal, exists := gs.proposals[proposalID]
	if !exists {
		return fmt.Errorf("proposal not found: %s", proposalID)
	}

	fmt.Printf("🤖 Simulating voting for proposal: %s\n", proposal.Title)

	// Simulate voting behavior based on validator reputation and proposal type
	for _, validator := range gs.validators {
		if !validator.Active {
			continue
		}

		// Skip if already voted
		if _, hasVoted := proposal.Votes[validator.Address]; hasVoted {
			continue
		}

		// Simulate voting probability based on reputation
		if rand.Float64() > validator.Reputation {
			continue // Validator doesn't participate
		}

		// Determine vote based on proposal type and validator characteristics
		var option VoteOption
		switch proposal.Type {
		case ProposalParameterChange:
			if rand.Float64() < 0.7 {
				option = VoteYes
			} else {
				option = VoteNo
			}
		case ProposalUpgrade:
			if rand.Float64() < 0.8 {
				option = VoteYes
			} else {
				option = VoteAbstain
			}
		case ProposalTreasury:
			if rand.Float64() < 0.6 {
				option = VoteYes
			} else if rand.Float64() < 0.8 {
				option = VoteNo
			} else {
				option = VoteAbstain
			}
		default:
			if rand.Float64() < 0.5 {
				option = VoteYes
			} else {
				option = VoteNo
			}
		}

		// Cast the vote
		gs.CastVote(proposalID, validator.Address, option)

		// Add some randomness to voting timing
		time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
	}

	return nil
}

// TallyVotes tallies votes for a proposal and determines the outcome
func (gs *GovernanceSimulator) TallyVotes(proposalID string) (*ProposalResult, error) {
	if !gs.enabled {
		return nil, fmt.Errorf("governance simulator is disabled")
	}

	gs.mu.Lock()
	defer gs.mu.Unlock()

	proposal, exists := gs.proposals[proposalID]
	if !exists {
		return nil, fmt.Errorf("proposal not found: %s", proposalID)
	}

	var yesVotes, noVotes, abstainVotes, vetoVotes uint64
	var totalVotingPower uint64

	for _, vote := range proposal.Votes {
		totalVotingPower += vote.Power
		switch vote.Option {
		case VoteYes:
			yesVotes += vote.Power
		case VoteNo:
			noVotes += vote.Power
		case VoteAbstain:
			abstainVotes += vote.Power
		case VoteNoWithVeto:
			vetoVotes += vote.Power
		}
	}

	result := &ProposalResult{
		ProposalID:       proposalID,
		YesVotes:         yesVotes,
		NoVotes:          noVotes,
		AbstainVotes:     abstainVotes,
		VetoVotes:        vetoVotes,
		TotalVotingPower: totalVotingPower,
		TotalPower:       proposal.TotalPower,
		Quorum:           float64(totalVotingPower) / float64(proposal.TotalPower),
		PassRate:         float64(yesVotes) / float64(totalVotingPower),
		VetoRate:         float64(vetoVotes) / float64(totalVotingPower),
	}

	// Determine outcome
	if result.Quorum < gs.params.QuorumThreshold {
		result.Outcome = "failed_quorum"
		proposal.Status = StatusRejected
	} else if result.VetoRate >= gs.params.VetoThreshold {
		result.Outcome = "vetoed"
		proposal.Status = StatusRejected
	} else if result.PassRate >= gs.params.PassThreshold {
		result.Outcome = "passed"
		proposal.Status = StatusPassed
	} else {
		result.Outcome = "rejected"
		proposal.Status = StatusRejected
	}

	message := fmt.Sprintf("Proposal %s: %s (%.1f%% quorum, %.1f%% yes)",
		proposal.Title, result.Outcome, result.Quorum*100, result.PassRate*100)
	fmt.Printf("📊 %s\n", message)
	gs.logEvent(message)

	return result, nil
}

// ProposalResult represents the result of a proposal vote
type ProposalResult struct {
	ProposalID       string  `json:"proposal_id"`
	YesVotes         uint64  `json:"yes_votes"`
	NoVotes          uint64  `json:"no_votes"`
	AbstainVotes     uint64  `json:"abstain_votes"`
	VetoVotes        uint64  `json:"veto_votes"`
	TotalVotingPower uint64  `json:"total_voting_power"`
	TotalPower       uint64  `json:"total_power"`
	Quorum           float64 `json:"quorum"`
	PassRate         float64 `json:"pass_rate"`
	VetoRate         float64 `json:"veto_rate"`
	Outcome          string  `json:"outcome"`
}

// backgroundProcessing handles background governance tasks
func (gs *GovernanceSimulator) backgroundProcessing() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-gs.ctx.Done():
			return
		case <-ticker.C:
			gs.processProposals()
		}
	}
}

// processProposals processes pending proposals
func (gs *GovernanceSimulator) processProposals() {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	now := time.Now()

	for _, proposal := range gs.proposals {
		switch proposal.Status {
		case StatusPending:
			if now.After(proposal.VotingStart) {
				proposal.Status = StatusActive
				gs.logEvent(fmt.Sprintf("Voting started for proposal: %s", proposal.Title))
			}
		case StatusActive:
			if now.After(proposal.VotingEnd) {
				// Auto-tally votes
				go func(pid string) {
					gs.TallyVotes(pid)
				}(proposal.ID)
			}
		}
	}
}

// getTotalVotingPower calculates total voting power
func (gs *GovernanceSimulator) getTotalVotingPower() uint64 {
	var total uint64
	for _, validator := range gs.validators {
		if validator.Active {
			total += validator.VotingPower
		}
	}
	return total
}

// logEvent logs an event to the event log
func (gs *GovernanceSimulator) logEvent(message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s", timestamp, message)
	gs.eventLog = append(gs.eventLog, logEntry)

	// Keep only last 1000 events
	if len(gs.eventLog) > 1000 {
		gs.eventLog = gs.eventLog[len(gs.eventLog)-1000:]
	}
}

// GetProposals returns all proposals
func (gs *GovernanceSimulator) GetProposals() map[string]*Proposal {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	result := make(map[string]*Proposal)
	for k, v := range gs.proposals {
		result[k] = v
	}
	return result
}

// GetValidators returns all validators
func (gs *GovernanceSimulator) GetValidators() map[string]*Validator {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	result := make(map[string]*Validator)
	for k, v := range gs.validators {
		result[k] = v
	}
	return result
}

// GetEventLog returns recent events
func (gs *GovernanceSimulator) GetEventLog(limit int) []string {
	gs.mu.RLock()
	defer gs.mu.RUnlock()

	if limit <= 0 || limit > len(gs.eventLog) {
		limit = len(gs.eventLog)
	}

	start := len(gs.eventLog) - limit
	result := make([]string, limit)
	copy(result, gs.eventLog[start:])
	return result
}

// Global governance simulator instance
var GlobalGovernanceSimulator *GovernanceSimulator

// InitializeGlobalGovernanceSimulator initializes the global governance simulator
func InitializeGlobalGovernanceSimulator() error {
	GlobalGovernanceSimulator = NewGovernanceSimulator()
	return GlobalGovernanceSimulator.Start()
}
