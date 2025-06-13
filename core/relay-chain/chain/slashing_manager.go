package chain

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
)

// SlashingCondition represents different types of validator violations
type SlashingCondition int

const (
	DoubleSign SlashingCondition = iota
	Downtime
	InvalidBlock
	MaliciousTransaction
	ConsensusViolation
)

// SlashingEvent represents a slashing incident
type SlashingEvent struct {
	ID          string            `json:"id"`
	Validator   string            `json:"validator"`
	Condition   SlashingCondition `json:"condition"`
	Severity    SlashingSeverity  `json:"severity"`
	Amount      uint64            `json:"amount"`
	Evidence    string            `json:"evidence"`
	Timestamp   int64             `json:"timestamp"`
	BlockHeight uint64            `json:"block_height"`
	Status      string            `json:"status"` // pending, executed, disputed
}

// SlashingSeverity determines the penalty amount
type SlashingSeverity int

const (
	Minor SlashingSeverity = iota
	Major
	Critical
)

// SlashingManager handles validator penalties and security
type SlashingManager struct {
	Events          map[string]*SlashingEvent    `json:"events"`
	ValidatorStrike map[string]int               `json:"validator_strikes"` // Track strikes per validator
	SlashingRates   map[SlashingSeverity]float64 `json:"slashing_rates"`
	StakeLedger     *StakeLedger                 `json:"-"`
	TokenRegistry   map[string]*token.Token      `json:"-"`
	mu              sync.RWMutex                 `json:"-"`
}

// NewSlashingManager creates a new slashing manager
func NewSlashingManager(stakeLedger *StakeLedger, tokenRegistry map[string]*token.Token) *SlashingManager {
	return &SlashingManager{
		Events:          make(map[string]*SlashingEvent),
		ValidatorStrike: make(map[string]int),
		SlashingRates: map[SlashingSeverity]float64{
			Minor:    0.01, // 1% of stake
			Major:    0.05, // 5% of stake
			Critical: 0.20, // 20% of stake
		},
		StakeLedger:   stakeLedger,
		TokenRegistry: tokenRegistry,
	}
}

// ReportViolation reports a validator violation for potential slashing
func (sm *SlashingManager) ReportViolation(validator string, condition SlashingCondition, evidence string, blockHeight uint64) (*SlashingEvent, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Generate event ID - safely handle short validator addresses
	validatorSuffix := validator
	if len(validator) > 8 {
		validatorSuffix = validator[:8]
	}
	eventID := fmt.Sprintf("slash_%d_%s", time.Now().UnixNano(), validatorSuffix)

	// Determine severity based on condition and validator history
	severity := sm.determineSeverity(validator, condition)

	// Calculate slashing amount
	validatorStake := sm.StakeLedger.GetStake(validator)
	if validatorStake == 0 {
		return nil, fmt.Errorf("validator %s has no stake to slash", validator)
	}

	slashAmount := uint64(float64(validatorStake) * sm.SlashingRates[severity])

	// Create slashing event
	event := &SlashingEvent{
		ID:          eventID,
		Validator:   validator,
		Condition:   condition,
		Severity:    severity,
		Amount:      slashAmount,
		Evidence:    evidence,
		Timestamp:   time.Now().Unix(),
		BlockHeight: blockHeight,
		Status:      "pending",
	}

	sm.Events[eventID] = event

	fmt.Printf("🚨 Slashing violation reported: %s for %s (Severity: %v, Amount: %d)\n",
		sm.getConditionName(condition), validator, severity, slashAmount)

	return event, nil
}

// ExecuteSlashing executes a pending slashing event
func (sm *SlashingManager) ExecuteSlashing(eventID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	event, exists := sm.Events[eventID]
	if !exists {
		return fmt.Errorf("slashing event %s not found", eventID)
	}

	if event.Status != "pending" {
		return fmt.Errorf("slashing event %s is not pending (status: %s)", eventID, event.Status)
	}

	// Get validator's current stake
	currentStake := sm.StakeLedger.GetStake(event.Validator)
	if currentStake == 0 {
		fmt.Printf("⚠️ Validator %s already has zero stake, skipping slashing\n", event.Validator)
		event.Status = "skipped"
		return nil
	}

	if currentStake < event.Amount {
		// Slash all remaining stake if insufficient
		event.Amount = currentStake
	}

	// SAFETY CHECK: Prevent slashing if it would leave no active validators
	activeValidators := sm.countActiveValidators()
	if activeValidators <= 1 && event.Amount >= currentStake {
		fmt.Printf("🛡️ SAFETY: Preventing slashing that would jail last validator %s\n", event.Validator)
		event.Status = "blocked_safety"
		return fmt.Errorf("cannot jail last active validator - network safety protection")
	}

	// Execute the slashing
	newStake := currentStake - event.Amount
	sm.StakeLedger.SetStake(event.Validator, newStake)

	// Burn the slashed tokens (remove from circulation)
	if bhxToken, exists := sm.TokenRegistry["BHX"]; exists {
		// Transfer slashed tokens from staking contract to burn address
		err := bhxToken.Transfer("staking_contract", "burn_address", event.Amount)
		if err != nil {
			fmt.Printf("⚠️ Failed to burn slashed tokens: %v\n", err)
		} else {
			fmt.Printf("🔥 Burned %d BHX tokens from slashing\n", event.Amount)
		}
	}

	// Update validator strikes
	sm.ValidatorStrike[event.Validator]++

	// Check if validator should be jailed (3 strikes rule)
	if sm.ValidatorStrike[event.Validator] >= 3 {
		// Additional safety check before jailing
		if activeValidators > 1 {
			sm.jailValidator(event.Validator)
		} else {
			fmt.Printf("🛡️ SAFETY: Not jailing last validator %s despite 3 strikes\n", event.Validator)
		}
	}

	// Update event status
	event.Status = "executed"

	fmt.Printf("⚡ Slashing executed: %d stake removed from %s (New stake: %d)\n",
		event.Amount, event.Validator, newStake)

	return nil
}

// AutoSlash automatically executes slashing for certain severe violations
func (sm *SlashingManager) AutoSlash(validator string, condition SlashingCondition, evidence string, blockHeight uint64) error {
	// Report the violation
	event, err := sm.ReportViolation(validator, condition, evidence, blockHeight)
	if err != nil {
		return err
	}

	// Auto-execute for critical violations
	if event.Severity == Critical {
		return sm.ExecuteSlashing(event.ID)
	}

	fmt.Printf("📋 Slashing event %s created for manual review\n", event.ID)
	return nil
}

// determineSeverity determines the severity of a violation
func (sm *SlashingManager) determineSeverity(validator string, condition SlashingCondition) SlashingSeverity {
	strikes := sm.ValidatorStrike[validator]

	switch condition {
	case DoubleSign:
		return Critical // Always critical - this is a real consensus attack
	case MaliciousTransaction:
		// Be more conservative - only critical after multiple strikes
		if strikes >= 2 {
			return Critical
		} else if strikes >= 1 {
			return Major
		}
		return Minor // First offense is minor for review
	case InvalidBlock:
		if strikes >= 2 {
			return Major
		}
		return Minor
	case ConsensusViolation:
		if strikes >= 1 {
			return Major
		}
		return Minor
	case Downtime:
		if strikes >= 3 {
			return Major
		}
		return Minor
	default:
		return Minor
	}
}

// jailValidator removes a validator from active set
func (sm *SlashingManager) jailValidator(validator string) {
	fmt.Printf("🔒 Validator %s has been jailed (3+ strikes)\n", validator)

	// Set stake to 0 to remove from validator set
	sm.StakeLedger.SetStake(validator, 0)

	// Mark as jailed (could implement unjailing mechanism later)
	sm.ValidatorStrike[validator] = -1 // Special value for jailed
}

// GetSlashingEvents returns all slashing events
func (sm *SlashingManager) GetSlashingEvents() map[string]*SlashingEvent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	events := make(map[string]*SlashingEvent)
	for id, event := range sm.Events {
		events[id] = event
	}
	return events
}

// GetValidatorStrikes returns strike count for a validator
func (sm *SlashingManager) GetValidatorStrikes(validator string) int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.ValidatorStrike[validator]
}

// IsValidatorJailed checks if a validator is jailed
func (sm *SlashingManager) IsValidatorJailed(validator string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.ValidatorStrike[validator] == -1
}

// countActiveValidators counts validators with stake > 0 and not jailed
func (sm *SlashingManager) countActiveValidators() int {
	activeCount := 0
	allStakes := sm.StakeLedger.GetAllStakes()

	for validator, stake := range allStakes {
		// Count as active if has stake and not jailed
		if stake > 0 && !sm.IsValidatorJailed(validator) {
			activeCount++
		}
	}

	return activeCount
}

// getConditionName returns human-readable condition name
func (sm *SlashingManager) getConditionName(condition SlashingCondition) string {
	switch condition {
	case DoubleSign:
		return "Double Signing"
	case Downtime:
		return "Excessive Downtime"
	case InvalidBlock:
		return "Invalid Block Production"
	case MaliciousTransaction:
		return "Malicious Transaction"
	case ConsensusViolation:
		return "Consensus Violation"
	default:
		return "Unknown Violation"
	}
}

// ToJSON serializes slashing manager state
func (sm *SlashingManager) ToJSON() ([]byte, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return json.Marshal(sm)
}

// FromJSON deserializes slashing manager state
func (sm *SlashingManager) FromJSON(data []byte) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return json.Unmarshal(data, sm)
}
