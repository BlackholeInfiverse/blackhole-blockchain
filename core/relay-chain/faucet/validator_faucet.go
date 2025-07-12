package faucet

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
)

// ValidatorFaucet manages token distribution to validators
type ValidatorFaucet struct {
	blockchain    *chain.Blockchain
	tokenSystem   *token.Token
	stakeLedger   *chain.StakeLedger
	config        *FaucetConfig
	distributions map[string]*DistributionRecord
	validators    map[string]*ValidatorInfo
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	running       bool
	stats         *FaucetStats
}

// FaucetConfig holds configuration for the validator faucet
type FaucetConfig struct {
	// Distribution amounts
	InitialValidatorAmount uint64 // Initial tokens for new validators
	MinimumStakeThreshold  uint64 // Minimum stake required to be eligible
	TopUpAmount            uint64 // Amount to top up when balance is low
	TopUpThreshold         uint64 // Balance threshold for top-up

	// Rate limiting
	CooldownPeriod       time.Duration // Time between distributions to same validator
	MaxDailyDistribution uint64        // Maximum tokens per validator per day

	// Eligibility criteria
	MinimumUptime        time.Duration // Minimum uptime required
	RequireActiveStaking bool          // Must have active stake

	// Automation
	AutoDistributionEnabled bool          // Enable automatic distribution
	CheckInterval           time.Duration // How often to check for distributions
}

// DistributionRecord tracks token distributions to validators
type DistributionRecord struct {
	ValidatorAddress string    `json:"validator_address"`
	Amount           uint64    `json:"amount"`
	Timestamp        time.Time `json:"timestamp"`
	Reason           string    `json:"reason"`
	TxHash           string    `json:"tx_hash"`
	DailyTotal       uint64    `json:"daily_total"`
	LastReset        time.Time `json:"last_reset"`
}

// ValidatorInfo tracks validator status and eligibility
type ValidatorInfo struct {
	Address          string    `json:"address"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	TotalStake       uint64    `json:"total_stake"`
	IsActive         bool      `json:"is_active"`
	BlocksProduced   uint64    `json:"blocks_produced"`
	LastDistribution time.Time `json:"last_distribution"`
	TotalReceived    uint64    `json:"total_received"`
}

// FaucetStats tracks overall faucet statistics
type FaucetStats struct {
	TotalDistributed   uint64    `json:"total_distributed"`
	TotalValidators    int       `json:"total_validators"`
	ActiveValidators   int       `json:"active_validators"`
	DistributionsToday uint64    `json:"distributions_today"`
	LastDistribution   time.Time `json:"last_distribution"`
	StartTime          time.Time `json:"start_time"`
}

// Distribution reasons
const (
	ReasonInitialStake = "initial_validator_stake"
	ReasonTopUp        = "balance_top_up"
	ReasonReward       = "validator_reward"
	ReasonManual       = "manual_distribution"
	ReasonEmergency    = "emergency_funding"
)

// NewValidatorFaucet creates a new validator faucet
func NewValidatorFaucet(blockchain *chain.Blockchain, tokenSystem *token.Token, config *FaucetConfig) *ValidatorFaucet {
	ctx, cancel := context.WithCancel(context.Background())

	if config == nil {
		config = DefaultFaucetConfig()
	}

	return &ValidatorFaucet{
		blockchain:    blockchain,
		tokenSystem:   tokenSystem,
		stakeLedger:   blockchain.StakeLedger,
		config:        config,
		distributions: make(map[string]*DistributionRecord),
		validators:    make(map[string]*ValidatorInfo),
		ctx:           ctx,
		cancel:        cancel,
		running:       false,
		stats: &FaucetStats{
			StartTime: time.Now(),
		},
	}
}

// DefaultFaucetConfig returns default configuration
func DefaultFaucetConfig() *FaucetConfig {
	return &FaucetConfig{
		InitialValidatorAmount:  1000,             // 1000 BHX for new validators
		MinimumStakeThreshold:   100,              // Must have at least 100 BHX staked
		TopUpAmount:             500,              // Top up with 500 BHX
		TopUpThreshold:          50,               // Top up when balance < 50 BHX
		CooldownPeriod:          1 * time.Hour,    // 1 hour between distributions
		MaxDailyDistribution:    5000,             // Max 5000 BHX per validator per day
		MinimumUptime:           10 * time.Minute, // 10 minutes minimum uptime
		RequireActiveStaking:    true,
		AutoDistributionEnabled: true,
		CheckInterval:           30 * time.Second, // Check every 30 seconds
	}
}

// Start begins the validator faucet service
func (vf *ValidatorFaucet) Start() error {
	vf.mu.Lock()
	defer vf.mu.Unlock()

	if vf.running {
		return errors.New("validator faucet is already running")
	}

	vf.running = true
	log.Println("🚰 Starting Validator Faucet service...")

	// Initialize existing validators
	if err := vf.initializeExistingValidators(); err != nil {
		log.Printf("⚠️ Warning: Failed to initialize existing validators: %v", err)
	}

	// Start automatic distribution if enabled
	if vf.config.AutoDistributionEnabled {
		go vf.autoDistributionLoop()
	}

	log.Printf("✅ Validator Faucet started successfully")
	log.Printf("   💰 Initial amount: %d BHX", vf.config.InitialValidatorAmount)
	log.Printf("   🔄 Top-up amount: %d BHX", vf.config.TopUpAmount)
	log.Printf("   ⏰ Check interval: %v", vf.config.CheckInterval)

	return nil
}

// Stop stops the validator faucet service
func (vf *ValidatorFaucet) Stop() {
	vf.mu.Lock()
	defer vf.mu.Unlock()

	if !vf.running {
		return
	}

	log.Println("🛑 Stopping Validator Faucet service...")
	vf.cancel()
	vf.running = false
	log.Println("✅ Validator Faucet stopped")
}

// RegisterValidator registers a new validator for faucet eligibility
func (vf *ValidatorFaucet) RegisterValidator(address string) error {
	vf.mu.Lock()
	defer vf.mu.Unlock()

	// Check if validator already exists
	if _, exists := vf.validators[address]; exists {
		return fmt.Errorf("validator %s is already registered", address)
	}

	// Create validator info
	validatorInfo := &ValidatorInfo{
		Address:   address,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		IsActive:  true,
	}

	vf.validators[address] = validatorInfo
	vf.stats.TotalValidators++

	log.Printf("📝 Registered new validator: %s", address)

	// Distribute initial tokens if eligible
	if vf.isEligibleForInitialDistribution(address) {
		go func() {
			if err := vf.DistributeToValidator(address, vf.config.InitialValidatorAmount, ReasonInitialStake); err != nil {
				log.Printf("❌ Failed to distribute initial tokens to %s: %v", address, err)
			}
		}()
	}

	return nil
}

// DistributeToValidator distributes tokens to a specific validator
func (vf *ValidatorFaucet) DistributeToValidator(address string, amount uint64, reason string) error {
	vf.mu.Lock()
	defer vf.mu.Unlock()

	// Validate inputs
	if amount == 0 {
		return errors.New("distribution amount must be greater than 0")
	}

	// Check if validator exists
	validatorInfo, exists := vf.validators[address]
	if !exists {
		return fmt.Errorf("validator %s is not registered", address)
	}

	// Check eligibility
	if !vf.isEligibleForDistribution(address, amount) {
		return fmt.Errorf("validator %s is not eligible for distribution", address)
	}

	// Check daily limits
	if err := vf.checkDailyLimits(address, amount); err != nil {
		return err
	}

	// Mint tokens to validator
	if err := vf.tokenSystem.Mint(address, amount); err != nil {
		return fmt.Errorf("failed to mint tokens: %v", err)
	}

	// Record distribution
	distribution := &DistributionRecord{
		ValidatorAddress: address,
		Amount:           amount,
		Timestamp:        time.Now(),
		Reason:           reason,
		TxHash:           fmt.Sprintf("faucet_%d", time.Now().UnixNano()),
	}

	// Update daily totals
	vf.updateDailyTotals(address, amount)

	// Store distribution record
	recordKey := fmt.Sprintf("%s_%d", address, time.Now().UnixNano())
	vf.distributions[recordKey] = distribution

	// Update validator info
	validatorInfo.LastDistribution = time.Now()
	validatorInfo.TotalReceived += amount

	// Update stats
	vf.stats.TotalDistributed += amount
	vf.stats.LastDistribution = time.Now()
	vf.stats.DistributionsToday += amount

	log.Printf("💰 Distributed %d BHX to validator %s (reason: %s)", amount, address, reason)

	return nil
}

// GetValidatorInfo returns information about a validator
func (vf *ValidatorFaucet) GetValidatorInfo(address string) (*ValidatorInfo, error) {
	vf.mu.RLock()
	defer vf.mu.RUnlock()

	info, exists := vf.validators[address]
	if !exists {
		return nil, fmt.Errorf("validator %s not found", address)
	}

	// Create a copy to avoid race conditions
	infoCopy := *info
	return &infoCopy, nil
}

// GetFaucetStats returns current faucet statistics
func (vf *ValidatorFaucet) GetFaucetStats() *FaucetStats {
	vf.mu.RLock()
	defer vf.mu.RUnlock()

	// Update active validators count
	activeCount := 0
	for _, validator := range vf.validators {
		if validator.IsActive && time.Since(validator.LastSeen) < 5*time.Minute {
			activeCount++
		}
	}
	vf.stats.ActiveValidators = activeCount

	// Create a copy to avoid race conditions
	statsCopy := *vf.stats
	return &statsCopy
}

// ListValidators returns all registered validators
func (vf *ValidatorFaucet) ListValidators() map[string]*ValidatorInfo {
	vf.mu.RLock()
	defer vf.mu.RUnlock()

	validators := make(map[string]*ValidatorInfo)
	for addr, info := range vf.validators {
		infoCopy := *info
		validators[addr] = &infoCopy
	}

	return validators
}

// GetDistributionHistory returns distribution history for a validator
func (vf *ValidatorFaucet) GetDistributionHistory(address string, limit int) []*DistributionRecord {
	vf.mu.RLock()
	defer vf.mu.RUnlock()

	var records []*DistributionRecord
	count := 0

	for _, record := range vf.distributions {
		if record.ValidatorAddress == address {
			recordCopy := *record
			records = append(records, &recordCopy)
			count++
			if limit > 0 && count >= limit {
				break
			}
		}
	}

	return records
}

// Helper methods

// initializeExistingValidators scans the stake ledger for existing validators
func (vf *ValidatorFaucet) initializeExistingValidators() error {
	stakes := vf.stakeLedger.GetAllStakes()

	for address, stake := range stakes {
		if stake >= vf.config.MinimumStakeThreshold {
			if _, exists := vf.validators[address]; !exists {
				validatorInfo := &ValidatorInfo{
					Address:    address,
					FirstSeen:  time.Now().Add(-24 * time.Hour), // Assume existing for 24h
					LastSeen:   time.Now(),
					TotalStake: stake,
					IsActive:   true,
				}
				vf.validators[address] = validatorInfo
				vf.stats.TotalValidators++
				log.Printf("📝 Initialized existing validator: %s (stake: %d)", address, stake)
			}
		}
	}

	return nil
}

// isEligibleForInitialDistribution checks if validator is eligible for initial distribution
func (vf *ValidatorFaucet) isEligibleForInitialDistribution(address string) bool {
	// Check if validator has minimum stake
	stake := vf.stakeLedger.GetStake(address)
	if stake < vf.config.MinimumStakeThreshold {
		return false
	}

	// Check if validator already received initial distribution
	for _, record := range vf.distributions {
		if record.ValidatorAddress == address && record.Reason == ReasonInitialStake {
			return false
		}
	}

	return true
}

// isEligibleForDistribution checks if validator is eligible for any distribution
func (vf *ValidatorFaucet) isEligibleForDistribution(address string, amount uint64) bool {
	validatorInfo, exists := vf.validators[address]
	if !exists {
		return false
	}

	// Check if validator is active
	if !validatorInfo.IsActive {
		return false
	}

	// Check minimum uptime
	uptime := time.Since(validatorInfo.FirstSeen)
	if uptime < vf.config.MinimumUptime {
		return false
	}

	// Check cooldown period
	if time.Since(validatorInfo.LastDistribution) < vf.config.CooldownPeriod {
		return false
	}

	// Check if validator has active stake (if required)
	if vf.config.RequireActiveStaking {
		stake := vf.stakeLedger.GetStake(address)
		if stake < vf.config.MinimumStakeThreshold {
			return false
		}
	}

	return true
}

// checkDailyLimits verifies daily distribution limits
func (vf *ValidatorFaucet) checkDailyLimits(address string, amount uint64) error {
	record, exists := vf.distributions[address]
	if !exists {
		return nil // No previous distributions
	}

	// Reset daily total if it's a new day
	if time.Since(record.LastReset) >= 24*time.Hour {
		record.DailyTotal = 0
		record.LastReset = time.Now()
	}

	// Check if adding this amount would exceed daily limit
	if record.DailyTotal+amount > vf.config.MaxDailyDistribution {
		return fmt.Errorf("daily distribution limit exceeded (current: %d, limit: %d)",
			record.DailyTotal+amount, vf.config.MaxDailyDistribution)
	}

	return nil
}

// updateDailyTotals updates the daily distribution totals
func (vf *ValidatorFaucet) updateDailyTotals(address string, amount uint64) {
	record, exists := vf.distributions[address]
	if !exists {
		record = &DistributionRecord{
			ValidatorAddress: address,
			DailyTotal:       0,
			LastReset:        time.Now(),
		}
		vf.distributions[address] = record
	}

	// Reset if new day
	if time.Since(record.LastReset) >= 24*time.Hour {
		record.DailyTotal = 0
		record.LastReset = time.Now()
	}

	record.DailyTotal += amount
}

// autoDistributionLoop runs the automatic distribution logic
func (vf *ValidatorFaucet) autoDistributionLoop() {
	ticker := time.NewTicker(vf.config.CheckInterval)
	defer ticker.Stop()

	log.Printf("🤖 Starting automatic distribution loop (interval: %v)", vf.config.CheckInterval)

	for {
		select {
		case <-vf.ctx.Done():
			log.Println("🛑 Automatic distribution loop stopped")
			return
		case <-ticker.C:
			vf.performAutomaticDistributions()
		}
	}
}

// performAutomaticDistributions checks and performs automatic distributions
func (vf *ValidatorFaucet) performAutomaticDistributions() {
	vf.mu.Lock()
	defer vf.mu.Unlock()

	// Update validator activity status
	vf.updateValidatorActivity()

	// Check each validator for distribution needs
	for address, validatorInfo := range vf.validators {
		if !validatorInfo.IsActive {
			continue
		}

		// Check if validator needs top-up
		balance, err := vf.tokenSystem.BalanceOf(address)
		if err != nil {
			log.Printf("⚠️ Failed to get balance for validator %s: %v", address, err)
			continue
		}

		// Top up if balance is below threshold
		if balance < vf.config.TopUpThreshold {
			if vf.isEligibleForDistribution(address, vf.config.TopUpAmount) {
				go func(addr string) {
					if err := vf.DistributeToValidator(addr, vf.config.TopUpAmount, ReasonTopUp); err != nil {
						log.Printf("❌ Failed to top up validator %s: %v", addr, err)
					}
				}(address)
			}
		}
	}
}

// updateValidatorActivity updates validator activity status based on stake ledger
func (vf *ValidatorFaucet) updateValidatorActivity() {
	stakes := vf.stakeLedger.GetAllStakes()

	// Mark validators as active if they have stake
	for address, stake := range stakes {
		if validatorInfo, exists := vf.validators[address]; exists {
			validatorInfo.TotalStake = stake
			validatorInfo.LastSeen = time.Now()
			validatorInfo.IsActive = stake >= vf.config.MinimumStakeThreshold
		}
	}

	// Mark validators as inactive if they haven't been seen recently
	for _, validatorInfo := range vf.validators {
		if time.Since(validatorInfo.LastSeen) > 10*time.Minute {
			validatorInfo.IsActive = false
		}
	}
}
