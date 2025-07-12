package chain

import (
	"fmt"
	"log"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
)

// FaucetConfig represents the configuration for the validator faucet
type FaucetConfig struct {
	InitialValidatorAmount  uint64
	MinimumStakeThreshold   uint64
	TopUpAmount             uint64
	TopUpThreshold          uint64
	CooldownPeriod          time.Duration
	MaxDailyDistribution    uint64
	MinimumUptime           time.Duration
	RequireActiveStaking    bool
	AutoDistributionEnabled bool
	CheckInterval           time.Duration
}

// DefaultFaucetConfig returns a default faucet configuration
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

// InitializeValidatorFaucet initializes the validator faucet for the blockchain
func (bc *Blockchain) InitializeValidatorFaucet(config *FaucetConfig) error {
	if config == nil {
		config = DefaultFaucetConfig()
	}

	// Get or create BHX token
	_ = bc.GetOrCreateBHXToken()

	// Create faucet (we'll import the actual faucet package when needed)
	// For now, we'll store the configuration
	log.Printf("🚰 Validator Faucet configuration initialized")
	log.Printf("   💰 Initial amount: %d BHX", config.InitialValidatorAmount)
	log.Printf("   🔄 Top-up amount: %d BHX", config.TopUpAmount)
	log.Printf("   ⏰ Check interval: %v", config.CheckInterval)

	return nil
}

// GetOrCreateBHXToken gets the BHX token or creates it if it doesn't exist
func (bc *Blockchain) GetOrCreateBHXToken() *token.Token {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Check if BHX token already exists
	if bhxToken, exists := bc.TokenRegistry["BHX"]; exists {
		return bhxToken
	}

	// Create BHX token
	bhxToken := token.NewToken("BlackHole", "BHX", 18, 0) // Unlimited supply

	// Mint initial supply for the system
	systemAddress := "system_treasury"
	initialSupply := uint64(1000000000) // 1 billion BHX

	if err := bhxToken.Mint(systemAddress, initialSupply); err != nil {
		log.Printf("⚠️ Warning: Failed to mint initial BHX supply: %v", err)
	} else {
		log.Printf("✅ BHX token created with %d initial supply", initialSupply)
	}

	// Register token in the blockchain
	bc.TokenRegistry["BHX"] = bhxToken

	return bhxToken
}

// RegisterValidatorForFaucet registers a validator for faucet eligibility
func (bc *Blockchain) RegisterValidatorForFaucet(address string) error {
	// Check if validator has minimum stake
	stake := bc.StakeLedger.GetStake(address)
	if stake < 100 { // Minimum stake threshold
		return fmt.Errorf("validator %s does not meet minimum stake requirement (has: %d, required: 100)", address, stake)
	}

	// Get BHX token
	bhxToken := bc.GetOrCreateBHXToken()

	// Check if validator already has tokens
	balance, err := bhxToken.BalanceOf(address)
	if err != nil {
		return fmt.Errorf("failed to check validator balance: %v", err)
	}

	// Distribute initial tokens if balance is low
	if balance < 50 { // Threshold for initial distribution
		initialAmount := uint64(1000)
		if err := bhxToken.Mint(address, initialAmount); err != nil {
			return fmt.Errorf("failed to distribute initial tokens: %v", err)
		}

		log.Printf("💰 Distributed %d BHX to new validator: %s", initialAmount, address)

		// Create a transaction record for this distribution
		tx := &Transaction{
			Type:      TokenTransfer,
			From:      "system_treasury",
			To:        address,
			Amount:    initialAmount,
			TokenID:   "BHX",
			Timestamp: time.Now().Unix(),
			Nonce:     uint64(time.Now().UnixNano()),
		}
		tx.ID = tx.CalculateHash()

		// Add to pending transactions
		bc.mu.Lock()
		bc.PendingTxs = append(bc.PendingTxs, tx)
		bc.mu.Unlock()
	}

	return nil
}

// TopUpValidator tops up a validator's balance if it's below threshold
func (bc *Blockchain) TopUpValidator(address string) error {
	// Check if validator is active
	stake := bc.StakeLedger.GetStake(address)
	if stake < 100 { // Minimum stake threshold
		return fmt.Errorf("validator %s is not active (stake: %d)", address, stake)
	}

	// Get BHX token
	bhxToken := bc.GetOrCreateBHXToken()

	// Check current balance
	balance, err := bhxToken.BalanceOf(address)
	if err != nil {
		return fmt.Errorf("failed to check validator balance: %v", err)
	}

	// Top up if below threshold
	threshold := uint64(50)
	if balance < threshold {
		topUpAmount := uint64(500)
		if err := bhxToken.Mint(address, topUpAmount); err != nil {
			return fmt.Errorf("failed to top up validator: %v", err)
		}

		log.Printf("🔄 Topped up validator %s with %d BHX (balance was: %d)", address, topUpAmount, balance)

		// Create a transaction record for this top-up
		tx := &Transaction{
			Type:      TokenTransfer,
			From:      "system_treasury",
			To:        address,
			Amount:    topUpAmount,
			TokenID:   "BHX",
			Timestamp: time.Now().Unix(),
			Nonce:     uint64(time.Now().UnixNano()),
		}
		tx.ID = tx.CalculateHash()

		// Add to pending transactions
		bc.mu.Lock()
		bc.PendingTxs = append(bc.PendingTxs, tx)
		bc.mu.Unlock()
	}

	return nil
}

// GetValidatorFaucetStats returns statistics about validator faucet distributions
func (bc *Blockchain) GetValidatorFaucetStats() map[string]interface{} {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	stats := make(map[string]interface{})

	// Count validators
	validators := bc.StakeLedger.GetAllStakes()
	activeValidators := 0
	for _, stake := range validators {
		if stake >= 100 { // Minimum stake threshold
			activeValidators++
		}
	}

	stats["total_validators"] = len(validators)
	stats["active_validators"] = activeValidators

	// Get BHX token info
	if bhxToken, exists := bc.TokenRegistry["BHX"]; exists {
		stats["bhx_total_supply"] = bhxToken.TotalSupply()
	}

	// Count faucet-related transactions
	faucetTxCount := 0
	for _, tx := range bc.PendingTxs {
		if tx.From == "system_treasury" && tx.TokenID == "BHX" {
			faucetTxCount++
		}
	}
	stats["pending_faucet_transactions"] = faucetTxCount

	return stats
}

// AutoTopUpValidators automatically tops up validators that need it
func (bc *Blockchain) AutoTopUpValidators() {
	validators := bc.StakeLedger.GetAllStakes()

	for address, stake := range validators {
		if stake >= 100 { // Only active validators
			if err := bc.TopUpValidator(address); err != nil {
				log.Printf("⚠️ Failed to auto top-up validator %s: %v", address, err)
			}
		}
	}
}
