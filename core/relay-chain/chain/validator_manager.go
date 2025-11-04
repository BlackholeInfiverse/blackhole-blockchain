package chain

import (
    "errors"
    "math/rand"
    "time"
)

// ValidatorManager handles validator selection and management
type ValidatorManager struct {
    StakeLedger *StakeLedger
}

// NewValidatorManager creates a new validator manager
func NewValidatorManager(stakeLedger *StakeLedger) *ValidatorManager {
    return &ValidatorManager{
        StakeLedger: stakeLedger,
    }
}

func (vm *ValidatorManager) SelectValidator(stakeLedger *StakeLedger) (string, error) {
    // Get all validators with their stakes
    validators := stakeLedger.GetAllStakes()
    if len(validators) == 0 {
        return "", errors.New("no validators available")
    }
    
    // Weight selection by stake amount
    totalStake := uint64(0)
    for _, stake := range validators {
        totalStake += stake
    }
    
    // Select validator proportionally to stake
    if totalStake == 0 {
        return "", errors.New("total stake is zero")
    }
    
    // Use random selection weighted by stake
    rand.Seed(time.Now().UnixNano())
    selection := rand.Uint64() % totalStake
    
    runningTotal := uint64(0)
    for addr, stake := range validators {
        runningTotal += stake
        if runningTotal > selection {
            return addr, nil
        }
    }
    
    // Fallback to highest stake validator if random selection fails
    return stakeLedger.GetHighestStakeValidator(), nil
}

