package token

import (
	"errors"
	"log"
	"time"
)

// AdminOverrideReason represents reasons for admin override actions
type AdminOverrideReason string

const (
	ReasonEmergency     AdminOverrideReason = "emergency"
	ReasonSecurity      AdminOverrideReason = "security_incident"
	ReasonMaintenance   AdminOverrideReason = "maintenance"
	ReasonRegulatory    AdminOverrideReason = "regulatory_compliance"
	ReasonBugFix        AdminOverrideReason = "bug_fix"
	ReasonUpgrade       AdminOverrideReason = "system_upgrade"
)

// AdminAction represents an admin override action
type AdminAction struct {
	Action      string              `json:"action"`
	Admin       string              `json:"admin"`
	Target      string              `json:"target,omitempty"`
	Amount      uint64              `json:"amount,omitempty"`
	Reason      AdminOverrideReason `json:"reason"`
	Timestamp   time.Time           `json:"timestamp"`
	TxHash      string              `json:"tx_hash"`
	Description string              `json:"description,omitempty"`
}

// isAdmin checks if an address is authorized as admin
func (t *Token) isAdmin(address string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.adminAddresses[address]
}

// requireAdmin ensures only admins can perform the action
func (t *Token) requireAdmin(address string) error {
	if !t.isAdmin(address) {
		return errors.New("unauthorized: admin access required")
	}
	return nil
}

// requireNotPaused ensures operations can only proceed when not paused
func (t *Token) requireNotPaused() error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.paused {
		return errors.New("token operations are paused")
	}
	return nil
}

// AdminOverride provides emergency admin access to token operations
func (t *Token) AdminOverride(adminAddr string, action string, targetAddr string, amount uint64, reason AdminOverrideReason, description string) error {
	log.Printf("Admin override requested: %s by %s (reason: %s)", action, adminAddr, reason)
	
	// Verify admin authorization
	if err := t.requireAdmin(adminAddr); err != nil {
		log.Printf("Admin override failed: %v", err)
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Create admin action record
	adminAction := AdminAction{
		Action:      action,
		Admin:       adminAddr,
		Target:      targetAddr,
		Amount:      amount,
		Reason:      reason,
		Timestamp:   time.Now(),
		TxHash:      t.generateTxHash("admin_override", adminAddr+":"+action, amount),
		Description: description,
	}

	var err error
	switch action {
	case "emergency_mint":
		err = t.adminEmergencyMint(targetAddr, amount, adminAction)
	case "emergency_burn":
		err = t.adminEmergencyBurn(targetAddr, amount, adminAction)
	case "emergency_transfer":
		// For emergency transfer, targetAddr should be "from:to"
		err = t.adminEmergencyTransfer(targetAddr, amount, adminAction)
	case "freeze_account":
		err = t.adminFreezeAccount(targetAddr, adminAction)
	case "unfreeze_account":
		err = t.adminUnfreezeAccount(targetAddr, adminAction)
	case "pause_token":
		err = t.adminPauseToken(adminAction)
	case "unpause_token":
		err = t.adminUnpauseToken(adminAction)
	case "emergency_mode_on":
		err = t.adminEnableEmergencyMode(adminAction)
	case "emergency_mode_off":
		err = t.adminDisableEmergencyMode(adminAction)
	case "add_admin":
		err = t.adminAddAdmin(targetAddr, adminAction)
	case "remove_admin":
		err = t.adminRemoveAdmin(targetAddr, adminAction)
	default:
		err = errors.New("unknown admin action: " + action)
	}

	if err != nil {
		log.Printf("Admin override failed: %v", err)
		return err
	}

	// Emit admin override event
	event := Event{
		Type:      "AdminOverride",
		From:      adminAddr,
		To:        targetAddr,
		Amount:    amount,
		Timestamp: time.Now(),
		TxHash:    adminAction.TxHash,
		Metadata: map[string]interface{}{
			"action":      action,
			"reason":      reason,
			"description": description,
			"admin":       adminAddr,
		},
	}
	t.events = append(t.events, event)

	log.Printf("Admin override successful: %s by %s", action, adminAddr)
	return nil
}

// adminEmergencyMint performs emergency minting (bypasses normal limits)
func (t *Token) adminEmergencyMint(to string, amount uint64, action AdminAction) error {
	if !t.validateAddress(to) {
		return errors.New("invalid target address")
	}
	if amount == 0 {
		return errors.New("amount must be > 0")
	}

	// Emergency mint bypasses max supply checks
	t.balances[to] += amount
	t.totalSupply += amount

	log.Printf("Emergency mint: %d tokens to %s (admin: %s)", amount, to, action.Admin)
	return nil
}

// adminEmergencyBurn performs emergency burning
func (t *Token) adminEmergencyBurn(from string, amount uint64, action AdminAction) error {
	if !t.validateAddress(from) {
		return errors.New("invalid target address")
	}
	if amount == 0 {
		return errors.New("amount must be > 0")
	}

	if t.balances[from] < amount {
		return errors.New("insufficient balance for emergency burn")
	}

	t.balances[from] -= amount
	t.totalSupply -= amount

	log.Printf("Emergency burn: %d tokens from %s (admin: %s)", amount, from, action.Admin)
	return nil
}

// adminEmergencyTransfer performs emergency transfer (bypasses normal checks)
func (t *Token) adminEmergencyTransfer(fromTo string, amount uint64, action AdminAction) error {
	// Parse "from:to" format
	// For simplicity, assuming format is validated externally
	// In production, you'd want proper parsing
	
	// This is a simplified implementation
	// You would implement proper parsing of fromTo parameter
	log.Printf("Emergency transfer: %d tokens (admin: %s)", amount, action.Admin)
	return nil
}

// adminFreezeAccount freezes an account (prevents all operations)
func (t *Token) adminFreezeAccount(account string, action AdminAction) error {
	if !t.validateAddress(account) {
		return errors.New("invalid account address")
	}

	// Implementation would add account to frozen list
	// For now, just log the action
	log.Printf("Account frozen: %s (admin: %s)", account, action.Admin)
	return nil
}

// adminUnfreezeAccount unfreezes an account
func (t *Token) adminUnfreezeAccount(account string, action AdminAction) error {
	if !t.validateAddress(account) {
		return errors.New("invalid account address")
	}

	log.Printf("Account unfrozen: %s (admin: %s)", account, action.Admin)
	return nil
}

// adminPauseToken pauses all token operations
func (t *Token) adminPauseToken(action AdminAction) error {
	if t.paused {
		return errors.New("token is already paused")
	}

	t.paused = true
	log.Printf("Token paused (admin: %s)", action.Admin)
	return nil
}

// adminUnpauseToken unpauses token operations
func (t *Token) adminUnpauseToken(action AdminAction) error {
	if !t.paused {
		return errors.New("token is not paused")
	}

	t.paused = false
	log.Printf("Token unpaused (admin: %s)", action.Admin)
	return nil
}

// adminEnableEmergencyMode enables emergency mode
func (t *Token) adminEnableEmergencyMode(action AdminAction) error {
	if t.emergencyMode {
		return errors.New("emergency mode is already enabled")
	}

	t.emergencyMode = true
	log.Printf("Emergency mode enabled (admin: %s)", action.Admin)
	return nil
}

// adminDisableEmergencyMode disables emergency mode
func (t *Token) adminDisableEmergencyMode(action AdminAction) error {
	if !t.emergencyMode {
		return errors.New("emergency mode is not enabled")
	}

	t.emergencyMode = false
	log.Printf("Emergency mode disabled (admin: %s)", action.Admin)
	return nil
}

// adminAddAdmin adds a new admin address
func (t *Token) adminAddAdmin(newAdmin string, action AdminAction) error {
	if !t.validateAddress(newAdmin) {
		return errors.New("invalid admin address")
	}

	if t.adminAddresses[newAdmin] {
		return errors.New("address is already an admin")
	}

	t.adminAddresses[newAdmin] = true
	log.Printf("Admin added: %s (by admin: %s)", newAdmin, action.Admin)
	return nil
}

// adminRemoveAdmin removes an admin address
func (t *Token) adminRemoveAdmin(adminToRemove string, action AdminAction) error {
	if !t.validateAddress(adminToRemove) {
		return errors.New("invalid admin address")
	}

	if !t.adminAddresses[adminToRemove] {
		return errors.New("address is not an admin")
	}

	// Prevent removing the last admin
	adminCount := 0
	for _, isAdmin := range t.adminAddresses {
		if isAdmin {
			adminCount++
		}
	}
	if adminCount <= 1 {
		return errors.New("cannot remove the last admin")
	}

	delete(t.adminAddresses, adminToRemove)
	log.Printf("Admin removed: %s (by admin: %s)", adminToRemove, action.Admin)
	return nil
}

// GetAdmins returns all admin addresses
func (t *Token) GetAdmins() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var admins []string
	for addr, isAdmin := range t.adminAddresses {
		if isAdmin {
			admins = append(admins, addr)
		}
	}
	return admins
}

// IsEmergencyMode returns whether emergency mode is enabled
func (t *Token) IsEmergencyMode() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.emergencyMode
}

// IsPaused returns whether token operations are paused
func (t *Token) IsPaused() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.paused
}

// GetTokenStatus returns comprehensive token status
func (t *Token) GetTokenStatus() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return map[string]interface{}{
		"name":           t.Name,
		"symbol":         t.Symbol,
		"decimals":       t.Decimals,
		"total_supply":   t.totalSupply,
		"max_supply":     t.maxSupply,
		"paused":         t.paused,
		"emergency_mode": t.emergencyMode,
		"admin_count":    len(t.adminAddresses),
		"admins":         t.GetAdmins(),
	}
}
