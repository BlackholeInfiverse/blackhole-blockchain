package token

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdminOverrideBasics(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 1000000)
	admin := "system"
	user := "0xUser"
	nonAdmin := "0xNonAdmin"

	t.Run("Default admin setup", func(t *testing.T) {
		assert.True(t, token.isAdmin(admin))
		assert.False(t, token.isAdmin(nonAdmin))
		
		admins := token.GetAdmins()
		assert.Contains(t, admins, admin)
		assert.Len(t, admins, 1)
	})

	t.Run("Add and remove admin", func(t *testing.T) {
		// Add new admin
		err := token.AdminOverride(admin, "add_admin", user, 0, ReasonMaintenance, "Adding new admin")
		assert.NoError(t, err)
		assert.True(t, token.isAdmin(user))

		// Remove admin
		err = token.AdminOverride(admin, "remove_admin", user, 0, ReasonMaintenance, "Removing admin")
		assert.NoError(t, err)
		assert.False(t, token.isAdmin(user))
	})

	t.Run("Cannot remove last admin", func(t *testing.T) {
		// Try to remove the only admin
		err := token.AdminOverride(admin, "remove_admin", admin, 0, ReasonMaintenance, "Removing last admin")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot remove the last admin")
	})

	t.Run("Non-admin cannot perform admin actions", func(t *testing.T) {
		err := token.AdminOverride(nonAdmin, "emergency_mint", user, 1000, ReasonEmergency, "Emergency mint")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unauthorized: admin access required")
	})
}

func TestEmergencyMinting(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 1000)
	admin := "system"
	user := "0xUser"

	t.Run("Emergency mint bypasses max supply", func(t *testing.T) {
		// Normal mint would fail due to max supply limit
		initialSupply := token.TotalSupply()
		
		// Emergency mint should succeed even if it exceeds max supply
		err := token.AdminOverride(admin, "emergency_mint", user, 2000, ReasonEmergency, "Emergency token supply")
		assert.NoError(t, err)

		// Verify tokens were minted
		balance, _ := token.BalanceOf(user)
		assert.Equal(t, uint64(2000), balance)
		assert.Equal(t, initialSupply+2000, token.TotalSupply())
	})

	t.Run("Emergency burn", func(t *testing.T) {
		// First mint some tokens
		token.AdminOverride(admin, "emergency_mint", user, 1000, ReasonEmergency, "Setup for burn test")
		
		initialBalance, _ := token.BalanceOf(user)
		initialSupply := token.TotalSupply()

		// Emergency burn
		err := token.AdminOverride(admin, "emergency_burn", user, 500, ReasonSecurity, "Emergency burn")
		assert.NoError(t, err)

		// Verify tokens were burned
		newBalance, _ := token.BalanceOf(user)
		assert.Equal(t, initialBalance-500, newBalance)
		assert.Equal(t, initialSupply-500, token.TotalSupply())
	})

	t.Run("Emergency burn with insufficient balance fails", func(t *testing.T) {
		balance, _ := token.BalanceOf(user)
		
		// Try to burn more than available
		err := token.AdminOverride(admin, "emergency_burn", user, balance+1000, ReasonSecurity, "Excessive burn")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "insufficient balance")
	})
}

func TestTokenPauseUnpause(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 1000000)
	admin := "system"
	user := "0xUser"

	// Setup: mint some tokens to user
	token.Mint(user, 1000)

	t.Run("Pause token operations", func(t *testing.T) {
		// Pause token
		err := token.AdminOverride(admin, "pause_token", "", 0, ReasonMaintenance, "Maintenance pause")
		assert.NoError(t, err)
		assert.True(t, token.IsPaused())

		// Normal operations should fail when paused
		err = token.Transfer(user, "0xOther", 100)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token operations are paused")

		err = token.Mint(user, 100)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token operations are paused")

		err = token.Burn(user, 100)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token operations are paused")
	})

	t.Run("Unpause token operations", func(t *testing.T) {
		// Unpause token
		err := token.AdminOverride(admin, "unpause_token", "", 0, ReasonMaintenance, "End maintenance")
		assert.NoError(t, err)
		assert.False(t, token.IsPaused())

		// Operations should work again
		err = token.Transfer(user, "0xOther", 100)
		assert.NoError(t, err)
	})

	t.Run("Cannot pause already paused token", func(t *testing.T) {
		// Pause first
		token.AdminOverride(admin, "pause_token", "", 0, ReasonMaintenance, "Pause")
		
		// Try to pause again
		err := token.AdminOverride(admin, "pause_token", "", 0, ReasonMaintenance, "Double pause")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token is already paused")
	})

	t.Run("Cannot unpause non-paused token", func(t *testing.T) {
		// Unpause first
		token.AdminOverride(admin, "unpause_token", "", 0, ReasonMaintenance, "Unpause")
		
		// Try to unpause again
		err := token.AdminOverride(admin, "unpause_token", "", 0, ReasonMaintenance, "Double unpause")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token is not paused")
	})
}

func TestEmergencyMode(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 1000)
	admin := "system"
	user := "0xUser"

	t.Run("Enable emergency mode", func(t *testing.T) {
		err := token.AdminOverride(admin, "emergency_mode_on", "", 0, ReasonEmergency, "Security incident")
		assert.NoError(t, err)
		assert.True(t, token.IsEmergencyMode())
	})

	t.Run("Emergency mode allows operations when paused", func(t *testing.T) {
		// Pause token
		token.AdminOverride(admin, "pause_token", "", 0, ReasonMaintenance, "Pause for emergency")
		assert.True(t, token.IsPaused())

		// Mint should work in emergency mode even when paused
		err := token.Mint(user, 1000)
		assert.NoError(t, err)

		// Burn should work in emergency mode even when paused
		err = token.Burn(user, 500)
		assert.NoError(t, err)
	})

	t.Run("Disable emergency mode", func(t *testing.T) {
		err := token.AdminOverride(admin, "emergency_mode_off", "", 0, ReasonMaintenance, "Emergency resolved")
		assert.NoError(t, err)
		assert.False(t, token.IsEmergencyMode())

		// Now operations should fail again due to pause
		err = token.Mint(user, 100)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token operations are paused")
	})

	t.Run("Cannot enable already enabled emergency mode", func(t *testing.T) {
		// Enable first
		token.AdminOverride(admin, "emergency_mode_on", "", 0, ReasonEmergency, "Enable")
		
		// Try to enable again
		err := token.AdminOverride(admin, "emergency_mode_on", "", 0, ReasonEmergency, "Double enable")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "emergency mode is already enabled")
	})
}

func TestAdminOverrideEvents(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 1000000)
	admin := "system"
	user := "0xUser"

	t.Run("Admin override events are emitted", func(t *testing.T) {
		// Clear existing events
		token.events = []Event{}

		// Perform admin override
		err := token.AdminOverride(admin, "emergency_mint", user, 1000, ReasonEmergency, "Test emergency mint")
		assert.NoError(t, err)

		// Check events
		events := token.GetEvents()
		assert.Len(t, events, 1)
		
		event := events[0]
		assert.Equal(t, EventType("AdminOverride"), event.Type)
		assert.Equal(t, admin, event.From)
		assert.Equal(t, user, event.To)
		assert.Equal(t, uint64(1000), event.Amount)
		assert.NotEmpty(t, event.TxHash)
		assert.NotZero(t, event.Timestamp)
		
		// Check metadata
		assert.Equal(t, "emergency_mint", event.Metadata["action"])
		assert.Equal(t, ReasonEmergency, event.Metadata["reason"])
		assert.Equal(t, "Test emergency mint", event.Metadata["description"])
		assert.Equal(t, admin, event.Metadata["admin"])
	})
}

func TestTokenStatus(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 1000000)
	admin := "system"

	t.Run("Get comprehensive token status", func(t *testing.T) {
		// Modify token state
		token.AdminOverride(admin, "pause_token", "", 0, ReasonMaintenance, "Test pause")
		token.AdminOverride(admin, "emergency_mode_on", "", 0, ReasonEmergency, "Test emergency")
		token.AdminOverride(admin, "add_admin", "0xNewAdmin", 0, ReasonMaintenance, "Add admin")

		status := token.GetTokenStatus()
		
		assert.Equal(t, "TestToken", status["name"])
		assert.Equal(t, "TT", status["symbol"])
		assert.Equal(t, uint8(18), status["decimals"])
		assert.Equal(t, uint64(0), status["total_supply"])
		assert.Equal(t, uint64(1000000), status["max_supply"])
		assert.Equal(t, true, status["paused"])
		assert.Equal(t, true, status["emergency_mode"])
		assert.Equal(t, 2, status["admin_count"])
		
		admins := status["admins"].([]string)
		assert.Contains(t, admins, admin)
		assert.Contains(t, admins, "0xNewAdmin")
	})
}

func TestInvalidAdminActions(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 1000000)
	admin := "system"

	t.Run("Unknown admin action", func(t *testing.T) {
		err := token.AdminOverride(admin, "unknown_action", "0xUser", 1000, ReasonMaintenance, "Test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown admin action")
	})

	t.Run("Invalid addresses", func(t *testing.T) {
		err := token.AdminOverride(admin, "emergency_mint", "", 1000, ReasonEmergency, "Empty address")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")

		err = token.AdminOverride(admin, "add_admin", "", 0, ReasonMaintenance, "Empty admin address")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("Zero amount operations", func(t *testing.T) {
		err := token.AdminOverride(admin, "emergency_mint", "0xUser", 0, ReasonEmergency, "Zero mint")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "amount must be > 0")

		err = token.AdminOverride(admin, "emergency_burn", "0xUser", 0, ReasonSecurity, "Zero burn")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "amount must be > 0")
	})
}
