package storage

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// User represents a registered user
type User struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Username     string    `gorm:"uniqueIndex;not null;size:50" json:"username"`
	Email        string    `gorm:"index;size:255" json:"email,omitempty"`
	PasswordHash string    `gorm:"not null;size:255" json:"-"`
	PasswordSalt string    `gorm:"not null;size:255" json:"-"`
	Status       string    `gorm:"not null;default:active;size:20" json:"status"`
	CreatedAt    time.Time `gorm:"not null" json:"created_at"`
	UpdatedAt    time.Time `gorm:"not null" json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	
	// Relationships
	Wallets      []Wallet      `gorm:"foreignKey:UserID" json:"wallets,omitempty"`
	Sessions     []Session     `gorm:"foreignKey:UserID" json:"-"`
	Transactions []Transaction `gorm:"foreignKey:UserID" json:"transactions,omitempty"`
}

// Wallet represents a cryptocurrency wallet
type Wallet struct {
	ID                uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID            uint      `gorm:"not null;index:idx_user_wallet" json:"user_id"`
	Name              string    `gorm:"not null;size:100;index:idx_user_wallet" json:"name"`
	Address           string    `gorm:"uniqueIndex;not null;size:100" json:"address"`
	PublicKey         string    `gorm:"not null;size:200" json:"public_key"`
	WalletType        string    `gorm:"not null;default:standard;size:20" json:"wallet_type"`
	Status            string    `gorm:"not null;default:active;size:20" json:"status"`
	KeyVersion        int       `gorm:"not null;default:1" json:"key_version"`
	CreatedAt         time.Time `gorm:"not null" json:"created_at"`
	UpdatedAt         time.Time `gorm:"not null" json:"updated_at"`
	LastAccessedAt    *time.Time `json:"last_accessed_at,omitempty"`
	
	// Relationships
	User         User          `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Transactions []Transaction `gorm:"foreignKey:WalletID" json:"transactions,omitempty"`
}

// Transaction represents a blockchain transaction
type Transaction struct {
	ID              uint           `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID          uint           `gorm:"not null;index:idx_user_transactions" json:"user_id"`
	WalletID        *uint          `gorm:"index:idx_wallet_transactions" json:"wallet_id,omitempty"`
	TxHash          string         `gorm:"uniqueIndex;not null;size:100" json:"tx_hash"`
	Type            string         `gorm:"not null;size:20;index:idx_tx_type" json:"type"`
	Status          string         `gorm:"not null;default:pending;size:20;index:idx_tx_status" json:"status"`
	FromAddress     string         `gorm:"not null;size:100;index:idx_from_address" json:"from_address"`
	ToAddress       string         `gorm:"not null;size:100;index:idx_to_address" json:"to_address"`
	TokenSymbol     string         `gorm:"not null;size:10;index:idx_token_symbol" json:"token_symbol"`
	Amount          string         `gorm:"not null;size:50" json:"amount"` // Store as string to avoid precision issues
	Fee             string         `gorm:"size:50" json:"fee,omitempty"`
	BlockHeight     *uint64        `gorm:"index:idx_block_height" json:"block_height,omitempty"`
	BlockHash       string         `gorm:"size:100" json:"block_hash,omitempty"`
	Confirmations   int            `gorm:"default:0" json:"confirmations"`
	Nonce           uint64         `json:"nonce"`
	CreatedAt       time.Time      `gorm:"not null;index:idx_tx_created" json:"created_at"`
	UpdatedAt       time.Time      `gorm:"not null" json:"updated_at"`
	CompletedAt     *time.Time     `json:"completed_at,omitempty"`
	
	// Relationships
	User   User    `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Wallet *Wallet `gorm:"foreignKey:WalletID" json:"wallet,omitempty"`
}

// Session represents a user session
type Session struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    uint      `gorm:"not null;index" json:"user_id"`
	SessionID string    `gorm:"uniqueIndex;not null;size:100" json:"session_id"`
	IPAddress string    `gorm:"size:45" json:"ip_address,omitempty"`
	UserAgent string    `gorm:"size:500" json:"user_agent,omitempty"`
	ExpiresAt time.Time `gorm:"not null;index:idx_session_expiry" json:"expires_at"`
	CreatedAt time.Time `gorm:"not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"not null" json:"updated_at"`
	
	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// AuditLog represents audit trail for important operations
type AuditLog struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID      *uint     `gorm:"index" json:"user_id,omitempty"`
	Action      string    `gorm:"not null;size:50;index:idx_audit_action" json:"action"`
	Resource    string    `gorm:"not null;size:50" json:"resource"`
	ResourceID  string    `gorm:"size:100" json:"resource_id,omitempty"`
	IPAddress   string    `gorm:"size:45" json:"ip_address,omitempty"`
	UserAgent   string    `gorm:"size:500" json:"user_agent,omitempty"`
	Details     JSON      `gorm:"type:jsonb" json:"details,omitempty"`
	Status      string    `gorm:"not null;size:20" json:"status"`
	CreatedAt   time.Time `gorm:"not null;index:idx_audit_created" json:"created_at"`
	
	// Relationships
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// APIKey represents API keys for programmatic access
type APIKey struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID      uint      `gorm:"not null;index" json:"user_id"`
	Name        string    `gorm:"not null;size:100" json:"name"`
	KeyHash     string    `gorm:"uniqueIndex;not null;size:255" json:"-"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `gorm:"index:idx_apikey_expiry" json:"expires_at,omitempty"`
	Status      string    `gorm:"not null;default:active;size:20" json:"status"`
	CreatedAt   time.Time `gorm:"not null" json:"created_at"`
	UpdatedAt   time.Time `gorm:"not null" json:"updated_at"`
	
	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// JSON custom type for handling JSON columns
type JSON map[string]interface{}

func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = make(JSON)
		return nil
	}
	
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into JSON", value)
	}
	
	return json.Unmarshal(bytes, j)
}

func (j JSON) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// BeforeCreate hook for User
func (u *User) BeforeCreate(tx *gorm.DB) error {
	now := time.Now().UTC()
	u.CreatedAt = now
	u.UpdatedAt = now
	if u.Status == "" {
		u.Status = "active"
	}
	return nil
}

// BeforeUpdate hook for User
func (u *User) BeforeUpdate(tx *gorm.DB) error {
	u.UpdatedAt = time.Now().UTC()
	return nil
}

// BeforeCreate hook for Wallet
func (w *Wallet) BeforeCreate(tx *gorm.DB) error {
	now := time.Now().UTC()
	w.CreatedAt = now
	w.UpdatedAt = now
	if w.Status == "" {
		w.Status = "active"
	}
	if w.WalletType == "" {
		w.WalletType = "standard"
	}
	if w.KeyVersion == 0 {
		w.KeyVersion = 1
	}
	return nil
}

// BeforeUpdate hook for Wallet
func (w *Wallet) BeforeUpdate(tx *gorm.DB) error {
	w.UpdatedAt = time.Now().UTC()
	return nil
}

// BeforeCreate hook for Transaction
func (t *Transaction) BeforeCreate(tx *gorm.DB) error {
	now := time.Now().UTC()
	t.CreatedAt = now
	t.UpdatedAt = now
	if t.Status == "" {
		t.Status = "pending"
	}
	return nil
}

// BeforeUpdate hook for Transaction
func (t *Transaction) BeforeUpdate(tx *gorm.DB) error {
	t.UpdatedAt = time.Now().UTC()
	if t.Status == "completed" || t.Status == "confirmed" {
		if t.CompletedAt == nil {
			now := time.Now().UTC()
			t.CompletedAt = &now
		}
	}
	return nil
}

// BeforeCreate hook for Session
func (s *Session) BeforeCreate(tx *gorm.DB) error {
	now := time.Now().UTC()
	s.CreatedAt = now
	s.UpdatedAt = now
	if s.ExpiresAt.IsZero() {
		// Default session expires in 24 hours
		s.ExpiresAt = now.Add(24 * time.Hour)
	}
	return nil
}

// BeforeUpdate hook for Session
func (s *Session) BeforeUpdate(tx *gorm.DB) error {
	s.UpdatedAt = time.Now().UTC()
	return nil
}

// BeforeCreate hook for APIKey
func (a *APIKey) BeforeCreate(tx *gorm.DB) error {
	now := time.Now().UTC()
	a.CreatedAt = now
	a.UpdatedAt = now
	if a.Status == "" {
		a.Status = "active"
	}
	return nil
}

// BeforeUpdate hook for APIKey
func (a *APIKey) BeforeUpdate(tx *gorm.DB) error {
	a.UpdatedAt = time.Now().UTC()
	return nil
}

// BeforeCreate hook for AuditLog
func (a *AuditLog) BeforeCreate(tx *gorm.DB) error {
	a.CreatedAt = time.Now().UTC()
	return nil
}

// Validation methods
func (u *User) Validate() error {
	if u.Username == "" {
		return fmt.Errorf("username is required")
	}
	if len(u.Username) < 3 || len(u.Username) > 50 {
		return fmt.Errorf("username must be between 3 and 50 characters")
	}
	if u.PasswordHash == "" {
		return fmt.Errorf("password hash is required")
	}
	return nil
}

func (w *Wallet) Validate() error {
	if w.Name == "" {
		return fmt.Errorf("wallet name is required")
	}
	if w.Address == "" {
		return fmt.Errorf("wallet address is required")
	}
	if w.PublicKey == "" {
		return fmt.Errorf("public key is required")
	}
	if w.UserID == 0 {
		return fmt.Errorf("user ID is required")
	}
	return nil
}

func (t *Transaction) Validate() error {
	if t.TxHash == "" {
		return fmt.Errorf("transaction hash is required")
	}
	if t.Type == "" {
		return fmt.Errorf("transaction type is required")
	}
	if t.FromAddress == "" {
		return fmt.Errorf("from address is required")
	}
	if t.ToAddress == "" {
		return fmt.Errorf("to address is required")
	}
	if t.Amount == "" {
		return fmt.Errorf("amount is required")
	}
	if t.TokenSymbol == "" {
		return fmt.Errorf("token symbol is required")
	}
	return nil
}