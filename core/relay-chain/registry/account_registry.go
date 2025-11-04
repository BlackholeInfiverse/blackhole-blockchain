package registry

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

// AccountInfo represents metadata about a blockchain account
type AccountInfo struct {
	Address     string    `json:"address"`
	CreatedAt   time.Time `json:"created_at"`
	LastActive  time.Time `json:"last_active"`
	IsContract  bool      `json:"is_contract"`
	WalletName  string    `json:"wallet_name,omitempty"`
	UserID      string    `json:"user_id,omitempty"`
	Source      string    `json:"source"` // "wallet_ui", "genesis", "contract", "otc"
	TxCount     int64     `json:"tx_count"`
	FirstTxHash string    `json:"first_tx_hash,omitempty"`
}

// TokenInteraction tracks which tokens an address has interacted with
type TokenInteraction struct {
	TokenSymbol   string    `json:"token_symbol"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	TxCount       int64     `json:"tx_count"`
	HasBalance    bool      `json:"has_balance"`
	MaxBalance    uint64    `json:"max_balance"`
}

// AccountRegistry manages all known blockchain addresses
type AccountRegistry struct {
	// Core storage
	accounts map[string]*AccountInfo                    // address -> account info
	tokenInteractions map[string]map[string]*TokenInteraction // address -> token -> interaction
	
	// Database
	db *leveldb.DB
	
	// Synchronization
	mutex sync.RWMutex
	
	// Statistics
	totalAccounts     int64
	contractAccounts  int64
	activeAccounts    int64
	lastCleanup       time.Time
}

// NewAccountRegistry creates a new account registry
func NewAccountRegistry(db *leveldb.DB) *AccountRegistry {
	ar := &AccountRegistry{
		accounts:          make(map[string]*AccountInfo),
		tokenInteractions: make(map[string]map[string]*TokenInteraction),
		db:                db,
		lastCleanup:       time.Now(),
	}
	
	// Load existing accounts from database
	ar.loadFromDatabase()
	
	log.Printf("✅ Account Registry initialized with %d accounts", len(ar.accounts))
	return ar
}

// RegisterAccount adds a new account to the registry
func (ar *AccountRegistry) RegisterAccount(address, source string, isContract bool, userID, walletName string) error {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()
	
	// Check if account already exists
	if existing, exists := ar.accounts[address]; exists {
		// Update last active time
		existing.LastActive = time.Now()
		if userID != "" && existing.UserID == "" {
			existing.UserID = userID
		}
		if walletName != "" && existing.WalletName == "" {
			existing.WalletName = walletName
		}
		ar.saveAccountToDatabase(existing)
		return nil
	}
	
	// Create new account info
	account := &AccountInfo{
		Address:    address,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
		IsContract: isContract,
		WalletName: walletName,
		UserID:     userID,
		Source:     source,
		TxCount:    0,
	}
	
	ar.accounts[address] = account
	ar.totalAccounts++
	
	if isContract {
		ar.contractAccounts++
	}
	
	// Initialize token interactions map
	ar.tokenInteractions[address] = make(map[string]*TokenInteraction)
	
	// Save to database
	if err := ar.saveAccountToDatabase(account); err != nil {
		log.Printf("❌ Failed to save account %s to database: %v", address, err)
		return err
	}
	
	log.Printf("✅ Registered new account: %s (source: %s, user: %s)", address, source, userID)
	return nil
}

// RecordTokenInteraction tracks when an address interacts with a token
func (ar *AccountRegistry) RecordTokenInteraction(address, tokenSymbol, txHash string, hasBalance bool, currentBalance uint64) {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()
	
	// Ensure account exists
	if _, exists := ar.accounts[address]; !exists {
		// Auto-register account if it doesn't exist
		ar.accounts[address] = &AccountInfo{
			Address:     address,
			CreatedAt:   time.Now(),
			LastActive:  time.Now(),
			IsContract:  false,
			Source:      "auto_detected",
			TxCount:     0,
		}
		ar.tokenInteractions[address] = make(map[string]*TokenInteraction)
		ar.totalAccounts++
	}
	
	// Update account activity
	account := ar.accounts[address]
	account.LastActive = time.Now()
	account.TxCount++
	if account.FirstTxHash == "" {
		account.FirstTxHash = txHash
	}
	
	// Update token interaction
	if ar.tokenInteractions[address] == nil {
		ar.tokenInteractions[address] = make(map[string]*TokenInteraction)
	}
	
	interaction, exists := ar.tokenInteractions[address][tokenSymbol]
	if !exists {
		interaction = &TokenInteraction{
			TokenSymbol: tokenSymbol,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			TxCount:     1,
			HasBalance:  hasBalance,
			MaxBalance:  currentBalance,
		}
		ar.tokenInteractions[address][tokenSymbol] = interaction
	} else {
		interaction.LastSeen = time.Now()
		interaction.TxCount++
		interaction.HasBalance = hasBalance
		if currentBalance > interaction.MaxBalance {
			interaction.MaxBalance = currentBalance
		}
	}
	
	// Save to database
	ar.saveAccountToDatabase(account)
	ar.saveTokenInteractionToDatabase(address, tokenSymbol, interaction)
}

// GetAccount retrieves account information
func (ar *AccountRegistry) GetAccount(address string) (*AccountInfo, bool) {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()
	
	account, exists := ar.accounts[address]
	if exists {
		// Update last active time for accessed accounts
		account.LastActive = time.Now()
	}
	return account, exists
}

// GetAllAccounts returns all registered accounts
func (ar *AccountRegistry) GetAllAccounts() map[string]*AccountInfo {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()
	
	// Return a copy to prevent external modification
	result := make(map[string]*AccountInfo)
	for addr, account := range ar.accounts {
		accountCopy := *account
		result[addr] = &accountCopy
	}
	
	return result
}

// GetUserAccounts returns all accounts for a specific user
func (ar *AccountRegistry) GetUserAccounts(userID string) []*AccountInfo {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()
	
	var userAccounts []*AccountInfo
	for _, account := range ar.accounts {
		if account.UserID == userID {
			accountCopy := *account
			userAccounts = append(userAccounts, &accountCopy)
		}
	}
	
	return userAccounts
}

// GetTokenInteractions returns token interactions for an address
func (ar *AccountRegistry) GetTokenInteractions(address string) map[string]*TokenInteraction {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()
	
	interactions, exists := ar.tokenInteractions[address]
	if !exists {
		return make(map[string]*TokenInteraction)
	}
	
	// Return a copy
	result := make(map[string]*TokenInteraction)
	for token, interaction := range interactions {
		interactionCopy := *interaction
		result[token] = &interactionCopy
	}
	
	return result
}

// GetActiveAccounts returns accounts active within the specified duration
func (ar *AccountRegistry) GetActiveAccounts(since time.Duration) []*AccountInfo {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()
	
	cutoff := time.Now().Add(-since)
	var activeAccounts []*AccountInfo
	
	for _, account := range ar.accounts {
		if account.LastActive.After(cutoff) {
			accountCopy := *account
			activeAccounts = append(activeAccounts, &accountCopy)
		}
	}
	
	return activeAccounts
}

// GetAccountsWithToken returns all accounts that have interacted with a specific token
func (ar *AccountRegistry) GetAccountsWithToken(tokenSymbol string) []string {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()
	
	var addresses []string
	for address, interactions := range ar.tokenInteractions {
		if _, exists := interactions[tokenSymbol]; exists {
			addresses = append(addresses, address)
		}
	}
	
	return addresses
}

// saveAccountToDatabase persists account info to database
func (ar *AccountRegistry) saveAccountToDatabase(account *AccountInfo) error {
	key := fmt.Sprintf("account_registry:%s", account.Address)
	data, err := json.Marshal(account)
	if err != nil {
		return err
	}
	
	return ar.db.Put([]byte(key), data, nil)
}

// saveTokenInteractionToDatabase persists token interaction to database
func (ar *AccountRegistry) saveTokenInteractionToDatabase(address, tokenSymbol string, interaction *TokenInteraction) error {
	key := fmt.Sprintf("token_interaction:%s:%s", address, tokenSymbol)
	data, err := json.Marshal(interaction)
	if err != nil {
		return err
	}
	
	return ar.db.Put([]byte(key), data, nil)
}

// loadFromDatabase loads all accounts and interactions from database
func (ar *AccountRegistry) loadFromDatabase() {
	iter := ar.db.NewIterator(nil, nil)
	defer iter.Release()
	
	accountsLoaded := 0
	interactionsLoaded := 0
	
	for iter.Next() {
		key := string(iter.Key())
		
		if len(key) >= 17 && key[:17] == "account_registry:" {
			// Load account
			address := key[17:]
			var account AccountInfo
			if err := json.Unmarshal(iter.Value(), &account); err == nil {
				ar.accounts[address] = &account
				if ar.tokenInteractions[address] == nil {
					ar.tokenInteractions[address] = make(map[string]*TokenInteraction)
				}
				accountsLoaded++
				
				if account.IsContract {
					ar.contractAccounts++
				}
			}
		} else if len(key) >= 18 && key[:18] == "token_interaction:" {
			// Load token interaction
			parts := key[18:]
			// Parse address:token format
			colonIndex := -1
			for i := len(parts) - 1; i >= 0; i-- {
				if parts[i] == ':' {
					colonIndex = i
					break
				}
			}
			
			if colonIndex > 0 {
				address := parts[:colonIndex]
				tokenSymbol := parts[colonIndex+1:]
				
				var interaction TokenInteraction
				if err := json.Unmarshal(iter.Value(), &interaction); err == nil {
					if ar.tokenInteractions[address] == nil {
						ar.tokenInteractions[address] = make(map[string]*TokenInteraction)
					}
					ar.tokenInteractions[address][tokenSymbol] = &interaction
					interactionsLoaded++
				}
			}
		}
	}
	
	ar.totalAccounts = int64(len(ar.accounts))
	
	if err := iter.Error(); err != nil {
		log.Printf("❌ Error loading account registry: %v", err)
	} else {
		log.Printf("✅ Loaded %d accounts and %d token interactions from database", 
			accountsLoaded, interactionsLoaded)
	}
}

// GetStats returns registry statistics
func (ar *AccountRegistry) GetStats() map[string]interface{} {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()
	
	// Count active accounts (active in last 24 hours)
	activeCount := int64(0)
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, account := range ar.accounts {
		if account.LastActive.After(cutoff) {
			activeCount++
		}
	}
	
	return map[string]interface{}{
		"total_accounts":    ar.totalAccounts,
		"contract_accounts": ar.contractAccounts,
		"active_24h":        activeCount,
		"total_interactions": len(ar.tokenInteractions),
		"last_cleanup":      ar.lastCleanup,
	}
}
