package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v3"
)

// Internal structs for BadgerDB storage that include all fields
// The main models exclude password hash from JSON for security
type badgerUser struct {
	ID           uint      `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"` // Include in BadgerDB storage
	PasswordSalt string    `json:"password_salt"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

type badgerWallet struct {
	ID                uint      `json:"id"`
	UserID            uint      `json:"user_id"`
	Name              string    `json:"name"`
	Address           string    `json:"address"`
	PublicKey         string    `json:"public_key"`
	WalletType        string    `json:"wallet_type"`
	Status            string    `json:"status"`
	KeyVersion        int       `json:"key_version"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	LastAccessedAt    *time.Time `json:"last_accessed_at,omitempty"`
}

type badgerTransaction struct {
	ID              uint           `json:"id"`
	UserID          uint           `json:"user_id"`
	WalletID        *uint          `json:"wallet_id,omitempty"`
	TxHash          string         `json:"tx_hash"`
	Type            string         `json:"type"`
	Status          string         `json:"status"`
	FromAddress     string         `json:"from_address"`
	ToAddress       string         `json:"to_address"`
	TokenSymbol     string         `json:"token_symbol"`
	Amount          string         `json:"amount"`
	Fee             string         `json:"fee,omitempty"`
	BlockHeight     *uint64        `json:"block_height,omitempty"`
	BlockHash       string         `json:"block_hash,omitempty"`
	Confirmations   int            `json:"confirmations"`
	Nonce           uint64         `json:"nonce"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	CompletedAt     *time.Time     `json:"completed_at,omitempty"`
}

type badgerSession struct {
	ID        uint      `json:"id"`
	UserID    uint      `json:"user_id"`
	SessionID string    `json:"session_id"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Conversion functions
func toBadgerUser(u *User) *badgerUser {
	return &badgerUser{
		ID:           u.ID,
		Username:     u.Username,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		PasswordSalt: u.PasswordSalt,
		Status:       u.Status,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
		LastLoginAt:  u.LastLoginAt,
	}
}

func fromBadgerUser(bu *badgerUser) *User {
	return &User{
		ID:           bu.ID,
		Username:     bu.Username,
		Email:        bu.Email,
		PasswordHash: bu.PasswordHash,
		PasswordSalt: bu.PasswordSalt,
		Status:       bu.Status,
		CreatedAt:    bu.CreatedAt,
		UpdatedAt:    bu.UpdatedAt,
		LastLoginAt:  bu.LastLoginAt,
	}
}

// BadgerService provides BadgerDB operations as fallback for PostgreSQL
type BadgerService struct {
	db *badger.DB
}

// NewBadgerService creates a new BadgerDB service
func NewBadgerService(db *badger.DB) *BadgerService {
	return &BadgerService{db: db}
}

// User operations in BadgerDB
func (bs *BadgerService) CreateUser(ctx context.Context, user *User) error {
	return bs.db.Update(func(txn *badger.Txn) error {
		// Check if username already exists
		userKey := fmt.Sprintf("user:username:%s", user.Username)
		_, err := txn.Get([]byte(userKey))
		if err == nil {
			return fmt.Errorf("username already exists")
		}
		if err != badger.ErrKeyNotFound {
			return err
		}

		// Generate ID if not set
		if user.ID == 0 {
			id, err := bs.getNextID(txn, "user_id_counter")
			if err != nil {
				return err
			}
			user.ID = uint(id)
		}

		// Set timestamps
		now := time.Now().UTC()
		user.CreatedAt = now
		user.UpdatedAt = now

		// Convert to BadgerDB format and serialize user
		badgerUser := toBadgerUser(user)
		userData, err := json.Marshal(badgerUser)
		if err != nil {
			return err
		}

		// Store user by ID
		userIDKey := fmt.Sprintf("user:id:%d", user.ID)
		if err := txn.Set([]byte(userIDKey), userData); err != nil {
			return err
		}

		// Store username -> ID mapping
		idBytes := []byte(strconv.FormatUint(uint64(user.ID), 10))
		return txn.Set([]byte(userKey), idBytes)
	})
}

func (bs *BadgerService) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	err := bs.db.View(func(txn *badger.Txn) error {
		// Get user ID from username
		userKey := fmt.Sprintf("user:username:%s", username)
		item, err := txn.Get([]byte(userKey))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return fmt.Errorf("user not found")
			}
			return err
		}

		var userIDBytes []byte
		err = item.Value(func(val []byte) error {
			userIDBytes = append([]byte(nil), val...)
			return nil
		})
		if err != nil {
			return err
		}

		userID, err := strconv.ParseUint(string(userIDBytes), 10, 64)
		if err != nil {
			return err
		}

		// Get user data by ID
		userIDKey := fmt.Sprintf("user:id:%d", userID)
		item, err = txn.Get([]byte(userIDKey))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			var badgerUser badgerUser
			err := json.Unmarshal(val, &badgerUser)
			if err == nil {
				user = *fromBadgerUser(&badgerUser)
			}
			return err
		})
	})
	return &user, err
}

func (bs *BadgerService) GetUserByID(ctx context.Context, userID uint) (*User, error) {
	var user User
	err := bs.db.View(func(txn *badger.Txn) error {
		userIDKey := fmt.Sprintf("user:id:%d", userID)
		item, err := txn.Get([]byte(userIDKey))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return fmt.Errorf("user not found")
			}
			return err
		}

		return item.Value(func(val []byte) error {
			var badgerUser badgerUser
			err := json.Unmarshal(val, &badgerUser)
			if err == nil {
				user = *fromBadgerUser(&badgerUser)
			}
			return err
		})
	})
	return &user, err
}

// Wallet operations in BadgerDB
func (bs *BadgerService) CreateWallet(ctx context.Context, wallet *Wallet) error {
	return bs.db.Update(func(txn *badger.Txn) error {
		// Check if wallet address already exists
		addrKey := fmt.Sprintf("wallet:address:%s", wallet.Address)
		_, err := txn.Get([]byte(addrKey))
		if err == nil {
			return fmt.Errorf("wallet address already exists")
		}
		if err != badger.ErrKeyNotFound {
			return err
		}

		// Generate ID if not set
		if wallet.ID == 0 {
			id, err := bs.getNextID(txn, "wallet_id_counter")
			if err != nil {
				return err
			}
			wallet.ID = uint(id)
		}

		// Set timestamps
		now := time.Now().UTC()
		wallet.CreatedAt = now
		wallet.UpdatedAt = now

		// Serialize wallet
		walletData, err := json.Marshal(wallet)
		if err != nil {
			return err
		}

		// Store wallet by ID
		walletIDKey := fmt.Sprintf("wallet:id:%d", wallet.ID)
		if err := txn.Set([]byte(walletIDKey), walletData); err != nil {
			return err
		}

		// Store address -> ID mapping
		idBytes := []byte(strconv.FormatUint(uint64(wallet.ID), 10))
		if err := txn.Set([]byte(addrKey), idBytes); err != nil {
			return err
		}

		// Store user wallet mapping
		userWalletsKey := fmt.Sprintf("user_wallets:%d:%d", wallet.UserID, wallet.ID)
		return txn.Set([]byte(userWalletsKey), []byte("1"))
	})
}

func (bs *BadgerService) GetUserWallets(ctx context.Context, userID uint) ([]Wallet, error) {
	var wallets []Wallet
	err := bs.db.View(func(txn *badger.Txn) error {
		prefix := fmt.Sprintf("user_wallets:%d:", userID)
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek([]byte(prefix)); it.ValidForPrefix([]byte(prefix)); it.Next() {
			key := string(it.Item().Key())
			// Extract wallet ID from key: user_wallets:userID:walletID
			parts := strings.Split(key, ":")
			if len(parts) != 3 {
				continue
			}

			walletID, err := strconv.ParseUint(parts[2], 10, 64)
			if err != nil {
				continue
			}

			// Get wallet data
			walletIDKey := fmt.Sprintf("wallet:id:%d", walletID)
			item, err := txn.Get([]byte(walletIDKey))
			if err != nil {
				continue
			}

			var wallet Wallet
			err = item.Value(func(val []byte) error {
				return json.Unmarshal(val, &wallet)
			})
			if err == nil {
				wallets = append(wallets, wallet)
			}
		}
		return nil
	})
	return wallets, err
}

func (bs *BadgerService) GetWalletByAddress(ctx context.Context, address string) (*Wallet, error) {
	var wallet Wallet
	err := bs.db.View(func(txn *badger.Txn) error {
		// Get wallet ID from address
		addrKey := fmt.Sprintf("wallet:address:%s", address)
		item, err := txn.Get([]byte(addrKey))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return fmt.Errorf("wallet not found")
			}
			return err
		}

		var walletIDBytes []byte
		err = item.Value(func(val []byte) error {
			walletIDBytes = append([]byte(nil), val...)
			return nil
		})
		if err != nil {
			return err
		}

		walletID, err := strconv.ParseUint(string(walletIDBytes), 10, 64)
		if err != nil {
			return err
		}

		// Get wallet data by ID
		walletIDKey := fmt.Sprintf("wallet:id:%d", walletID)
		item, err = txn.Get([]byte(walletIDKey))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &wallet)
		})
	})
	return &wallet, err
}

// Transaction operations in BadgerDB
func (bs *BadgerService) CreateTransaction(ctx context.Context, tx *Transaction) error {
	return bs.db.Update(func(txn *badger.Txn) error {
		// Check if transaction hash already exists
		hashKey := fmt.Sprintf("transaction:hash:%s", tx.TxHash)
		_, err := txn.Get([]byte(hashKey))
		if err == nil {
			return fmt.Errorf("transaction hash already exists")
		}
		if err != badger.ErrKeyNotFound {
			return err
		}

		// Generate ID if not set
		if tx.ID == 0 {
			id, err := bs.getNextID(txn, "transaction_id_counter")
			if err != nil {
				return err
			}
			tx.ID = uint(id)
		}

		// Set timestamps
		now := time.Now().UTC()
		tx.CreatedAt = now
		tx.UpdatedAt = now

		// Serialize transaction
		txData, err := json.Marshal(tx)
		if err != nil {
			return err
		}

		// Store transaction by ID
		txIDKey := fmt.Sprintf("transaction:id:%d", tx.ID)
		if err := txn.Set([]byte(txIDKey), txData); err != nil {
			return err
		}

		// Store hash -> ID mapping
		idBytes := []byte(strconv.FormatUint(uint64(tx.ID), 10))
		if err := txn.Set([]byte(hashKey), idBytes); err != nil {
			return err
		}

		// Store user transaction mapping
		userTxKey := fmt.Sprintf("user_transactions:%d:%d", tx.UserID, tx.ID)
		return txn.Set([]byte(userTxKey), []byte("1"))
	})
}

func (bs *BadgerService) GetUserTransactions(ctx context.Context, userID uint, limit int) ([]Transaction, error) {
	var transactions []Transaction
	err := bs.db.View(func(txn *badger.Txn) error {
		prefix := fmt.Sprintf("user_transactions:%d:", userID)
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		count := 0
		for it.Seek([]byte(prefix)); it.ValidForPrefix([]byte(prefix)) && (limit == 0 || count < limit); it.Next() {
			key := string(it.Item().Key())
			// Extract transaction ID from key: user_transactions:userID:txID
			parts := strings.Split(key, ":")
			if len(parts) != 3 {
				continue
			}

			txID, err := strconv.ParseUint(parts[2], 10, 64)
			if err != nil {
				continue
			}

			// Get transaction data
			txIDKey := fmt.Sprintf("transaction:id:%d", txID)
			item, err := txn.Get([]byte(txIDKey))
			if err != nil {
				continue
			}

			var tx Transaction
			err = item.Value(func(val []byte) error {
				return json.Unmarshal(val, &tx)
			})
			if err == nil {
				transactions = append(transactions, tx)
				count++
			}
		}
		return nil
	})
	return transactions, err
}

// Session operations in BadgerDB
func (bs *BadgerService) CreateSession(ctx context.Context, session *Session) error {
	return bs.db.Update(func(txn *badger.Txn) error {
		// Generate ID if not set
		if session.ID == 0 {
			id, err := bs.getNextID(txn, "session_id_counter")
			if err != nil {
				return err
			}
			session.ID = uint(id)
		}

		// Set timestamps
		now := time.Now().UTC()
		session.CreatedAt = now
		session.UpdatedAt = now

		// Serialize session
		sessionData, err := json.Marshal(session)
		if err != nil {
			return err
		}

		// Store session by ID
		sessionIDKey := fmt.Sprintf("session:id:%d", session.ID)
		if err := txn.Set([]byte(sessionIDKey), sessionData); err != nil {
			return err
		}

		// Store session ID -> ID mapping
		sessionKey := fmt.Sprintf("session:token:%s", session.SessionID)
		idBytes := []byte(strconv.FormatUint(uint64(session.ID), 10))
		return txn.Set([]byte(sessionKey), idBytes)
	})
}

func (bs *BadgerService) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	var session Session
	err := bs.db.View(func(txn *badger.Txn) error {
		// Get session ID from token
		sessionKey := fmt.Sprintf("session:token:%s", sessionID)
		item, err := txn.Get([]byte(sessionKey))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return fmt.Errorf("session not found")
			}
			return err
		}

		var sessionIDBytes []byte
		err = item.Value(func(val []byte) error {
			sessionIDBytes = append([]byte(nil), val...)
			return nil
		})
		if err != nil {
			return err
		}

		internalID, err := strconv.ParseUint(string(sessionIDBytes), 10, 64)
		if err != nil {
			return err
		}

		// Get session data by ID
		sessionIDKey := fmt.Sprintf("session:id:%d", internalID)
		item, err = txn.Get([]byte(sessionIDKey))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &session)
		})
	})

	// Check if session is expired
	if err == nil && session.ExpiresAt.Before(time.Now().UTC()) {
		bs.DeleteSession(ctx, sessionID) // Clean up expired session
		return nil, fmt.Errorf("session expired")
	}

	return &session, err
}

func (bs *BadgerService) DeleteSession(ctx context.Context, sessionID string) error {
	return bs.db.Update(func(txn *badger.Txn) error {
		sessionKey := fmt.Sprintf("session:token:%s", sessionID)
		
		// Get internal session ID first
		item, err := txn.Get([]byte(sessionKey))
		if err != nil {
			return err // Already deleted or doesn't exist
		}

		var sessionIDBytes []byte
		err = item.Value(func(val []byte) error {
			sessionIDBytes = append([]byte(nil), val...)
			return nil
		})
		if err != nil {
			return err
		}

		internalID, err := strconv.ParseUint(string(sessionIDBytes), 10, 64)
		if err != nil {
			return err
		}

		// Delete both mappings
		sessionIDKey := fmt.Sprintf("session:id:%d", internalID)
		if err := txn.Delete([]byte(sessionIDKey)); err != nil {
			return err
		}
		return txn.Delete([]byte(sessionKey))
	})
}

// Helper function to generate sequential IDs
func (bs *BadgerService) getNextID(txn *badger.Txn, counterKey string) (uint64, error) {
	item, err := txn.Get([]byte(counterKey))
	if err == badger.ErrKeyNotFound {
		// Initialize counter
		if err := txn.Set([]byte(counterKey), []byte("1")); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if err != nil {
		return 0, err
	}

	var currentIDBytes []byte
	err = item.Value(func(val []byte) error {
		currentIDBytes = append([]byte(nil), val...)
		return nil
	})
	if err != nil {
		return 0, err
	}

	currentID, err := strconv.ParseUint(string(currentIDBytes), 10, 64)
	if err != nil {
		return 0, err
	}

	nextID := currentID + 1
	nextIDBytes := []byte(strconv.FormatUint(nextID, 10))
	if err := txn.Set([]byte(counterKey), nextIDBytes); err != nil {
		return 0, err
	}

	return nextID, nil
}