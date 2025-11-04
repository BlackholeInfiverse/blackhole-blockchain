package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Service provides high-level storage operations with fallback support
type Service struct {
	manager     *StorageManager
	badgerSvc   *BadgerService
	usePostgres bool
}

// NewService creates a new storage service
func NewService(manager *StorageManager) *Service {
	svc := &Service{
		manager:     manager,
		usePostgres: manager.PostgreSQL != nil,
	}

	if manager.BadgerDB != nil {
		svc.badgerSvc = NewBadgerService(manager.BadgerDB)
	}

	return svc
}

// Authentication methods
func (s *Service) CreateUser(ctx context.Context, username, email, password string) (*User, error) {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
		PasswordSalt: "", // bcrypt handles its own salting
		Status:       "active",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if s.usePostgres {
		err = s.manager.PostgreSQL.Create(user).Error
		if err != nil {
			return nil, fmt.Errorf("failed to create user in postgres: %w", err)
		}
		
		// Cache in Redis if available
		if s.manager.Redis != nil {
			s.cacheUser(user)
		}
	} else if s.badgerSvc != nil {
		err = s.badgerSvc.CreateUser(ctx, user)
		if err != nil {
			return nil, fmt.Errorf("failed to create user in badger: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no storage backend available")
	}

	// Don't return password hash in response
	user.PasswordHash = ""
	return user, nil
}

func (s *Service) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	var user *User
	var err error

	// For authentication, we always need to fetch from storage to get the password hash
	// Cached users don't have password hashes for security reasons
	if s.usePostgres {
		user = &User{}
		err = s.manager.PostgreSQL.Where("username = ? AND status = ?", username, "active").First(user).Error
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
	} else if s.badgerSvc != nil {
		user, err = s.badgerSvc.GetUserByUsername(ctx, username)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("no storage backend available")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	// Don't return password hash
	user.PasswordHash = ""
	return user, nil
}

func (s *Service) GetUserByID(ctx context.Context, userID uint) (*User, error) {
	var user *User
	var err error

	if s.usePostgres {
		user = &User{}
		err = s.manager.PostgreSQL.Where("id = ? AND status = ?", userID, "active").First(user).Error
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
	} else if s.badgerSvc != nil {
		user, err = s.badgerSvc.GetUserByID(ctx, userID)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("no storage backend available")
	}

	// Don't return password hash
	user.PasswordHash = ""
	return user, nil
}

// Wallet methods
func (s *Service) CreateWallet(ctx context.Context, userID uint, address, name, walletType, publicKey string) (*Wallet, error) {
	wallet := &Wallet{
		UserID:               userID,
		Address:              address,
		Name:                 name,
		PublicKey:            publicKey,
		WalletType:           walletType,
		Status:               "active",
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
	}

	if s.usePostgres {
		err := s.manager.PostgreSQL.Create(wallet).Error
		if err != nil {
			return nil, fmt.Errorf("failed to create wallet: %w", err)
		}

		// Cache wallet in Redis if available
		if s.manager.Redis != nil {
			// We'll cache the wallet itself, not balance since there's no balance field
		}
	} else if s.badgerSvc != nil {
		err := s.badgerSvc.CreateWallet(ctx, wallet)
		if err != nil {
			return nil, fmt.Errorf("failed to create wallet in badger: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no storage backend available")
	}

	return wallet, nil
}

func (s *Service) GetUserWallets(ctx context.Context, userID uint) ([]Wallet, error) {
	var wallets []Wallet
	var err error

	if s.usePostgres {
		err = s.manager.PostgreSQL.Where("user_id = ? AND status = ?", userID, "active").Find(&wallets).Error
		if err != nil {
			return nil, fmt.Errorf("failed to get user wallets: %w", err)
		}
	} else if s.badgerSvc != nil {
		wallets, err = s.badgerSvc.GetUserWallets(ctx, userID)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("no storage backend available")
	}

	return wallets, nil
}

func (s *Service) GetWalletByAddress(ctx context.Context, address string) (*Wallet, error) {
	var wallet *Wallet
	var err error

	if s.usePostgres {
		wallet = &Wallet{}
		err = s.manager.PostgreSQL.Where("address = ? AND status = ?", address, "active").First(wallet).Error
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("wallet not found")
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get wallet: %w", err)
		}
	} else if s.badgerSvc != nil {
		wallet, err = s.badgerSvc.GetWalletByAddress(ctx, address)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("no storage backend available")
	}

	return wallet, nil
}

// Note: Wallet balance is not stored in the wallet table, it would be calculated from transactions
// func (s *Service) UpdateWalletBalance(ctx context.Context, address string, balance float64) error {
//     // Balance would be calculated from transaction history rather than stored
//     return fmt.Errorf("wallet balance is calculated from transactions, not stored directly")
// }

// Transaction methods
func (s *Service) CreateTransaction(ctx context.Context, userID uint, txHash, fromAddr, toAddr, txType, tokenSymbol, amount, status string) (*Transaction, error) {
	tx := &Transaction{
		UserID:      userID,
		TxHash:      txHash,
		FromAddress: fromAddr,
		ToAddress:   toAddr,
		Amount:      amount,
		Type:        txType,
		TokenSymbol: tokenSymbol,
		Status:      status,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	if s.usePostgres {
		err := s.manager.PostgreSQL.Create(tx).Error
		if err != nil {
			return nil, fmt.Errorf("failed to create transaction: %w", err)
		}
	} else if s.badgerSvc != nil {
		err := s.badgerSvc.CreateTransaction(ctx, tx)
		if err != nil {
			return nil, fmt.Errorf("failed to create transaction in badger: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no storage backend available")
	}

	return tx, nil
}

func (s *Service) GetUserTransactions(ctx context.Context, userID uint, limit int) ([]Transaction, error) {
	var transactions []Transaction
	var err error

	if s.usePostgres {
		query := s.manager.PostgreSQL.Where("user_id = ?", userID).Order("created_at DESC")
		if limit > 0 {
			query = query.Limit(limit)
		}
		err = query.Find(&transactions).Error
		if err != nil {
			return nil, fmt.Errorf("failed to get user transactions: %w", err)
		}
	} else if s.badgerSvc != nil {
		transactions, err = s.badgerSvc.GetUserTransactions(ctx, userID, limit)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("no storage backend available")
	}

	return transactions, nil
}

// Session methods
func (s *Service) CreateSession(ctx context.Context, userID uint) (*Session, error) {
	// Generate session ID
	sessionBytes := make([]byte, 32)
	if _, err := rand.Read(sessionBytes); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	sessionID := hex.EncodeToString(sessionBytes)

	// Session expires in 24 hours
	expiresAt := time.Now().UTC().Add(24 * time.Hour)

	session := &Session{
		SessionID: sessionID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if s.usePostgres {
		err := s.manager.PostgreSQL.Create(session).Error
		if err != nil {
			return nil, fmt.Errorf("failed to create session: %w", err)
		}

		// Cache session in Redis with TTL
		if s.manager.Redis != nil {
			s.cacheSession(session)
		}
	} else if s.badgerSvc != nil {
		err := s.badgerSvc.CreateSession(ctx, session)
		if err != nil {
			return nil, fmt.Errorf("failed to create session in badger: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no storage backend available")
	}

	return session, nil
}

func (s *Service) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	var session *Session
	var err error

	// Check cache first if Redis is available
	if s.manager.Redis != nil {
		session = s.getCachedSession(sessionID)
		if session != nil {
			return session, nil
		}
	}

	// If not in cache, fetch from primary storage
	if s.usePostgres {
		session = &Session{}
		err = s.manager.PostgreSQL.Where("session_id = ? AND expires_at > ?", 
			sessionID, time.Now().UTC()).First(session).Error
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("session not found or expired")
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get session: %w", err)
		}

		// Cache the session
		if s.manager.Redis != nil {
			s.cacheSession(session)
		}
	} else if s.badgerSvc != nil {
		session, err = s.badgerSvc.GetSession(ctx, sessionID)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("no storage backend available")
	}

	return session, nil
}

func (s *Service) DeleteSession(ctx context.Context, sessionID string) error {
	if s.usePostgres {
		err := s.manager.PostgreSQL.Where("session_id = ?", sessionID).Delete(&Session{}).Error
		if err != nil {
			return fmt.Errorf("failed to delete session: %w", err)
		}

		// Remove from cache
		if s.manager.Redis != nil {
			s.removeCachedSession(sessionID)
		}
	} else if s.badgerSvc != nil {
		err := s.badgerSvc.DeleteSession(ctx, sessionID)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no storage backend available")
	}

	return nil
}

// Audit logging
func (s *Service) LogUserAction(ctx context.Context, userID uint, action, details string) error {
	if !s.usePostgres {
		// Skip audit logging for BadgerDB fallback to keep it simple
		log.Printf("AUDIT: User %d performed action: %s - %s", userID, action, details)
		return nil
	}

	auditLog := &AuditLog{
		UserID:    &userID,
		Action:    action,
		Resource:  "user", // default resource type
		Details:   JSON{"description": details},
		Status:    "success",
		IPAddress: s.getClientIP(ctx),
		CreatedAt: time.Now().UTC(),
	}

	err := s.manager.PostgreSQL.Create(auditLog).Error
	if err != nil {
		log.Printf("Failed to create audit log: %v", err)
		// Don't fail the main operation due to audit logging failure
	}

	return nil
}

// Health check methods
func (s *Service) HealthCheck(ctx context.Context) map[string]string {
	status := make(map[string]string)

	// Check PostgreSQL
	if s.manager.PostgreSQL != nil {
		health := s.manager.HealthCheck(ctx)
		if health["postgres"] != nil {
			status["postgres"] = fmt.Sprintf("unhealthy: %v", health["postgres"])
		} else {
			status["postgres"] = "healthy"
		}
	} else {
		status["postgres"] = "not configured"
	}

	// Check Redis
	if s.manager.Redis != nil {
		health := s.manager.HealthCheck(ctx)
		if health["redis"] != nil {
			status["redis"] = fmt.Sprintf("unhealthy: %v", health["redis"])
		} else {
			status["redis"] = "healthy"
		}
	} else {
		status["redis"] = "not configured"
	}

	// Check BadgerDB
	if s.manager.BadgerDB != nil {
		status["badger"] = "healthy"
	} else {
		status["badger"] = "not configured"
	}

	return status
}

// Close closes all storage connections
func (s *Service) Close() error {
	return s.manager.Close()
}

// Helper method to get client IP from context
func (s *Service) getClientIP(ctx context.Context) string {
	if ip := ctx.Value("client_ip"); ip != nil {
		if ipStr, ok := ip.(string); ok {
			return ipStr
		}
	}
	return "unknown"
}

