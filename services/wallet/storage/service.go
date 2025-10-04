package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

// WalletService provides high-level wallet operations with caching
type WalletService struct {
	storage *StorageManager
}

// NewWalletService creates a new wallet service
func NewWalletService(storage *StorageManager) *WalletService {
	return &WalletService{
		storage: storage,
	}
}

// User operations
func (ws *WalletService) CreateUser(ctx context.Context, username, passwordHash, passwordSalt string) (*User, error) {
	user := &User{
		Username:     username,
		PasswordHash: passwordHash,
		PasswordSalt: passwordSalt,
		Status:       "active",
	}

	if err := user.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	err := ws.storage.PostgreSQL.WithContext(ctx).Create(user).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, fmt.Errorf("username already exists")
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Log audit trail
	ws.logAudit(ctx, &user.ID, "CREATE", "user", strconv.FormatUint(uint64(user.ID), 10), nil, "success")

	return user, nil
}

func (ws *WalletService) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	// Try cache first
	cacheKey := fmt.Sprintf("user:username:%s", username)
	cached, err := ws.storage.Redis.Get(ctx, cacheKey).Result()
	if err == nil {
		var user User
		if err := json.Unmarshal([]byte(cached), &user); err == nil {
			return &user, nil
		}
	}

	// Query database
	var user User
	err = ws.storage.PostgreSQL.WithContext(ctx).
		Where("username = ? AND status = ?", username, "active").
		First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Cache result for 15 minutes
	userJSON, _ := json.Marshal(user)
	ws.storage.Redis.Set(ctx, cacheKey, userJSON, 15*time.Minute)

	return &user, nil
}

func (ws *WalletService) UpdateUserLastLogin(ctx context.Context, userID uint) error {
	now := time.Now().UTC()
	err := ws.storage.PostgreSQL.WithContext(ctx).
		Model(&User{}).
		Where("id = ?", userID).
		Update("last_login_at", now).Error

	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	// Invalidate user cache
	ws.invalidateUserCache(ctx, userID)
	return nil
}

// Wallet operations
func (ws *WalletService) CreateWallet(ctx context.Context, userID uint, name, address, publicKey string) (*Wallet, error) {
	wallet := &Wallet{
		UserID:        userID,
		Name:          name,
		Address:       address,
		PublicKey:     publicKey,
		WalletType:    "standard",
		Status:        "active",
		SecurityLevel: "standard",
		KeyVersion:    1,
	}

	if err := wallet.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	err := ws.storage.PostgreSQL.WithContext(ctx).Create(wallet).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			if strings.Contains(err.Error(), "address") {
				return nil, fmt.Errorf("wallet address already exists")
			}
			return nil, fmt.Errorf("wallet with this name already exists for user")
		}
		return nil, fmt.Errorf("failed to create wallet: %w", err)
	}

	// Log audit trail
	ws.logAudit(ctx, &userID, "CREATE", "wallet", strconv.FormatUint(uint64(wallet.ID), 10), 
		map[string]interface{}{"wallet_name": name, "address": address}, "success")

	// Invalidate user wallets cache
	ws.invalidateUserWalletsCache(ctx, userID)

	return wallet, nil
}

func (ws *WalletService) GetUserWallets(ctx context.Context, userID uint) ([]Wallet, error) {
	// Try cache first
	cacheKey := fmt.Sprintf("user:wallets:%d", userID)
	cached, err := ws.storage.Redis.Get(ctx, cacheKey).Result()
	if err == nil {
		var wallets []Wallet
		if err := json.Unmarshal([]byte(cached), &wallets); err == nil {
			return wallets, nil
		}
	}

	// Query database
	var wallets []Wallet
	err = ws.storage.PostgreSQL.WithContext(ctx).
		Where("user_id = ? AND status = ?", userID, "active").
		Order("created_at DESC").
		Find(&wallets).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get user wallets: %w", err)
	}

	// Cache result for 5 minutes
	walletsJSON, _ := json.Marshal(wallets)
	ws.storage.Redis.Set(ctx, cacheKey, walletsJSON, 5*time.Minute)

	return wallets, nil
}

func (ws *WalletService) GetWalletByAddress(ctx context.Context, address string) (*Wallet, error) {
	// Try cache first
	cacheKey := fmt.Sprintf("wallet:address:%s", address)
	cached, err := ws.storage.Redis.Get(ctx, cacheKey).Result()
	if err == nil {
		var wallet Wallet
		if err := json.Unmarshal([]byte(cached), &wallet); err == nil {
			return &wallet, nil
		}
	}

	// Query database
	var wallet Wallet
	err = ws.storage.PostgreSQL.WithContext(ctx).
		Where("address = ? AND status = ?", address, "active").
		First(&wallet).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("wallet not found")
		}
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}

	// Cache result for 10 minutes
	walletJSON, _ := json.Marshal(wallet)
	ws.storage.Redis.Set(ctx, cacheKey, walletJSON, 10*time.Minute)

	return &wallet, nil
}

// Transaction operations
func (ws *WalletService) CreateTransaction(ctx context.Context, userID uint, walletID *uint, 
	txHash, txType, fromAddr, toAddr, tokenSymbol, amount string) (*Transaction, error) {

	// Validate amount format
	if _, ok := new(big.Int).SetString(amount, 10); !ok {
		return nil, fmt.Errorf("invalid amount format: %s", amount)
	}

	tx := &Transaction{
		UserID:      userID,
		WalletID:    walletID,
		TxHash:      txHash,
		Type:        txType,
		Status:      "pending",
		FromAddress: fromAddr,
		ToAddress:   toAddr,
		TokenSymbol: strings.ToUpper(tokenSymbol),
		Amount:      amount,
		Nonce:       uint64(time.Now().UnixNano()),
	}

	if err := tx.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	err := ws.storage.PostgreSQL.WithContext(ctx).Create(tx).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, fmt.Errorf("transaction hash already exists")
		}
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	// Log audit trail
	ws.logAudit(ctx, &userID, "CREATE", "transaction", txHash,
		map[string]interface{}{"type": txType, "amount": amount, "token": tokenSymbol}, "success")

	// Invalidate user transactions cache
	ws.invalidateUserTransactionsCache(ctx, userID)

	return tx, nil
}

func (ws *WalletService) UpdateTransactionStatus(ctx context.Context, txHash, status string, 
	blockHeight *uint64, confirmations int) error {

	updates := map[string]interface{}{
		"status":        status,
		"confirmations": confirmations,
		"updated_at":    time.Now().UTC(),
	}

	if blockHeight != nil {
		updates["block_height"] = *blockHeight
	}

	if status == "completed" || status == "confirmed" {
		updates["completed_at"] = time.Now().UTC()
	}

	err := ws.storage.PostgreSQL.WithContext(ctx).
		Model(&Transaction{}).
		Where("tx_hash = ?", txHash).
		Updates(updates).Error

	if err != nil {
		return fmt.Errorf("failed to update transaction status: %w", err)
	}

	// Invalidate transaction cache
	ws.invalidateTransactionCache(ctx, txHash)

	return nil
}

func (ws *WalletService) GetUserTransactions(ctx context.Context, userID uint, limit int) ([]Transaction, error) {
	// Try cache first for small limits
	if limit <= 50 {
		cacheKey := fmt.Sprintf("user:transactions:%d:limit:%d", userID, limit)
		cached, err := ws.storage.Redis.Get(ctx, cacheKey).Result()
		if err == nil {
			var transactions []Transaction
			if err := json.Unmarshal([]byte(cached), &transactions); err == nil {
				return transactions, nil
			}
		}
	}

	// Query database
	var transactions []Transaction
	err := ws.storage.PostgreSQL.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&transactions).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get user transactions: %w", err)
	}

	// Cache result for 2 minutes if small result set
	if limit <= 50 {
		cacheKey := fmt.Sprintf("user:transactions:%d:limit:%d", userID, limit)
		txJSON, _ := json.Marshal(transactions)
		ws.storage.Redis.Set(ctx, cacheKey, txJSON, 2*time.Minute)
	}

	return transactions, nil
}

// Balance operations with caching
func (ws *WalletService) CacheBalance(ctx context.Context, address, tokenSymbol string, balance *big.Int, ttl time.Duration) error {
	cacheKey := fmt.Sprintf("balance:%s:%s", address, strings.ToUpper(tokenSymbol))
	return ws.storage.Redis.Set(ctx, cacheKey, balance.String(), ttl).Err()
}

func (ws *WalletService) GetCachedBalance(ctx context.Context, address, tokenSymbol string) (*big.Int, error) {
	cacheKey := fmt.Sprintf("balance:%s:%s", address, strings.ToUpper(tokenSymbol))
	
	result, err := ws.storage.Redis.Get(ctx, cacheKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("balance not cached")
		}
		return nil, err
	}

	balance, ok := new(big.Int).SetString(result, 10)
	if !ok {
		return nil, fmt.Errorf("invalid cached balance format")
	}

	return balance, nil
}

func (ws *WalletService) InvalidateBalanceCache(ctx context.Context, address, tokenSymbol string) error {
	cacheKey := fmt.Sprintf("balance:%s:%s", address, strings.ToUpper(tokenSymbol))
	return ws.storage.Redis.Del(ctx, cacheKey).Err()
}

// Session management
func (ws *WalletService) CreateSession(ctx context.Context, userID uint, sessionID, ipAddress, userAgent string, expiresAt time.Time) error {
	session := &Session{
		UserID:    userID,
		SessionID: sessionID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		ExpiresAt: expiresAt,
	}

	err := ws.storage.PostgreSQL.WithContext(ctx).Create(session).Error
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	// Cache session for quick lookup
	cacheKey := fmt.Sprintf("session:%s", sessionID)
	sessionJSON, _ := json.Marshal(session)
	ws.storage.Redis.Set(ctx, cacheKey, sessionJSON, time.Until(expiresAt))

	return nil
}

func (ws *WalletService) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	// Try cache first
	cacheKey := fmt.Sprintf("session:%s", sessionID)
	cached, err := ws.storage.Redis.Get(ctx, cacheKey).Result()
	if err == nil {
		var session Session
		if err := json.Unmarshal([]byte(cached), &session); err == nil {
			// Check if session is still valid
			if session.ExpiresAt.After(time.Now().UTC()) {
				return &session, nil
			}
		}
	}

	// Query database
	var session Session
	err = ws.storage.PostgreSQL.WithContext(ctx).
		Where("session_id = ? AND expires_at > ?", sessionID, time.Now().UTC()).
		First(&session).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("session not found or expired")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

func (ws *WalletService) DeleteSession(ctx context.Context, sessionID string) error {
	// Delete from database
	err := ws.storage.PostgreSQL.WithContext(ctx).
		Where("session_id = ?", sessionID).
		Delete(&Session{}).Error

	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Remove from cache
	cacheKey := fmt.Sprintf("session:%s", sessionID)
	ws.storage.Redis.Del(ctx, cacheKey)

	return nil
}

// Cleanup operations
func (ws *WalletService) CleanupExpiredSessions(ctx context.Context) error {
	result := ws.storage.PostgreSQL.WithContext(ctx).
		Where("expires_at < ?", time.Now().UTC()).
		Delete(&Session{})

	if result.Error != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", result.Error)
	}

	if result.RowsAffected > 0 {
		fmt.Printf("Cleaned up %d expired sessions\n", result.RowsAffected)
	}

	return nil
}

// Private helper methods
func (ws *WalletService) logAudit(ctx context.Context, userID *uint, action, resource, resourceID string, details map[string]interface{}, status string) {
	auditLog := &AuditLog{
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Status:     status,
	}

	if details != nil {
		auditLog.Details = JSON(details)
	}

	// Log asynchronously to avoid blocking main operations
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ws.storage.PostgreSQL.WithContext(ctx).Create(auditLog)
	}()
}

func (ws *WalletService) invalidateUserCache(ctx context.Context, userID uint) {
	keys := []string{
		fmt.Sprintf("user:id:%d", userID),
		fmt.Sprintf("user:wallets:%d", userID),
	}
	ws.storage.Redis.Del(ctx, keys...)
}

func (ws *WalletService) invalidateUserWalletsCache(ctx context.Context, userID uint) {
	cacheKey := fmt.Sprintf("user:wallets:%d", userID)
	ws.storage.Redis.Del(ctx, cacheKey)
}

func (ws *WalletService) invalidateUserTransactionsCache(ctx context.Context, userID uint) {
	// Use pattern to delete all transaction cache entries for user
	pattern := fmt.Sprintf("user:transactions:%d:*", userID)
	
	// Note: In production, consider using a more efficient cache invalidation strategy
	keys, err := ws.storage.Redis.Keys(ctx, pattern).Result()
	if err == nil && len(keys) > 0 {
		ws.storage.Redis.Del(ctx, keys...)
	}
}

func (ws *WalletService) invalidateTransactionCache(ctx context.Context, txHash string) {
	cacheKey := fmt.Sprintf("transaction:%s", txHash)
	ws.storage.Redis.Del(ctx, cacheKey)
}

// Batch operations for performance
func (ws *WalletService) BatchUpdateTransactionStatuses(ctx context.Context, updates []TransactionUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	// Use database transaction for consistency
	return ws.storage.PostgreSQL.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, update := range updates {
			updateData := map[string]interface{}{
				"status":        update.Status,
				"confirmations": update.Confirmations,
				"updated_at":    time.Now().UTC(),
			}

			if update.BlockHeight != nil {
				updateData["block_height"] = *update.BlockHeight
			}

			if update.Status == "completed" || update.Status == "confirmed" {
				updateData["completed_at"] = time.Now().UTC()
			}

			err := tx.Model(&Transaction{}).
				Where("tx_hash = ?", update.TxHash).
				Updates(updateData).Error

			if err != nil {
				return err
			}
		}
		return nil
	})
}

// TransactionUpdate represents a batch transaction update
type TransactionUpdate struct {
	TxHash        string
	Status        string
	BlockHeight   *uint64
	Confirmations int
}