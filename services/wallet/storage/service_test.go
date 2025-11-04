package storage

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestStorageService(t *testing.T) {
	// Create test storage configuration with unique path
	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	config := &StorageConfig{
		BadgerDB: BadgerDBConfig{
			Path:     "./test_badger_db_" + timestamp,
			InMemory: false,
		},
	}

	// Initialize storage manager
	manager, err := NewStorageManager(config)
	if err != nil {
		t.Fatalf("Failed to create storage manager: %v", err)
	}
	defer manager.Close()

	// Clean up test database
	defer func() {
		os.RemoveAll("./test_badger_db_" + timestamp)
	}()

	// Create service
	service := NewService(manager)
	ctx := context.Background()

	t.Run("User Operations", func(t *testing.T) {
		// Test user creation
		user, err := service.CreateUser(ctx, "testuser1", "test1@example.com", "password123")
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		if user.Username != "testuser1" || user.Email != "test1@example.com" {
			t.Errorf("User data mismatch: got %+v", user)
		}

		// Test user authentication
		authUser, err := service.AuthenticateUser(ctx, "testuser1", "password123")
		if err != nil {
			t.Fatalf("Failed to authenticate user: %v", err)
		}

		if authUser.ID != user.ID {
			t.Errorf("Authenticated user ID mismatch: got %d, want %d", authUser.ID, user.ID)
		}

		// Test wrong password
		_, err = service.AuthenticateUser(ctx, "testuser1", "wrongpassword")
		if err == nil {
			t.Error("Expected authentication to fail with wrong password")
		}

		// Test get user by ID
		fetchedUser, err := service.GetUserByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("Failed to get user by ID: %v", err)
		}

		if fetchedUser.Username != user.Username {
			t.Errorf("Fetched user username mismatch: got %s, want %s", fetchedUser.Username, user.Username)
		}
	})

	t.Run("Wallet Operations", func(t *testing.T) {
		// Create a user first
		user, err := service.CreateUser(ctx, "walletuser2", "wallet2@example.com", "password123")
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Test wallet creation
		wallet, err := service.CreateWallet(ctx, user.ID, "0x1234567890abcdef", "Test Wallet", "ethereum", "0x1234567890abcdef1234567890abcdef12345678")
		if err != nil {
			t.Fatalf("Failed to create wallet: %v", err)
		}

		if wallet.Address != "0x1234567890abcdef" || wallet.UserID != user.ID {
			t.Errorf("Wallet data mismatch: got %+v", wallet)
		}

		// Test get user wallets
		wallets, err := service.GetUserWallets(ctx, user.ID)
		if err != nil {
			t.Fatalf("Failed to get user wallets: %v", err)
		}

		if len(wallets) != 1 || wallets[0].ID != wallet.ID {
			t.Errorf("User wallets mismatch: got %+v", wallets)
		}

		// Test get wallet by address
		fetchedWallet, err := service.GetWalletByAddress(ctx, "0x1234567890abcdef")
		if err != nil {
			t.Fatalf("Failed to get wallet by address: %v", err)
		}

		if fetchedWallet.ID != wallet.ID {
			t.Errorf("Fetched wallet ID mismatch: got %d, want %d", fetchedWallet.ID, wallet.ID)
		}

		// Note: Wallet balance is calculated from transactions, not stored directly
	})

	t.Run("Transaction Operations", func(t *testing.T) {
		// Create a user first
		user, err := service.CreateUser(ctx, "txuser3", "tx3@example.com", "password123")
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Test transaction creation
		tx, err := service.CreateTransaction(ctx, user.ID, "0xabcdef1234567890", "0xfrom", "0xto", "send", "ETH", "50.0", "pending")
		if err != nil {
			t.Fatalf("Failed to create transaction: %v", err)
		}

		if tx.TxHash != "0xabcdef1234567890" || tx.Amount != "50.0" {
			t.Errorf("Transaction data mismatch: got %+v", tx)
		}

		// Test get user transactions
		transactions, err := service.GetUserTransactions(ctx, user.ID, 10)
		if err != nil {
			t.Fatalf("Failed to get user transactions: %v", err)
		}

		if len(transactions) != 1 || transactions[0].ID != tx.ID {
			t.Errorf("User transactions mismatch: got %+v", transactions)
		}
	})

	t.Run("Session Operations", func(t *testing.T) {
		// Create a user first
		user, err := service.CreateUser(ctx, "sessionuser4", "session4@example.com", "password123")
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Test session creation
		session, err := service.CreateSession(ctx, user.ID)
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		if session.UserID != user.ID || session.SessionID == "" {
			t.Errorf("Session data mismatch: got %+v", session)
		}

		// Test get session
		fetchedSession, err := service.GetSession(ctx, session.SessionID)
		if err != nil {
			t.Fatalf("Failed to get session: %v", err)
		}

		if fetchedSession.ID != session.ID {
			t.Errorf("Fetched session ID mismatch: got %d, want %d", fetchedSession.ID, session.ID)
		}

		// Test delete session
		err = service.DeleteSession(ctx, session.SessionID)
		if err != nil {
			t.Fatalf("Failed to delete session: %v", err)
		}

		// Verify session is deleted
		_, err = service.GetSession(ctx, session.SessionID)
		if err == nil {
			t.Error("Expected session to be deleted")
		}
	})

	t.Run("Health Check", func(t *testing.T) {
		health := service.HealthCheck(ctx)
		
		// BadgerDB should be healthy
		if health["badger"] != "healthy" {
			t.Errorf("BadgerDB should be healthy, got: %s", health["badger"])
		}

		// PostgreSQL and Redis should be not configured
		if health["postgres"] != "not configured" {
			t.Errorf("PostgreSQL should be not configured, got: %s", health["postgres"])
		}
		if health["redis"] != "not configured" {
			t.Errorf("Redis should be not configured, got: %s", health["redis"])
		}
	})
}

func TestStorageServiceErrors(t *testing.T) {
	// Create test storage configuration with unique path
	timestamp := strconv.FormatInt(time.Now().UnixNano(), 10)
	config := &StorageConfig{
		BadgerDB: BadgerDBConfig{
			Path:     "./test_badger_db_errors_" + timestamp,
			InMemory: false,
		},
	}

	// Initialize storage manager
	manager, err := NewStorageManager(config)
	if err != nil {
		t.Fatalf("Failed to create storage manager: %v", err)
	}
	defer manager.Close()

	// Clean up test database
	defer func() {
		os.RemoveAll("./test_badger_db_errors_" + timestamp)
	}()

	// Create service
	service := NewService(manager)
	ctx := context.Background()

	t.Run("Duplicate User", func(t *testing.T) {
		// Create first user
		_, err := service.CreateUser(ctx, "duplicate5", "dup5@example.com", "password123")
		if err != nil {
			t.Fatalf("Failed to create first user: %v", err)
		}

		// Try to create duplicate user
		_, err = service.CreateUser(ctx, "duplicate5", "dup25@example.com", "password123")
		if err == nil {
			t.Error("Expected error when creating duplicate user")
		}
	})

	t.Run("Nonexistent User", func(t *testing.T) {
		// Try to authenticate nonexistent user
		_, err := service.AuthenticateUser(ctx, "nonexistent", "password")
		if err == nil {
			t.Error("Expected error when authenticating nonexistent user")
		}

		// Try to get nonexistent user
		_, err = service.GetUserByID(ctx, 999999)
		if err == nil {
			t.Error("Expected error when getting nonexistent user")
		}
	})

	t.Run("Duplicate Wallet", func(t *testing.T) {
		// Create user first
		user, err := service.CreateUser(ctx, "walletowner6", "owner6@example.com", "password123")
		if err != nil {
			t.Fatalf("Failed to create user: %v", err)
		}

		// Create first wallet
		_, err = service.CreateWallet(ctx, user.ID, "0xduplicate", "Wallet 1", "ethereum", "0x1111111111111111111111111111111111111111")
		if err != nil {
			t.Fatalf("Failed to create first wallet: %v", err)
		}

		// Try to create duplicate wallet
		_, err = service.CreateWallet(ctx, user.ID, "0xduplicate", "Wallet 2", "ethereum", "0x2222222222222222222222222222222222222222")
		if err == nil {
			t.Error("Expected error when creating duplicate wallet address")
		}
	})

	t.Run("Nonexistent Wallet", func(t *testing.T) {
		// Try to get nonexistent wallet
		_, err := service.GetWalletByAddress(ctx, "0xnonexistent")
		if err == nil {
			t.Error("Expected error when getting nonexistent wallet")
		}

		// Note: Balance updates are not supported as balance is calculated from transactions
	})
}

// Benchmark tests
func BenchmarkUserCreation(b *testing.B) {
	config := &StorageConfig{
		BadgerDB: BadgerDBConfig{
			Path:     "./bench_badger_db",
			InMemory: false,
		},
	}

	manager, err := NewStorageManager(config)
	if err != nil {
		b.Fatalf("Failed to create storage manager: %v", err)
	}
	defer manager.Close()
	defer os.RemoveAll("./bench_badger_db")

	service := NewService(manager)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		username := fmt.Sprintf("user%d_%d", i, time.Now().UnixNano())
		email := fmt.Sprintf("user%d_%d@example.com", i, time.Now().UnixNano())
		_, err := service.CreateUser(ctx, username, email, "password123")
		if err != nil {
			b.Fatalf("Failed to create user: %v", err)
		}
	}
}

func BenchmarkUserAuthentication(b *testing.B) {
	config := &StorageConfig{
		BadgerDB: BadgerDBConfig{
			Path:     "./bench_auth_badger_db",
			InMemory: false,
		},
	}

	manager, err := NewStorageManager(config)
	if err != nil {
		b.Fatalf("Failed to create storage manager: %v", err)
	}
	defer manager.Close()
	defer os.RemoveAll("./bench_auth_badger_db")

	service := NewService(manager)
	ctx := context.Background()

	// Create a user for authentication
	timestamp := time.Now().UnixNano()
	username := fmt.Sprintf("benchuser_%d", timestamp)
	_, err = service.CreateUser(ctx, username, "bench@example.com", "password123")
	if err != nil {
		b.Fatalf("Failed to create user: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := service.AuthenticateUser(ctx, username, "password123")
		if err != nil {
			b.Fatalf("Failed to authenticate user: %v", err)
		}
	}
}