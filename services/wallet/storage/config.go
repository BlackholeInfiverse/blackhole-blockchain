package storage

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/go-redis/redis/v8"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// StorageConfig holds configuration for all storage systems
type StorageConfig struct {
	PostgreSQL PostgreSQLConfig
	Redis      RedisConfig
	BadgerDB   BadgerDBConfig
}

type PostgreSQLConfig struct {
	Host     string
	Port     int
	Database string
	Username string
	Password string
	SSLMode  string
}

type RedisConfig struct {
	Address  string
	Password string
	DB       int
}

type BadgerDBConfig struct {
	Path       string
	InMemory   bool
	Encryption bool
}

// Storage manager that coordinates all storage systems
type StorageManager struct {
	PostgreSQL *gorm.DB
	Redis      *redis.Client
	BadgerDB   *badger.DB
	Config     *StorageConfig
}

// LoadConfigFromEnv loads configuration from environment variables
func LoadConfigFromEnv() *StorageConfig {
	config := &StorageConfig{
		PostgreSQL: PostgreSQLConfig{
			Host:     getEnv("POSTGRES_HOST", "localhost"),
			Port:     getEnvInt("POSTGRES_PORT", 5432),
			Database: getEnv("POSTGRES_DB", "blackhole_wallet"),
			Username: getEnv("POSTGRES_USER", "postgres"),
			Password: getEnv("POSTGRES_PASSWORD", "password"),
			SSLMode:  getEnv("POSTGRES_SSL_MODE", "disable"),
		},
		Redis: RedisConfig{
			Address:  getEnv("REDIS_ADDRESS", "localhost:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
		},
		BadgerDB: BadgerDBConfig{
			Path:       getEnv("BADGER_PATH", "./data/badger"),
			InMemory:   getEnvBool("BADGER_IN_MEMORY", false),
			Encryption: getEnvBool("BADGER_ENCRYPTION", true),
		},
	}
	return config
}

// NewStorageManager initializes all storage systems with graceful fallbacks
func NewStorageManager(config *StorageConfig) (*StorageManager, error) {
	sm := &StorageManager{Config: config}

	// Initialize BadgerDB first (always required)
	if err := sm.initBadgerDB(); err != nil {
		return nil, fmt.Errorf("failed to initialize BadgerDB: %w", err)
	}

	// Try to initialize PostgreSQL (optional for development)
	if err := sm.initPostgreSQL(); err != nil {
		log.Printf("⚠️ Warning: PostgreSQL not available, using BadgerDB only: %v", err)
		sm.PostgreSQL = nil
	} else {
		// Auto-migrate database schemas only if PostgreSQL is available
		if err := sm.autoMigrate(); err != nil {
			log.Printf("⚠️ Warning: Failed to auto-migrate schemas: %v", err)
		}
	}

	// Try to initialize Redis (optional for development)
	if err := sm.initRedis(); err != nil {
		log.Printf("⚠️ Warning: Redis not available, caching disabled: %v", err)
		sm.Redis = nil
	}

	return sm, nil
}

func (sm *StorageManager) initPostgreSQL() error {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=UTC",
		sm.Config.PostgreSQL.Host,
		sm.Config.PostgreSQL.Username,
		sm.Config.PostgreSQL.Password,
		sm.Config.PostgreSQL.Database,
		sm.Config.PostgreSQL.Port,
		sm.Config.PostgreSQL.SSLMode,
	)

	var err error
	sm.PostgreSQL, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})

	if err != nil {
		return err
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	sqlDB, err := sm.PostgreSQL.DB()
	if err != nil {
		return err
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		return err
	}

	// Configure connection pool
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return nil
}

func (sm *StorageManager) initRedis() error {
	sm.Redis = redis.NewClient(&redis.Options{
		Addr:         sm.Config.Redis.Address,
		Password:     sm.Config.Redis.Password,
		DB:           sm.Config.Redis.DB,
		PoolSize:     10,
		MinIdleConns: 2,
		MaxRetries:   2,
	})

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := sm.Redis.Ping(ctx).Err(); err != nil {
		return err
	}

	return nil
}

func (sm *StorageManager) initBadgerDB() error {
	opts := badger.DefaultOptions(sm.Config.BadgerDB.Path)
	
	if sm.Config.BadgerDB.InMemory {
		opts = opts.WithInMemory(true)
	}
	
	if sm.Config.BadgerDB.Encryption {
		// Enable encryption (requires encryption key)
		encKey := []byte(getEnv("BADGER_ENCRYPTION_KEY", "your-32-byte-encryption-key-here"))
		if len(encKey) >= 32 {
			opts = opts.WithEncryptionKey(encKey[:32])
		}
	}

	opts = opts.WithLogger(&BadgerLogger{})

	var err error
	sm.BadgerDB, err = badger.Open(opts)
	return err
}

func (sm *StorageManager) autoMigrate() error {
	if sm.PostgreSQL == nil {
		return nil
	}
	
	// Auto-migrate all models
	return sm.PostgreSQL.AutoMigrate(
		&User{},
		&Wallet{},
		&Transaction{},
		&Session{},
		&AuditLog{},
		&APIKey{},
	)
}

// IsPostgreSQLAvailable checks if PostgreSQL is available
func (sm *StorageManager) IsPostgreSQLAvailable() bool {
	return sm.PostgreSQL != nil
}

// IsRedisAvailable checks if Redis is available
func (sm *StorageManager) IsRedisAvailable() bool {
	return sm.Redis != nil
}

// Close gracefully closes all storage connections
func (sm *StorageManager) Close() error {
	var errors []error

	// Close PostgreSQL
	if sm.PostgreSQL != nil {
		if sqlDB, err := sm.PostgreSQL.DB(); err == nil {
			if err := sqlDB.Close(); err != nil {
				errors = append(errors, fmt.Errorf("PostgreSQL close error: %w", err))
			}
		}
	}

	// Close Redis
	if sm.Redis != nil {
		if err := sm.Redis.Close(); err != nil {
			errors = append(errors, fmt.Errorf("Redis close error: %w", err))
		}
	}

	// Close BadgerDB
	if sm.BadgerDB != nil {
		if err := sm.BadgerDB.Close(); err != nil {
			errors = append(errors, fmt.Errorf("BadgerDB close error: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("multiple close errors: %v", errors)
	}

	return nil
}

// Health check for all storage systems
func (sm *StorageManager) HealthCheck(ctx context.Context) map[string]error {
	health := make(map[string]error)

	// PostgreSQL health check
	if sm.PostgreSQL != nil {
		if sqlDB, err := sm.PostgreSQL.DB(); err == nil {
			health["postgresql"] = sqlDB.PingContext(ctx)
		} else {
			health["postgresql"] = err
		}
	} else {
		health["postgresql"] = fmt.Errorf("PostgreSQL not configured")
	}

	// Redis health check
	if sm.Redis != nil {
		health["redis"] = sm.Redis.Ping(ctx).Err()
	} else {
		health["redis"] = fmt.Errorf("Redis not configured")
	}

	// BadgerDB health check (always healthy if open)
	if sm.BadgerDB.IsClosed() {
		health["badgerdb"] = fmt.Errorf("BadgerDB is closed")
	} else {
		health["badgerdb"] = nil
	}

	return health
}

// Utility functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// Custom BadgerDB logger
type BadgerLogger struct{}

func (l *BadgerLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[BadgerDB ERROR] "+format, args...)
}

func (l *BadgerLogger) Warningf(format string, args ...interface{}) {
	log.Printf("[BadgerDB WARNING] "+format, args...)
}

func (l *BadgerLogger) Infof(format string, args ...interface{}) {
	log.Printf("[BadgerDB INFO] "+format, args...)
}

func (l *BadgerLogger) Debugf(format string, args ...interface{}) {
	// Suppress debug logs in production
	if getEnv("APP_ENV", "production") != "production" {
		log.Printf("[BadgerDB DEBUG] "+format, args...)
	}
}