package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// ValidatedCacheEntry represents a secure cache entry with integrity validation
type ValidatedCacheEntry struct {
	Balance   uint64        `json:"balance"`
	Timestamp time.Time     `json:"timestamp"`
	Checksum  string        `json:"checksum"`
	Source    string        `json:"source"` // "database", "blockchain", "preload"
	Validated bool          `json:"validated"`
	TTL       time.Duration `json:"ttl"`
}

// UserLimits defines per-user cache limitations
type UserLimits struct {
	MaxEntries        int       `json:"max_entries"`
	MaxMemoryBytes    int64     `json:"max_memory_bytes"`
	RequestsPerMinute int       `json:"requests_per_minute"`
	LastRequestTime   time.Time `json:"last_request_time"`
	RequestCount      int       `json:"request_count"`
	ViolationCount    int       `json:"violation_count"`
	BlockedUntil      time.Time `json:"blocked_until"`
}

// UserSpecificCache represents an isolated cache for a single user
type UserSpecificCache struct {
	UserID      string                                     `json:"user_id"`
	Balances    map[string]map[string]*ValidatedCacheEntry `json:"balances"` // address -> token -> entry
	CreatedAt   time.Time                                  `json:"created_at"`
	LastAccess  time.Time                                  `json:"last_access"`
	EntryCount  int                                        `json:"entry_count"`
	MemoryUsage int64                                      `json:"memory_usage"`
	mutex       sync.RWMutex
}

// ProductionBalanceCache is the main secure cache system
type ProductionBalanceCache struct {
	// Core cache storage
	userCaches map[string]*UserSpecificCache
	mutex      sync.RWMutex

	// Security configuration
	encryptionKey   []byte
	maxTotalMemory  int64
	maxUsersInCache int
	defaultTTL      time.Duration
	validationTTL   time.Duration

	// Rate limiting
	globalLimits *UserLimits
	userLimits   map[string]*UserLimits

	// Monitoring
	totalRequests      int64
	cacheHits          int64
	cacheMisses        int64
	securityViolations int64

	// Cleanup
	cleanupInterval time.Duration
	lastCleanup     time.Time
}

// NewProductionBalanceCache creates a new secure cache system
func NewProductionBalanceCache(encryptionKey []byte) *ProductionBalanceCache {
	pbc := &ProductionBalanceCache{
		userCaches:      make(map[string]*UserSpecificCache),
		encryptionKey:   encryptionKey,
		maxTotalMemory:  100 * 1024 * 1024, // 100MB default
		maxUsersInCache: 1000,              // Max 1000 concurrent users
		defaultTTL:      30 * time.Second,  // 30s for UI display
		validationTTL:   5 * time.Second,   // 5s for transaction validation
		userLimits:      make(map[string]*UserLimits),
		cleanupInterval: 60 * time.Second, // Cleanup every minute
		lastCleanup:     time.Now(),
		globalLimits: &UserLimits{
			MaxEntries:        1000,
			MaxMemoryBytes:    10 * 1024 * 1024, // 10MB per user
			RequestsPerMinute: 100,
		},
	}

	// Start background cleanup
	go pbc.startCleanupWorker()

	log.Printf("✅ Production Balance Cache initialized with %dMB memory limit", pbc.maxTotalMemory/(1024*1024))
	return pbc
}

// IsValid checks if a cache entry is valid and not tampered with
func (vce *ValidatedCacheEntry) IsValid(secret string) bool {
	if !vce.Validated {
		return false
	}

	// Check TTL
	if time.Since(vce.Timestamp) > vce.TTL {
		return false
	}

	// Verify integrity checksum
	expectedChecksum := sha256.Sum256([]byte(
		fmt.Sprintf("%d:%d:%s:%s", vce.Balance, vce.Timestamp.Unix(), vce.Source, secret),
	))

	return vce.Checksum == hex.EncodeToString(expectedChecksum[:])
}

// createIntegrityHash creates a secure hash for cache entry validation
func (pbc *ProductionBalanceCache) createIntegrityHash(balance uint64, timestamp time.Time, source string) string {
	hash := sha256.Sum256([]byte(
		fmt.Sprintf("%d:%d:%s:%s", balance, timestamp.Unix(), source, string(pbc.encryptionKey)),
	))
	return hex.EncodeToString(hash[:])
}

// validateUserAccess performs security validation for cache access
func (pbc *ProductionBalanceCache) validateUserAccess(userID, address string) error {
	// Get or create user limits
	limits, exists := pbc.userLimits[userID]
	if !exists {
		limits = &UserLimits{
			MaxEntries:        pbc.globalLimits.MaxEntries,
			MaxMemoryBytes:    pbc.globalLimits.MaxMemoryBytes,
			RequestsPerMinute: pbc.globalLimits.RequestsPerMinute,
			LastRequestTime:   time.Now(),
			RequestCount:      0,
			ViolationCount:    0,
		}
		pbc.userLimits[userID] = limits
	}

	// Check if user is blocked
	if time.Now().Before(limits.BlockedUntil) {
		pbc.securityViolations++
		return errors.New("user temporarily blocked due to suspicious activity")
	}

	// Rate limiting check
	now := time.Now()
	if now.Sub(limits.LastRequestTime) < time.Minute {
		limits.RequestCount++
		if limits.RequestCount > limits.RequestsPerMinute {
			limits.ViolationCount++
			if limits.ViolationCount > 5 {
				// Block user for 1 hour
				limits.BlockedUntil = now.Add(1 * time.Hour)
				log.Printf("🚨 User %s blocked for 1 hour due to rate limit violations", userID)
			}
			pbc.securityViolations++
			return errors.New("rate limit exceeded")
		}
	} else {
		// Reset rate limit counter
		limits.RequestCount = 1
		limits.LastRequestTime = now
	}

	return nil
}

// getUserCache gets or creates an isolated cache for a user
func (pbc *ProductionBalanceCache) getUserCache(userID string) *UserSpecificCache {
	pbc.mutex.Lock()
	defer pbc.mutex.Unlock()

	cache, exists := pbc.userCaches[userID]
	if !exists {
		cache = &UserSpecificCache{
			UserID:      userID,
			Balances:    make(map[string]map[string]*ValidatedCacheEntry),
			CreatedAt:   time.Now(),
			LastAccess:  time.Now(),
			EntryCount:  0,
			MemoryUsage: 0,
		}
		pbc.userCaches[userID] = cache

		// Check if we need to evict old users
		if len(pbc.userCaches) > pbc.maxUsersInCache {
			pbc.evictOldestUser()
		}
	}

	cache.LastAccess = time.Now()
	return cache
}

// GetBalance retrieves a balance with full security validation
func (pbc *ProductionBalanceCache) GetBalance(userID, address, token string, forValidation bool) (uint64, bool, error) {
	pbc.totalRequests++

	// Security validation
	if err := pbc.validateUserAccess(userID, address); err != nil {
		return 0, false, err
	}

	// Get user's isolated cache
	userCache := pbc.getUserCache(userID)
	userCache.mutex.RLock()
	defer userCache.mutex.RUnlock()

	// Check if address exists in user's cache
	if addressBalances, exists := userCache.Balances[address]; exists {
		if entry, exists := addressBalances[token]; exists {
			// Determine TTL based on usage
			ttl := pbc.defaultTTL
			if forValidation {
				ttl = pbc.validationTTL
			}

			// Check if entry is valid with appropriate TTL
			if time.Since(entry.Timestamp) <= ttl && entry.IsValid(string(pbc.encryptionKey)) {
				pbc.cacheHits++
				return entry.Balance, true, nil // Cache hit
			}
		}
	}

	pbc.cacheMisses++
	return 0, false, nil // Cache miss
}

// SetBalance stores a balance in the cache with full validation
func (pbc *ProductionBalanceCache) SetBalance(userID, address, token string, balance uint64, source string) error {
	// Security validation
	if err := pbc.validateUserAccess(userID, address); err != nil {
		return err
	}

	// Get user's isolated cache
	userCache := pbc.getUserCache(userID)
	userCache.mutex.Lock()
	defer userCache.mutex.Unlock()

	// Check user's memory limits
	if userCache.MemoryUsage >= pbc.globalLimits.MaxMemoryBytes {
		// Evict oldest entries for this user
		pbc.evictOldestEntriesForUser(userCache)
	}

	// Create validated entry
	now := time.Now()
	entry := &ValidatedCacheEntry{
		Balance:   balance,
		Timestamp: now,
		Source:    source,
		Validated: true,
		TTL:       pbc.defaultTTL,
		Checksum:  pbc.createIntegrityHash(balance, now, source),
	}

	// Initialize address map if needed
	if userCache.Balances[address] == nil {
		userCache.Balances[address] = make(map[string]*ValidatedCacheEntry)
	}

	// Store entry
	userCache.Balances[address][token] = entry
	userCache.EntryCount++
	userCache.MemoryUsage += int64(len(fmt.Sprintf("%v", entry))) // Rough memory calculation

	return nil
}

// PreloadUserBalances loads all balances for a user's wallets
func (pbc *ProductionBalanceCache) PreloadUserBalances(userID string, addresses []string, tokens []string, balanceLoader func(string, string) uint64) error {
	// Security validation
	if err := pbc.validateUserAccess(userID, "preload"); err != nil {
		return err
	}

	userCache := pbc.getUserCache(userID)
	userCache.mutex.Lock()
	defer userCache.mutex.Unlock()

	loadedCount := 0
	for _, address := range addresses {
		for _, token := range tokens {
			balance := balanceLoader(address, token)

			now := time.Now()
			entry := &ValidatedCacheEntry{
				Balance:   balance,
				Timestamp: now,
				Source:    "preload",
				Validated: true,
				TTL:       pbc.defaultTTL,
				Checksum:  pbc.createIntegrityHash(balance, now, "preload"),
			}

			if userCache.Balances[address] == nil {
				userCache.Balances[address] = make(map[string]*ValidatedCacheEntry)
			}

			userCache.Balances[address][token] = entry
			loadedCount++
		}
	}

	userCache.EntryCount += loadedCount
	log.Printf("✅ Preloaded %d balances for user %s", loadedCount, userID)
	return nil
}

// InvalidateBalance removes a specific balance from cache (used after transactions)
func (pbc *ProductionBalanceCache) InvalidateBalance(userID, address, token string) {
	userCache := pbc.getUserCache(userID)
	userCache.mutex.Lock()
	defer userCache.mutex.Unlock()

	if addressBalances, exists := userCache.Balances[address]; exists {
		if _, exists := addressBalances[token]; exists {
			delete(addressBalances, token)
			userCache.EntryCount--
		}
	}
}

// UpdateBalance immediately updates a balance in cache (used after transactions)
func (pbc *ProductionBalanceCache) UpdateBalance(userID, address, token string, newBalance uint64) error {
	return pbc.SetBalance(userID, address, token, newBalance, "transaction_update")
}

// evictOldestUser removes the least recently used user cache
func (pbc *ProductionBalanceCache) evictOldestUser() {
	oldestTime := time.Now()
	oldestUserID := ""

	for userID, cache := range pbc.userCaches {
		if cache.LastAccess.Before(oldestTime) {
			oldestTime = cache.LastAccess
			oldestUserID = userID
		}
	}

	if oldestUserID != "" {
		delete(pbc.userCaches, oldestUserID)
		log.Printf("🧹 Evicted cache for inactive user: %s", oldestUserID)
	}
}

// evictOldestEntriesForUser removes old entries for a specific user
func (pbc *ProductionBalanceCache) evictOldestEntriesForUser(userCache *UserSpecificCache) {
	// Simple strategy: remove entries older than 5 minutes
	cutoff := time.Now().Add(-5 * time.Minute)

	for address, tokens := range userCache.Balances {
		for token, entry := range tokens {
			if entry.Timestamp.Before(cutoff) {
				delete(tokens, token)
				userCache.EntryCount--
			}
		}

		// Remove empty address maps
		if len(tokens) == 0 {
			delete(userCache.Balances, address)
		}
	}
}

// startCleanupWorker runs background cleanup tasks
func (pbc *ProductionBalanceCache) startCleanupWorker() {
	ticker := time.NewTicker(pbc.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		pbc.performCleanup()
	}
}

// performCleanup removes expired entries and manages memory
func (pbc *ProductionBalanceCache) performCleanup() {
	pbc.mutex.Lock()
	defer pbc.mutex.Unlock()

	now := time.Now()
	totalMemory := int64(0)
	activeUsers := 0

	for userID, userCache := range pbc.userCaches {
		userCache.mutex.Lock()

		// Remove expired entries
		for address, tokens := range userCache.Balances {
			for token, entry := range tokens {
				if now.Sub(entry.Timestamp) > entry.TTL*2 { // Double TTL for cleanup
					delete(tokens, token)
					userCache.EntryCount--
				}
			}

			if len(tokens) == 0 {
				delete(userCache.Balances, address)
			}
		}

		// Remove inactive user caches (inactive for 1 hour)
		if now.Sub(userCache.LastAccess) > 1*time.Hour {
			userCache.mutex.Unlock()
			delete(pbc.userCaches, userID)
			continue
		}

		totalMemory += userCache.MemoryUsage
		activeUsers++
		userCache.mutex.Unlock()
	}

	pbc.lastCleanup = now
	log.Printf("🧹 Cache cleanup completed: %d active users, %dKB total memory",
		activeUsers, totalMemory/1024)
}

// GetStats returns cache performance statistics
func (pbc *ProductionBalanceCache) GetStats() map[string]interface{} {
	pbc.mutex.RLock()
	defer pbc.mutex.RUnlock()

	hitRate := float64(0)
	if pbc.totalRequests > 0 {
		hitRate = float64(pbc.cacheHits) / float64(pbc.totalRequests) * 100
	}

	return map[string]interface{}{
		"total_requests":      pbc.totalRequests,
		"cache_hits":          pbc.cacheHits,
		"cache_misses":        pbc.cacheMisses,
		"hit_rate_percent":    hitRate,
		"active_users":        len(pbc.userCaches),
		"security_violations": pbc.securityViolations,
		"last_cleanup":        pbc.lastCleanup,
	}
}
