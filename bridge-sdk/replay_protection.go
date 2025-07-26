package bridgesdk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

// ReplayProtection manages event deduplication and replay attack prevention
type ReplayProtection struct {
	db           *bbolt.DB
	cache        map[string]*EventRecord
	cacheMutex   sync.RWMutex
	maxCacheSize int
	dbPath       string
}

// EventRecord represents a processed event record
type EventRecord struct {
	Hash        string    `json:"hash"`
	TxHash      string    `json:"tx_hash"`
	SourceChain string    `json:"source_chain"`
	Amount      float64   `json:"amount"`
	Timestamp   int64     `json:"timestamp"`
	ProcessedAt time.Time `json:"processed_at"`
	EventType   string    `json:"event_type"`
	FromAddress string    `json:"from_address,omitempty"`
	ToAddress   string    `json:"to_address,omitempty"`
	TokenSymbol string    `json:"token_symbol,omitempty"`
}

// EventHashInput represents the input for hash generation
type EventHashInput struct {
	TxHash      string  `json:"tx_hash"`
	SourceChain string  `json:"source_chain"`
	Amount      float64 `json:"amount"`
	Timestamp   int64   `json:"timestamp"`
	FromAddress string  `json:"from_address,omitempty"`
	ToAddress   string  `json:"to_address,omitempty"`
	TokenSymbol string  `json:"token_symbol,omitempty"`
}

const (
	EventsBucket     = "events"
	HashIndexBucket  = "hash_index"
	TxHashBucket     = "tx_hash_index"
	DefaultCacheSize = 10000
)

// NewReplayProtection creates a new replay protection instance
func NewReplayProtection(dataDir string) (*ReplayProtection, error) {
	dbPath := filepath.Join(dataDir, "replay_protection.db")
	
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{
		Timeout: 1 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open BoltDB: %v", err)
	}

	// Create buckets if they don't exist
	err = db.Update(func(tx *bbolt.Tx) error {
		buckets := []string{EventsBucket, HashIndexBucket, TxHashBucket}
		for _, bucket := range buckets {
			_, err := tx.CreateBucketIfNotExists([]byte(bucket))
			if err != nil {
				return fmt.Errorf("failed to create bucket %s: %v", bucket, err)
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	rp := &ReplayProtection{
		db:           db,
		cache:        make(map[string]*EventRecord),
		maxCacheSize: DefaultCacheSize,
		dbPath:       dbPath,
	}

	// Load recent events into cache
	err = rp.loadRecentEventsToCache()
	if err != nil {
		log.Printf("⚠️ Warning: Failed to load cache: %v", err)
	}

	log.Printf("✅ Replay protection initialized with database: %s", dbPath)
	return rp, nil
}

// GenerateEventHash creates a deterministic hash for an event
func (rp *ReplayProtection) GenerateEventHash(event *TransactionEvent) string {
	// Create a normalized input for hashing
	input := EventHashInput{
		TxHash:      strings.ToLower(strings.TrimSpace(event.TxHash)),
		SourceChain: strings.ToLower(strings.TrimSpace(event.SourceChain)),
		Amount:      event.Amount,
		Timestamp:   event.Timestamp,
		FromAddress: strings.ToLower(strings.TrimSpace(event.FromAddress)),
		ToAddress:   strings.ToLower(strings.TrimSpace(event.ToAddress)),
		TokenSymbol: strings.ToUpper(strings.TrimSpace(event.TokenSymbol)),
	}

	// Create a deterministic string representation
	hashData := fmt.Sprintf("%s|%s|%.18f|%d|%s|%s|%s",
		input.TxHash,
		input.SourceChain,
		input.Amount,
		input.Timestamp,
		input.FromAddress,
		input.ToAddress,
		input.TokenSymbol,
	)

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(hashData))
	return hex.EncodeToString(hash[:])
}

// GenerateRelayTransactionHash creates a hash for relay transactions
func (rp *ReplayProtection) GenerateRelayTransactionHash(tx *RelayTransaction) string {
	// Create a normalized input for hashing
	hashData := fmt.Sprintf("%s|%s|%s|%d|%s|%s|%s|%d",
		strings.ToLower(strings.TrimSpace(tx.SourceTxHash)),
		strings.ToLower(string(tx.SourceChain)),
		strings.ToLower(string(tx.DestChain)),
		tx.Amount,
		strings.ToLower(strings.TrimSpace(tx.SourceAddress)),
		strings.ToLower(strings.TrimSpace(tx.DestAddress)),
		strings.ToUpper(strings.TrimSpace(tx.TokenSymbol)),
		tx.CreatedAt,
	)

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(hashData))
	return hex.EncodeToString(hash[:])
}

// IsEventProcessed checks if an event has already been processed
func (rp *ReplayProtection) IsEventProcessed(event *TransactionEvent) (bool, *EventRecord, error) {
	eventHash := rp.GenerateEventHash(event)
	
	// Check cache first
	rp.cacheMutex.RLock()
	if record, exists := rp.cache[eventHash]; exists {
		rp.cacheMutex.RUnlock()
		return true, record, nil
	}
	rp.cacheMutex.RUnlock()

	// Check database
	var record *EventRecord
	err := rp.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(EventsBucket))
		if bucket == nil {
			return nil
		}

		data := bucket.Get([]byte(eventHash))
		if data == nil {
			return nil
		}

		record = &EventRecord{}
		return json.Unmarshal(data, record)
	})

	if err != nil {
		return false, nil, fmt.Errorf("failed to check database: %v", err)
	}

	if record != nil {
		// Add to cache for faster future lookups
		rp.addToCache(eventHash, record)
		return true, record, nil
	}

	return false, nil, nil
}

// IsTransactionHashProcessed checks if a transaction hash has been processed
func (rp *ReplayProtection) IsTransactionHashProcessed(txHash, sourceChain string) (bool, []string, error) {
	key := fmt.Sprintf("%s:%s", strings.ToLower(sourceChain), strings.ToLower(txHash))
	
	var eventHashes []string
	err := rp.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(TxHashBucket))
		if bucket == nil {
			return nil
		}

		data := bucket.Get([]byte(key))
		if data == nil {
			return nil
		}

		return json.Unmarshal(data, &eventHashes)
	})

	if err != nil {
		return false, nil, fmt.Errorf("failed to check transaction hash: %v", err)
	}

	return len(eventHashes) > 0, eventHashes, nil
}

// RecordEvent records a processed event to prevent replay attacks
func (rp *ReplayProtection) RecordEvent(event *TransactionEvent) error {
	eventHash := rp.GenerateEventHash(event)
	
	// Check if already processed
	processed, _, err := rp.IsEventProcessed(event)
	if err != nil {
		return fmt.Errorf("failed to check if event is processed: %v", err)
	}
	if processed {
		return fmt.Errorf("event already processed: %s", eventHash)
	}

	// Create event record
	record := &EventRecord{
		Hash:        eventHash,
		TxHash:      event.TxHash,
		SourceChain: event.SourceChain,
		Amount:      event.Amount,
		Timestamp:   event.Timestamp,
		ProcessedAt: time.Now(),
		EventType:   "transaction_event",
		FromAddress: event.FromAddress,
		ToAddress:   event.ToAddress,
		TokenSymbol: event.TokenSymbol,
	}

	// Store in database
	err = rp.db.Update(func(tx *bbolt.Tx) error {
		// Store event record
		eventsBucket := tx.Bucket([]byte(EventsBucket))
		recordData, err := json.Marshal(record)
		if err != nil {
			return err
		}
		err = eventsBucket.Put([]byte(eventHash), recordData)
		if err != nil {
			return err
		}

		// Store hash index
		hashBucket := tx.Bucket([]byte(HashIndexBucket))
		err = hashBucket.Put([]byte(eventHash), []byte(record.TxHash))
		if err != nil {
			return err
		}

		// Store transaction hash index
		txHashBucket := tx.Bucket([]byte(TxHashBucket))
		txKey := fmt.Sprintf("%s:%s", strings.ToLower(event.SourceChain), strings.ToLower(event.TxHash))
		
		// Get existing hashes for this transaction
		var existingHashes []string
		if data := txHashBucket.Get([]byte(txKey)); data != nil {
			json.Unmarshal(data, &existingHashes)
		}
		
		// Add new hash
		existingHashes = append(existingHashes, eventHash)
		hashesData, err := json.Marshal(existingHashes)
		if err != nil {
			return err
		}
		
		return txHashBucket.Put([]byte(txKey), hashesData)
	})

	if err != nil {
		return fmt.Errorf("failed to record event: %v", err)
	}

	// Add to cache
	rp.addToCache(eventHash, record)

	log.Printf("🔒 Recorded event hash: %s (tx: %s)", eventHash[:16]+"...", event.TxHash)
	return nil
}

// addToCache adds a record to the in-memory cache
func (rp *ReplayProtection) addToCache(hash string, record *EventRecord) {
	rp.cacheMutex.Lock()
	defer rp.cacheMutex.Unlock()

	// If cache is full, remove oldest entries
	if len(rp.cache) >= rp.maxCacheSize {
		rp.evictOldestFromCache()
	}

	rp.cache[hash] = record
}

// evictOldestFromCache removes the oldest entries from cache
func (rp *ReplayProtection) evictOldestFromCache() {
	// Convert cache to slice for sorting
	type cacheEntry struct {
		hash   string
		record *EventRecord
	}
	
	entries := make([]cacheEntry, 0, len(rp.cache))
	for hash, record := range rp.cache {
		entries = append(entries, cacheEntry{hash, record})
	}

	// Sort by ProcessedAt time
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].record.ProcessedAt.Before(entries[j].record.ProcessedAt)
	})

	// Remove oldest 25% of entries
	removeCount := len(entries) / 4
	if removeCount < 1 {
		removeCount = 1
	}

	for i := 0; i < removeCount; i++ {
		delete(rp.cache, entries[i].hash)
	}
}

// loadRecentEventsToCache loads recent events into memory cache
func (rp *ReplayProtection) loadRecentEventsToCache() error {
	cutoffTime := time.Now().Add(-24 * time.Hour) // Load events from last 24 hours
	
	return rp.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(EventsBucket))
		if bucket == nil {
			return nil
		}

		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var record EventRecord
			if err := json.Unmarshal(v, &record); err != nil {
				continue // Skip invalid records
			}

			// Only load recent events
			if record.ProcessedAt.After(cutoffTime) {
				rp.cache[string(k)] = &record
			}

			// Don't exceed cache size
			if len(rp.cache) >= rp.maxCacheSize {
				break
			}
		}

		return nil
	})
}

// GetEventRecord retrieves an event record by hash
func (rp *ReplayProtection) GetEventRecord(eventHash string) (*EventRecord, error) {
	// Check cache first
	rp.cacheMutex.RLock()
	if record, exists := rp.cache[eventHash]; exists {
		rp.cacheMutex.RUnlock()
		return record, nil
	}
	rp.cacheMutex.RUnlock()

	// Check database
	var record *EventRecord
	err := rp.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(EventsBucket))
		if bucket == nil {
			return fmt.Errorf("events bucket not found")
		}

		data := bucket.Get([]byte(eventHash))
		if data == nil {
			return fmt.Errorf("event record not found")
		}

		record = &EventRecord{}
		return json.Unmarshal(data, record)
	})

	if err != nil {
		return nil, err
	}

	// Add to cache
	rp.addToCache(eventHash, record)
	return record, nil
}

// GetProcessedEventsCount returns the total number of processed events
func (rp *ReplayProtection) GetProcessedEventsCount() (int, error) {
	var count int
	err := rp.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(EventsBucket))
		if bucket == nil {
			return nil
		}

		stats := bucket.Stats()
		count = stats.KeyN
		return nil
	})

	return count, err
}

// GetRecentEvents returns recent processed events
func (rp *ReplayProtection) GetRecentEvents(limit int) ([]*EventRecord, error) {
	var events []*EventRecord

	err := rp.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(EventsBucket))
		if bucket == nil {
			return nil
		}

		cursor := bucket.Cursor()

		// Collect all events first
		var allEvents []*EventRecord
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var record EventRecord
			if err := json.Unmarshal(v, &record); err != nil {
				continue // Skip invalid records
			}
			allEvents = append(allEvents, &record)
		}

		// Sort by ProcessedAt time (newest first)
		sort.Slice(allEvents, func(i, j int) bool {
			return allEvents[i].ProcessedAt.After(allEvents[j].ProcessedAt)
		})

		// Take only the requested number
		if limit > 0 && len(allEvents) > limit {
			events = allEvents[:limit]
		} else {
			events = allEvents
		}

		return nil
	})

	return events, err
}

// CleanupOldEvents removes events older than the specified duration
func (rp *ReplayProtection) CleanupOldEvents(maxAge time.Duration) (int, error) {
	cutoffTime := time.Now().Add(-maxAge)
	var deletedCount int

	err := rp.db.Update(func(tx *bbolt.Tx) error {
		eventsBucket := tx.Bucket([]byte(EventsBucket))
		hashBucket := tx.Bucket([]byte(HashIndexBucket))
		txHashBucket := tx.Bucket([]byte(TxHashBucket))

		if eventsBucket == nil {
			return nil
		}

		cursor := eventsBucket.Cursor()
		var toDelete []string

		// Find events to delete
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var record EventRecord
			if err := json.Unmarshal(v, &record); err != nil {
				continue
			}

			if record.ProcessedAt.Before(cutoffTime) {
				toDelete = append(toDelete, string(k))
			}
		}

		// Delete old events
		for _, hash := range toDelete {
			// Get the record first to clean up indexes
			data := eventsBucket.Get([]byte(hash))
			if data != nil {
				var record EventRecord
				if json.Unmarshal(data, &record) == nil {
					// Clean up transaction hash index
					txKey := fmt.Sprintf("%s:%s", strings.ToLower(record.SourceChain), strings.ToLower(record.TxHash))
					if txData := txHashBucket.Get([]byte(txKey)); txData != nil {
						var hashes []string
						if json.Unmarshal(txData, &hashes) == nil {
							// Remove this hash from the list
							for i, h := range hashes {
								if h == hash {
									hashes = append(hashes[:i], hashes[i+1:]...)
									break
								}
							}
							// Update or delete the transaction hash entry
							if len(hashes) > 0 {
								if newData, err := json.Marshal(hashes); err == nil {
									txHashBucket.Put([]byte(txKey), newData)
								}
							} else {
								txHashBucket.Delete([]byte(txKey))
							}
						}
					}
				}
			}

			// Delete from all buckets
			eventsBucket.Delete([]byte(hash))
			hashBucket.Delete([]byte(hash))

			// Remove from cache
			rp.cacheMutex.Lock()
			delete(rp.cache, hash)
			rp.cacheMutex.Unlock()

			deletedCount++
		}

		return nil
	})

	if err == nil && deletedCount > 0 {
		log.Printf("🧹 Cleaned up %d old event records", deletedCount)
	}

	return deletedCount, err
}

// GetStats returns statistics about the replay protection system
func (rp *ReplayProtection) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	// Cache stats
	rp.cacheMutex.RLock()
	stats["cache_size"] = len(rp.cache)
	stats["max_cache_size"] = rp.maxCacheSize
	rp.cacheMutex.RUnlock()

	// Database stats
	rp.db.View(func(tx *bbolt.Tx) error {
		if bucket := tx.Bucket([]byte(EventsBucket)); bucket != nil {
			bucketStats := bucket.Stats()
			stats["total_events"] = bucketStats.KeyN
			stats["db_size_bytes"] = bucketStats.BucketN
		}

		if bucket := tx.Bucket([]byte(TxHashBucket)); bucket != nil {
			bucketStats := bucket.Stats()
			stats["unique_transactions"] = bucketStats.KeyN
		}

		return nil
	})

	stats["db_path"] = rp.dbPath
	return stats
}

// Close closes the replay protection database
func (rp *ReplayProtection) Close() error {
	if rp.db != nil {
		log.Println("🔒 Closing replay protection database...")
		return rp.db.Close()
	}
	return nil
}

// ValidateEventIntegrity validates the integrity of an event before processing
func (rp *ReplayProtection) ValidateEventIntegrity(event *TransactionEvent) error {
	// Basic validation
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	if strings.TrimSpace(event.TxHash) == "" {
		return fmt.Errorf("transaction hash cannot be empty")
	}

	if strings.TrimSpace(event.SourceChain) == "" {
		return fmt.Errorf("source chain cannot be empty")
	}

	if event.Amount < 0 {
		return fmt.Errorf("amount cannot be negative")
	}

	if event.Timestamp <= 0 {
		return fmt.Errorf("timestamp must be positive")
	}

	// Check if timestamp is reasonable (not too far in the future or past)
	now := time.Now().Unix()
	maxFuture := now + 300  // 5 minutes in the future
	maxPast := now - 86400  // 24 hours in the past

	if event.Timestamp > maxFuture {
		return fmt.Errorf("timestamp too far in the future")
	}

	if event.Timestamp < maxPast {
		return fmt.Errorf("timestamp too far in the past")
	}

	return nil
}
