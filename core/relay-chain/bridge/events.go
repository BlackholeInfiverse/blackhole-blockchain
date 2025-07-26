package bridge

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// BridgeEventType represents different types of bridge events
type BridgeEventType string

const (
	EventBridgeInitiated  BridgeEventType = "BridgeInitiated"
	EventBridgeConfirmed  BridgeEventType = "BridgeConfirmed"
	EventBridgeCompleted  BridgeEventType = "BridgeCompleted"
	EventBridgeFailed     BridgeEventType = "BridgeFailed"
	EventTokenLocked      BridgeEventType = "TokenLocked"
	EventTokenMinted      BridgeEventType = "TokenMinted"
	EventTokenBurned      BridgeEventType = "TokenBurned"
	EventTokenUnlocked    BridgeEventType = "TokenUnlocked"
	EventRelaySignature   BridgeEventType = "RelaySignature"
	EventBridgeApproval   BridgeEventType = "BridgeApproval"
)

// BridgeEvent represents a comprehensive bridge event with metadata
type BridgeEvent struct {
	Type            BridgeEventType        `json:"type"`
	BridgeID        string                 `json:"bridge_id"`
	SourceChain     ChainType              `json:"source_chain"`
	DestChain       ChainType              `json:"dest_chain"`
	SourceAddress   string                 `json:"source_address"`
	DestAddress     string                 `json:"dest_address"`
	TokenSymbol     string                 `json:"token_symbol"`
	Amount          uint64                 `json:"amount"`
	Timestamp       time.Time              `json:"timestamp"`
	BlockHeight     uint64                 `json:"block_height,omitempty"`
	TxHash          string                 `json:"tx_hash,omitempty"`
	RelaySignatures []string               `json:"relay_signatures,omitempty"`
	GasUsed         uint64                 `json:"gas_used,omitempty"`
	GasPrice        uint64                 `json:"gas_price,omitempty"`
	Fee             uint64                 `json:"fee,omitempty"`
	Status          string                 `json:"status"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// BridgeEventEmitter manages bridge event emission and storage
type BridgeEventEmitter struct {
	events   []BridgeEvent
	mu       sync.RWMutex
	handlers map[BridgeEventType][]func(BridgeEvent)
}

// NewBridgeEventEmitter creates a new bridge event emitter
func NewBridgeEventEmitter() *BridgeEventEmitter {
	return &BridgeEventEmitter{
		events:   make([]BridgeEvent, 0),
		handlers: make(map[BridgeEventType][]func(BridgeEvent)),
	}
}

// EmitEvent emits a bridge event with comprehensive metadata
func (bee *BridgeEventEmitter) EmitEvent(event BridgeEvent) {
	bee.mu.Lock()
	defer bee.mu.Unlock()

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Store event
	bee.events = append(bee.events, event)

	// Log event
	eventJSON, _ := json.MarshalIndent(event, "", "  ")
	log.Printf("🌉 Bridge Event Emitted: %s\n%s", event.Type, string(eventJSON))

	// Call registered handlers
	if handlers, exists := bee.handlers[event.Type]; exists {
		for _, handler := range handlers {
			go handler(event) // Run handlers in goroutines to avoid blocking
		}
	}
}

// RegisterHandler registers an event handler for a specific event type
func (bee *BridgeEventEmitter) RegisterHandler(eventType BridgeEventType, handler func(BridgeEvent)) {
	bee.mu.Lock()
	defer bee.mu.Unlock()

	if bee.handlers[eventType] == nil {
		bee.handlers[eventType] = make([]func(BridgeEvent), 0)
	}
	bee.handlers[eventType] = append(bee.handlers[eventType], handler)
}

// GetEvents returns all events, optionally filtered by type
func (bee *BridgeEventEmitter) GetEvents(eventType ...BridgeEventType) []BridgeEvent {
	bee.mu.RLock()
	defer bee.mu.RUnlock()

	if len(eventType) == 0 {
		// Return all events
		events := make([]BridgeEvent, len(bee.events))
		copy(events, bee.events)
		return events
	}

	// Filter by event type
	var filtered []BridgeEvent
	for _, event := range bee.events {
		for _, filterType := range eventType {
			if event.Type == filterType {
				filtered = append(filtered, event)
				break
			}
		}
	}
	return filtered
}

// GetEventsByBridgeID returns events for a specific bridge transaction
func (bee *BridgeEventEmitter) GetEventsByBridgeID(bridgeID string) []BridgeEvent {
	bee.mu.RLock()
	defer bee.mu.RUnlock()

	var filtered []BridgeEvent
	for _, event := range bee.events {
		if event.BridgeID == bridgeID {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// GetEventStats returns statistics about bridge events
func (bee *BridgeEventEmitter) GetEventStats() map[string]interface{} {
	bee.mu.RLock()
	defer bee.mu.RUnlock()

	stats := map[string]interface{}{
		"total_events": len(bee.events),
		"event_types":  make(map[BridgeEventType]int),
		"chains":       make(map[ChainType]int),
		"tokens":       make(map[string]int),
	}

	for _, event := range bee.events {
		// Count by event type
		stats["event_types"].(map[BridgeEventType]int)[event.Type]++
		
		// Count by source chain
		stats["chains"].(map[ChainType]int)[event.SourceChain]++
		
		// Count by token
		stats["tokens"].(map[string]int)[event.TokenSymbol]++
	}

	return stats
}

// CreateBridgeInitiatedEvent creates a bridge initiated event with metadata
func CreateBridgeInitiatedEvent(bridgeTx *BridgeTransaction) BridgeEvent {
	return BridgeEvent{
		Type:          EventBridgeInitiated,
		BridgeID:      bridgeTx.ID,
		SourceChain:   bridgeTx.SourceChain,
		DestChain:     bridgeTx.DestChain,
		SourceAddress: bridgeTx.SourceAddress,
		DestAddress:   bridgeTx.DestAddress,
		TokenSymbol:   bridgeTx.TokenSymbol,
		Amount:        bridgeTx.Amount,
		Timestamp:     time.Unix(bridgeTx.CreatedAt, 0),
		Status:        bridgeTx.Status,
		Metadata: map[string]interface{}{
			"bridge_fee":        0, // Will be calculated
			"estimated_time":    "2-5 minutes",
			"required_confirms": 3,
			"relay_threshold":   2,
		},
	}
}

// CreateTokenLockedEvent creates a token locked event
func CreateTokenLockedEvent(bridgeTx *BridgeTransaction, txHash string, gasUsed uint64) BridgeEvent {
	return BridgeEvent{
		Type:          EventTokenLocked,
		BridgeID:      bridgeTx.ID,
		SourceChain:   bridgeTx.SourceChain,
		DestChain:     bridgeTx.DestChain,
		SourceAddress: bridgeTx.SourceAddress,
		DestAddress:   bridgeTx.DestAddress,
		TokenSymbol:   bridgeTx.TokenSymbol,
		Amount:        bridgeTx.Amount,
		TxHash:        txHash,
		GasUsed:       gasUsed,
		Status:        "locked",
		Metadata: map[string]interface{}{
			"lock_contract":   "bridge_contract",
			"lock_timestamp":  time.Now().Unix(),
			"unlock_timeout":  3600, // 1 hour timeout
		},
	}
}

// CreateRelaySignatureEvent creates a relay signature event
func CreateRelaySignatureEvent(bridgeTx *BridgeTransaction, relayID string, signature string) BridgeEvent {
	return BridgeEvent{
		Type:            EventRelaySignature,
		BridgeID:        bridgeTx.ID,
		SourceChain:     bridgeTx.SourceChain,
		DestChain:       bridgeTx.DestChain,
		TokenSymbol:     bridgeTx.TokenSymbol,
		Amount:          bridgeTx.Amount,
		RelaySignatures: []string{signature},
		Status:          "signing",
		Metadata: map[string]interface{}{
			"relay_id":          relayID,
			"signature_count":   len(bridgeTx.RelaySignatures) + 1,
			"required_sigs":     2,
			"signature_valid":   true,
		},
	}
}

// CreateBridgeCompletedEvent creates a bridge completed event
func CreateBridgeCompletedEvent(bridgeTx *BridgeTransaction, destTxHash string, gasUsed uint64) BridgeEvent {
	return BridgeEvent{
		Type:          EventBridgeCompleted,
		BridgeID:      bridgeTx.ID,
		SourceChain:   bridgeTx.SourceChain,
		DestChain:     bridgeTx.DestChain,
		SourceAddress: bridgeTx.SourceAddress,
		DestAddress:   bridgeTx.DestAddress,
		TokenSymbol:   bridgeTx.TokenSymbol,
		Amount:        bridgeTx.Amount,
		TxHash:        destTxHash,
		GasUsed:       gasUsed,
		Status:        "completed",
		Metadata: map[string]interface{}{
			"completion_time":   time.Now().Unix(),
			"total_time":        time.Now().Unix() - bridgeTx.CreatedAt,
			"dest_token":        bridgeTx.TokenSymbol, // Could be wrapped token
			"bridge_success":    true,
		},
	}
}
