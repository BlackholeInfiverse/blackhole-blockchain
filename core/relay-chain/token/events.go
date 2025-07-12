package token

import (
	"time"
)

type EventType string

const (
	EventTransfer EventType = "Transfer"
	EventMint     EventType = "Mint"
	EventBurn     EventType = "Burn"
	EventApproval EventType = "Approval"
)

type Event struct {
	Type      EventType              `json:"type"`
	From      string                 `json:"from,omitempty"`      // Optional (e.g., for Mint)
	To        string                 `json:"to,omitempty"`        // Optional (e.g., for Burn)
	Amount    uint64                 `json:"amount"`
	Timestamp time.Time              `json:"timestamp"`
	TxHash    string                 `json:"tx_hash"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Emit events to a channel or logging system (customize as needed)
func (t *Token) emitEvent(event Event) {
	if t.events == nil {
		t.events = []Event{}
	}
	t.events = append(t.events, event)
}

// GetEvents returns all events for this token
func (t *Token) GetEvents() []Event {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Return a copy to prevent external modification
	events := make([]Event, len(t.events))
	copy(events, t.events)
	return events
}

// GetEventsByType returns events filtered by type
func (t *Token) GetEventsByType(eventType EventType) []Event {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var filtered []Event
	for _, event := range t.events {
		if event.Type == eventType {
			filtered = append(filtered, event)
		}
	}
	return filtered
}