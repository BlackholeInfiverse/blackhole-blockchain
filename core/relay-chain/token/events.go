package token

type EventType string

const (
	EventTransfer EventType = "Transfer"
	EventMint     EventType = "Mint"
	EventBurn     EventType = "Burn"
)

type Event struct {
	Type    EventType
	From    string  // Optional (e.g., for Mint)
	To      string  // Optional (e.g., for Burn)
	Amount  uint64
}

// Emit events to a channel or logging system (customize as needed)
func (t *Token) emitEvent(event Event) {
    if t.events == nil {
        t.events = []Event{}
    }
    t.events = append(t.events, event)
}