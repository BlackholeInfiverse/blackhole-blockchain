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
	// Example: Integrate with WebSocket, Kafka, or log to file
	// eventChannel <- event
}