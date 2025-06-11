package internal

import (
    "crypto/sha256"
    "encoding/hex"
    "strconv"
)

type BridgeMessage struct {
   Index     int
	Timestamp string
	Data      string
	PrevHash  string
	Hash      string
	Nonce     int
}

// ComputeChecksum generates a SHA256 hash of the message fields for integrity and uniqueness.
func (bm *BridgeMessage) ComputeChecksum() string {
    data := strconv.Itoa(bm.Index) +
        bm.Timestamp +
        bm.Data +
        bm.PrevHash +
        bm.Hash +
        strconv.Itoa(bm.Nonce)
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}
      
// BridgeMessageStore keeps track of processed messages to prevent duplicates/replays.
type BridgeMessageStore struct {
    seen map[string]struct{}
}

func NewBridgeMessageStore() *BridgeMessageStore {
    return &BridgeMessageStore{seen: make(map[string]struct{})}
}

// AddIfNew returns true if the message is new, false if duplicate/replay.
func (s *BridgeMessageStore) AddIfNew(msg *BridgeMessage) bool {
    cs := msg.ComputeChecksum()
    if _, exists := s.seen[cs]; exists {
        return false
    }
    s.seen[cs] = struct{}{}
    return true
}