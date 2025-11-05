package bridgesdk

// pb package stubs for proto-generated types

type SignedBridgeMessage struct {
	Message   *Transaction `json:"message"`
	Signature []byte       `json:"signature"`
	PublicKey []byte       `json:"public_key"`
}

type RelayToChainResponse struct {
	Success              bool   `json:"success"`
	RelayTransactionId   string `json:"relay_transaction_id"`
	Error                string `json:"error,omitempty"`
}

// pb namespace alias for compatibility
var pb = struct {
	SignedBridgeMessage  func() SignedBridgeMessage
	RelayToChainResponse func() RelayToChainResponse
}{
	SignedBridgeMessage:  func() SignedBridgeMessage { return SignedBridgeMessage{} },
	RelayToChainResponse: func() RelayToChainResponse { return RelayToChainResponse{} },
}
