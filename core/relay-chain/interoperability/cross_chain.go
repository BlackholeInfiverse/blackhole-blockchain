package interoperability

// CrossChainMessage represents data for parachain communication
type CrossChainMessage struct {
	SourceChainID string
	TargetChainID string
	Payload       []byte
	Nonce         uint64
}

// CrossChainClient interface for parachain communication
type CrossChainClient interface {
	SendMessage(msg CrossChainMessage) error
	ReceiveMessages() []CrossChainMessage
}