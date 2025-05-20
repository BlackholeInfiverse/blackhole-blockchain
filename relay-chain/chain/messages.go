package chain

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
)

type MessageType byte

const (
	MessageTypeTx MessageType = iota
	MessageTypeBlock
	MessageTypeSyncReq
	MessageTypeSyncResp
)

type Message struct {
	Type MessageType
	Data []byte
}

func (m *Message) Encode(w io.Writer) error {
	return gob.NewEncoder(w).Encode(m)
}

func (m *Message) Decode(r io.Reader) error {
	return gob.NewDecoder(r).Decode(m)
}

type TransactionWrapper struct {
	Transaction *Transaction
}

func (tw *TransactionWrapper) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(tw.Transaction); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DeserializeTransaction(data []byte) (*Transaction, error) {
	var tx Transaction
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&tx); err != nil {
		return nil, err
	}
	return &tx, nil
}

type BlockWrapper struct {
	Block *Block
}

func (bw *BlockWrapper) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(bw.Block); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DeserializeBlock(data []byte) (*Block, error) {
	fmt.Println("➡️ Deserializing block, data length:", len(data))
	// Log first 100 bytes of data for debugging
	if len(data) > 0 {
		dumpLen := len(data)
		if dumpLen > 100 {
			dumpLen = 100
		}
		fmt.Println("📜 Data prefix (hex):", hex.EncodeToString(data[:dumpLen]))
	}
	var block Block
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&block); err != nil {
		fmt.Println("❌ Gob Decode Error:", err)
		return nil, fmt.Errorf("failed to deserialize block: %v", err)
	}
	// Verify hash integrity
	computedHash := block.CalculateHash()
	if block.Hash != computedHash {
		fmt.Println("❌ Hash mismatch: expected", block.Hash, "got", computedHash)
		return nil, fmt.Errorf("hash mismatch: expected %s, got %s", block.Hash, computedHash)
	}
	fmt.Println("✅ Successfully deserialized block, index:", block.Header.Index)
	return &block, nil
}