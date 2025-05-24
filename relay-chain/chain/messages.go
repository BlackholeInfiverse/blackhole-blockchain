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

const ProtocolVersion = 2

type Message struct {
	Type    MessageType
	Data    []byte
	Version uint32
}

func (m *Message) Encode(w io.Writer) error {
	m.Version = ProtocolVersion
	return gob.NewEncoder(w).Encode(m)
}

func (m *Message) Decode(r io.Reader) error {
	if err := gob.NewDecoder(r).Decode(m); err != nil {
		return err
	}
	if m.Version != ProtocolVersion {
		return fmt.Errorf("protocol version mismatch: got %d, expected %d", m.Version, ProtocolVersion)
	}
	return nil
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
	if len(data) > 0 {
		dumpLen := len(data)
		if dumpLen > 100 {
			dumpLen = 100
		}
		fmt.Println("📜 Data prefix (hex):", hex.EncodeToString(data[:dumpLen]))
	}
	if bytes.Contains(data, []byte("CommonType")) {
		fmt.Println("❌ Block data contains CommonType reference")
		fmt.Println("📜 Full block data (hex):", hex.EncodeToString(data))
		return nil, fmt.Errorf("invalid block: contains CommonType reference")
	}
	var block Block
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&block); err != nil {
		fmt.Println("❌ Gob Decode Error:", err)
		fmt.Println("📜 Full block data (hex):", hex.EncodeToString(data))
		return nil, fmt.Errorf("failed to deserialize block: %v", err)
	}
	computedHash := block.CalculateHash()
	if block.Hash != computedHash {
		fmt.Println("❌ Hash mismatch: expected", block.Hash, "got", computedHash)
		return nil, fmt.Errorf("hash mismatch: expected %s, got %s", block.Hash, computedHash)
	}
	fmt.Println("✅ Successfully deserialized block, index:", block.Header.Index)
	return &block, nil
}
