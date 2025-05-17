package chain

import (
	"bytes"
	"encoding/gob"
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
	var block Block
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&block); err != nil {
		return nil, err
	}
	return &block, nil
}
