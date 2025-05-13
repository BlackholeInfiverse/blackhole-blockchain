package p2p

import (
	"bytes"
	"encoding/gob"
	"io"

	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/chain"
)

type MessageType byte

const (
	MessageTypeTx      MessageType = iota
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
	Transaction *chain.Transaction
}

func (tw *TransactionWrapper) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(tw.Transaction); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DeserializeTransaction(data []byte) (*chain.Transaction, error) {
	var tx chain.Transaction
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&tx); err != nil {
		return nil, err
	}
	return &tx, nil
}

type BlockWrapper struct {
	Block *chain.Block
}

func (bw *BlockWrapper) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(bw.Block); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DeserializeBlock(data []byte) (*chain.Block, error) {
	var block chain.Block
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&block); err != nil {
		return nil, err
	}
	return &block, nil
}