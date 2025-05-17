package chain

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/crypto"
)

type TransactionType string

const (
	OTCTransfer   TransactionType = "OTC_TRANSFER"
	TokenTransfer TransactionType = "TOKEN_TRANSFER"
	DEXSwap       TransactionType = "DEX_SWAP"
	Staking       TransactionType = "STAKING"
)

type Transaction struct {
	ID        string          `json:"id"`
	Type      TransactionType `json:"type"`
	From      string          `json:"from"`
	To        string          `json:"to"`
	Amount    uint64          `json:"amount"`
	Token     string          `json:"token"` // For multi-token support
	Fee       uint64          `json:"fee"`   // For priority/fee market
	Nonce     uint64          `json:"nonce"` // Prevent replay attacks
	Signature []byte          `json:"signature"`
	Data      string          `json:"data"` // Additional data
	Timestamp int64           `json:"timestamp"`
}

func (tx *Transaction) Serialize() (any, any) {
	panic("unimplemented")
}

func NewTransaction(txType TransactionType, from, to string, amount uint64) *Transaction {
	tx := &Transaction{
		ID:        "",
		Type:      txType,
		From:      from,
		To:        to,
		Amount:    amount,
		Token:     "BHX", // Native token
		Fee:       0,     // Free transactions per white paper
		Nonce:     0,
		Timestamp: time.Now().Unix(),
	}
	tx.ID = tx.CalculateHash()
	return tx
}

func (tx *Transaction) CalculateHash() string {
	data, _ := json.Marshal(struct {
		Type      TransactionType `json:"type"`
		From      string          `json:"from"`
		To        string          `json:"to"`
		Amount    uint64          `json:"amount"`
		Token     string          `json:"token"`
		Nonce     uint64          `json:"nonce"`
		Timestamp int64           `json:"timestamp"`
	}{
		tx.Type,
		tx.From,
		tx.To,
		tx.Amount,
		tx.Token,
		tx.Nonce,
		tx.Timestamp,
	})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (tx *Transaction) Sign(privateKey *ecdsa.PrivateKey) error {
	hash := tx.CalculateHash()
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, []byte(hash))
	if err != nil {
		return err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	tx.Signature = signature
	return nil
}

func (tx *Transaction) Verify() bool {
	// ✅ Skip signature check for system reward transactions
	if tx.From == "system" && tx.Type == TokenTransfer {
		return true
	}

	if tx.Signature == nil {
		return false
	}

	publicKey, err := crypto.ParsePublicKey(tx.From)
	if err != nil {
		return false
	}

	hash := tx.CalculateHash()
	r := big.Int{}
	s := big.Int{}
	sigLen := len(tx.Signature)
	r.SetBytes(tx.Signature[:(sigLen / 2)])
	s.SetBytes(tx.Signature[(sigLen / 2):])

	return ecdsa.Verify(publicKey, []byte(hash), &r, &s)
}
