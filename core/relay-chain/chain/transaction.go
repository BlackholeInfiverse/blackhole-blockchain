package chain

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"time"

	// "github.com/BlackholeInfiverse/blackhole-blockchain/relay-chain/crypto"
	"github.com/btcsuite/btcd/btcec/v2"
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
	Token     string          `json:"token"`
	Fee       uint64          `json:"fee"`
	Nonce     uint64          `json:"nonce"`
	Signature []byte          `json:"signature"`
	Data      string          `json:"data"`
	Timestamp int64           `json:"timestamp"`
	PublicKey []byte          `json:"public_key"`
}

func (tx *Transaction) Serialize() (any, any) {
	panic("unimplemented")
}

func NewTransaction(txType TransactionType, from, to string, amount uint64, publicKey []byte) *Transaction {
	tx := &Transaction{
		ID:        "",
		Type:      txType,
		From:      from,
		To:        to,
		Amount:    amount,
		Token:     "BHX",
		Fee:       0,
		Nonce:     0,
		Timestamp: time.Now().Unix(),
		PublicKey: publicKey, // ✅ include the public key
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
		PublicKey []byte          `json:"public_key"` // ✅ include this
	}{
		tx.Type,
		tx.From,
		tx.To,
		tx.Amount,
		tx.Token,
		tx.Nonce,
		tx.Timestamp,
		tx.PublicKey, // ✅ pass actual value
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
	if tx.From == "system" && tx.Type == TokenTransfer {
		log.Println("Info: System token transfer - auto verified")
		return true
	}

	if tx.Signature == nil || len(tx.Signature) == 0 {
		log.Println("Error: Empty signature")
		return false
	}

	publicKey, err := btcec.ParsePubKey(tx.PublicKey)
	if err != nil {
		log.Println("❌ Failed to parse public key:", err)
		return false
	}
	log.Println("Info: Public key parsed successfully")

	hashHex := tx.CalculateHash()
	log.Printf("Info: Transaction hash (hex): %s\n", hashHex)

	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		log.Println("❌ Failed to decode hash hex string:", err)
		return false
	}

	r := big.Int{}
	s := big.Int{}
	sigLen := len(tx.Signature)
	r.SetBytes(tx.Signature[:sigLen/2])
	s.SetBytes(tx.Signature[sigLen/2:])
	log.Printf("Info: Signature components r: %s, s: %s\n", r.String(), s.String())

	ecdsaPubKey := publicKey.ToECDSA()

	verified := ecdsa.Verify(ecdsaPubKey, hashBytes, &r, &s)
	log.Printf("Info: Signature verification result: %v\n", verified)
	return verified
}
