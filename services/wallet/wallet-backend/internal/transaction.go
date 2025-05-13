package internal

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/Shivam-Patel-G/blackhole-blockchain/wallet-backend/crypto"
)

type Transaction struct {
	Sender    string
	Receiver  string
	Amount    int64
	Signature string
}

// Create the hash of a transaction
func (tx *Transaction) Hash() []byte {
	data := tx.Sender + tx.Receiver + string(tx.Amount)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// Sign the transaction using a KeyManager
func (tx *Transaction) Sign(km *crypto.KeyManager) error {
	hash := tx.Hash()

	r, s, err := ecdsa.Sign(nil, km.GetPrivateKey(), hash)
	if err != nil {
		return err
	}

	sig := append(r.Bytes(), s.Bytes()...)
	tx.Signature = hex.EncodeToString(sig)
	return nil
}

// Verify that the transaction was signed by the sender
func (tx *Transaction) Verify() (bool, error) {
	pubKey, err := crypto.GetPublicKeyFromAddress(tx.Sender)
	if err != nil {
		return false, err
	}

	sigBytes, err := hex.DecodeString(tx.Signature)
	if err != nil {
		return false, err
	}

	if len(sigBytes)%2 != 0 {
		return false, errors.New("invalid signature length")
	}

	r := new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2])
	s := new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:])
	hash := tx.Hash()

	valid := ecdsa.Verify(pubKey, hash, r, s)
	return valid, nil
}
