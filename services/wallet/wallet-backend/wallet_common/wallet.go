package wallet_common

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/services/wallet/wallet-backend/crypto"
)

type Wallet struct {
	PublicKey        string `json:"public_key"`
	Address          string `json:"address"`
	Mnemonic         string `json:"mnemonic"`
	EncryptedPrivKey string `json:"encrypted_priv_key"`
}

// Create a new wallet with mnemonic-based key
func NewWallet(password string) (*Wallet, error) {
	km, mnemonic, err := crypto.NewKeyManagerWithMnemonic()
	if err != nil {
		return nil, fmt.Errorf("failed to create key manager: %v", err)
	}

	encryptedKey, err := crypto.EncryptPrivateKey(km, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %v", err)
	}

	return &Wallet{
		PublicKey:        km.GetPublicKey(),
		Address:          km.GetAddress(),
		Mnemonic:         mnemonic,
		EncryptedPrivKey: encryptedKey,
	}, nil
}

// Restore wallet from mnemonic
func RestoreWallet(mnemonic, password string) (*Wallet, error) {
	km, err := crypto.RestoreKeyManagerFromMnemonic(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to restore from mnemonic: %v", err)
	}

	encryptedKey, err := crypto.EncryptPrivateKey(km, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %v", err)
	}

	return &Wallet{
		PublicKey:        km.GetPublicKey(),
		Address:          km.GetAddress(),
		Mnemonic:         mnemonic,
		EncryptedPrivKey: encryptedKey,
	}, nil
}

// Load wallet from saved file
func Load(walletPath, password string) (*Wallet, error) {
	data, err := os.ReadFile(walletPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read wallet file: %v", err)
	}

	var walletData Wallet
	if err := json.Unmarshal(data, &walletData); err != nil {
		return nil, fmt.Errorf("failed to parse wallet data: %v", err)
	}

	if walletData.EncryptedPrivKey == "" {
		return nil, errors.New("missing encrypted private key in wallet file")
	}

	// Verify the password by attempting to decrypt
	_, err = crypto.DecryptPrivateKey(walletData.EncryptedPrivKey, password)
	if err != nil {
		return nil, fmt.Errorf("invalid password or corrupted wallet: %v", err)
	}

	return &walletData, nil
}

// Save wallet to a file
func (w *Wallet) Save(walletPath string) error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal wallet: %v", err)
	}

	if err := os.WriteFile(walletPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write wallet file: %v", err)
	}

	return nil
}

// SignTransaction signs arbitrary data with the wallet's private key
func (w *Wallet) SignTransaction(data []byte, password string) ([]byte, error) {
	km, err := crypto.DecryptPrivateKey(w.EncryptedPrivKey, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %v", err)
	}

	signature, err := km.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}

	return signature, nil
}

// Transaction related code remains the same as before
type Transaction struct {
	Version   uint      `json:"version"`
	Nonce     uint64    `json:"nonce"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Value     string    `json:"value"`
	Data      []byte    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
	Signature []byte    `json:"signature"`
	PublicKey string    `json:"public_key"`
	Metadata  Metadata  `json:"metadata"`
}

type Metadata struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

func NewTransaction(from, to, value, txType string) *Transaction {
	return &Transaction{
		Version:   1,
		From:      from,
		To:        to,
		Value:     value,
		Timestamp: time.Now().UTC(),
		Metadata: Metadata{
			Type: txType,
		},
	}
}

func (tx *Transaction) Sign(wallet *Wallet, password string) error {
	if wallet == nil {
		return errors.New("wallet is nil")
	}

	txData, err := tx.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize transaction: %v", err)
	}

	signature, err := wallet.SignTransaction(txData, password)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %v", err)
	}

	tx.Signature = signature
	tx.PublicKey = wallet.PublicKey
	return nil
}

func (tx *Transaction) Serialize() ([]byte, error) {
	tempTx := struct {
		Version   uint      `json:"version"`
		Nonce     uint64    `json:"nonce"`
		From      string    `json:"from"`
		To        string    `json:"to"`
		Value     string    `json:"value"`
		Data      []byte    `json:"data"`
		Timestamp time.Time `json:"timestamp"`
		Metadata  Metadata  `json:"metadata"`
	}{
		Version:   tx.Version,
		Nonce:     tx.Nonce,
		From:      tx.From,
		To:        tx.To,
		Value:     tx.Value,
		Data:      tx.Data,
		Timestamp: tx.Timestamp,
		Metadata:  tx.Metadata,
	}

	return json.Marshal(tempTx)
}

func (tx *Transaction) Verify() (bool, error) {
	if len(tx.Signature) == 0 {
		return false, errors.New("transaction has no signature")
	}

	txData, err := tx.Serialize()
	if err != nil {
		return false, fmt.Errorf("failed to serialize transaction: %v", err)
	}

	tempWallet := &Wallet{PublicKey: tx.PublicKey}
	return tempWallet.VerifyTransaction(txData, tx.Signature)
}

// VerifyTransaction verifies signed data with the wallet's public key
func (w *Wallet) VerifyTransaction(data, signature []byte) (bool, error) {
	km, err := crypto.NewKeyManagerFromPublicKey(w.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to create key manager: %v", err)
	}

	return km.Verify(data, signature)
}

func CreateAndSignTransaction(mnemonic, password, toAddress, amount, txType string) (*Transaction, error) {
	// Restore wallet
	wallet, err := RestoreWallet(mnemonic, password)
	if err != nil {
		return nil, fmt.Errorf("failed to restore wallet: %v", err)
	}

	// Create transaction
	tx := NewTransaction(wallet.Address, toAddress, amount, txType)

	// Sign transaction
	err = tx.Sign(wallet, password)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}

	return tx, nil
}
