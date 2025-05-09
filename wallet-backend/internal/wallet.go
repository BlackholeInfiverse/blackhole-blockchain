package internal

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/Shivam-Patel-G/blackhole-blockchain/wallet-backend/crypto"
)

type Wallet struct {
	PublicKey        string
	Address          string
	Mnemonic         string
	EncryptedPrivKey string
}

// Create a new wallet with mnemonic-based key
func NewWallet() (*Wallet, error) {
	km, mnemonic, err := crypto.NewKeyManagerWithMnemonic()
	if err != nil {
		return nil, err
	}

	encryptedKey, err := crypto.EncryptPrivateKey(km)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		PublicKey:        km.GetPublicKey(),
		Address:          km.GetAddress(),
		Mnemonic:         mnemonic,
		EncryptedPrivKey: encryptedKey,
	}, nil
}

// Restore wallet from saved file
func Load(walletPath string) (*Wallet, error) {
	data, err := os.ReadFile(walletPath)
	if err != nil {
		return nil, err
	}

	var walletData Wallet
	if err := json.Unmarshal(data, &walletData); err != nil {
		return nil, err
	}

	if walletData.EncryptedPrivKey == "" {
		return nil, errors.New("missing EncryptedPrivKey in wallet file")
	}

	km, err := crypto.DecryptPrivateKey(walletData.EncryptedPrivKey)
	if err != nil {
		return nil, err
	}

	// Update walletData with KeyManager values
	walletData.PublicKey = km.GetPublicKey()
	walletData.Address = km.GetAddress()

	return &walletData, nil
}

// Save wallet to a file
func (w *Wallet) Save(walletPath string) error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(walletPath, data, 0600)
}
