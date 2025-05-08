package internal

import (
	// "crypto/aes"
	// "crypto/cipher"
	// "crypto/rand"
	// "encoding/hex"
	"encoding/json"
	"errors"
	// "io"
	"os"

	"github.com/Shivam-Patel-G/blackhole-blockchain/wallet-backend/crypto"
)

type Wallet struct {
	KeyManager       *crypto.KeyManager `json:"-"`
	PublicKey        string             `json:"public_key"`
	Address          string             `json:"address"`
	EncryptedPrivKey string             `json:"encrypted_private_key"`
	Mnemonic         string             `json:"mnemonic,omitempty"` 
}

var encryptionKey = []byte("0123456789ABCDEF0123456789ABCDEF") // exactly 32 bytes

 // must be 32 bytes

func NewWallet() (*Wallet, error) {
	km, err := crypto.NewKeyManager()
	if err != nil {
		return nil, err
	}

	pubKey := km.GetPublicKey()
	address := crypto.DeriveAddress(pubKey)

	privKeyHex := km.GetPrivateKeyHex()
	encrypted, err := encrypt([]byte(privKeyHex), encryptionKey)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		KeyManager:       km,
		PublicKey:        pubKey,
		Address:          address,
		EncryptedPrivKey: encrypted,
		Mnemonic:         "", // if using HD wallets
	}, nil
}

func (w *Wallet) Save(walletPath string) error {
	fileData, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(walletPath, fileData, 0600)
}

func Load(walletPath string) (*Wallet, error) {
	data, err := os.ReadFile(walletPath)
	if err != nil {
		return nil, err
	}

	var temp Wallet
	if err := json.Unmarshal(data, &temp); err != nil {
		return nil, err
	}

	if temp.EncryptedPrivKey == "" {
		return nil, errors.New("missing EncryptedPrivKey in wallet file")
	}

	// Decrypt private key
	privKeyBytes, err := decrypt(temp.EncryptedPrivKey, encryptionKey)
	if err != nil {
		return nil, err
	}

	km, err := crypto.NewKeyManagerFromPrivateKeyHex(string(privKeyBytes))
	if err != nil {
		return nil, err
	}

	temp.KeyManager = km
	return &temp, nil
}
