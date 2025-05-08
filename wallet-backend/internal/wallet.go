package internal

import (
	"encoding/json"
	"os"
	"github.com/Shivam-Patel-G/blackhole-blockchain/wallet-backend/crypto"
)

type Wallet struct {
	KeyManager *crypto.KeyManager
	PublicKey  string
}

func NewWallet() (*Wallet, error) {
	keyManager, err := crypto.NewKeyManager()
	if err != nil {
		return nil, err
	}
	return &Wallet{
		KeyManager: keyManager,
		PublicKey:  keyManager.GetPublicKey(),
	}, nil
}

func (w *Wallet) Save(walletPath string) error {
	data, err := json.Marshal(map[string]string{
		"public_key": w.PublicKey,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(walletPath, data, 0600)
}

func Load(walletPath string) (*Wallet, error) {
	data, err := os.ReadFile(walletPath)
	if err != nil {
		return nil, err
	}

	var walletData struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(data, &walletData); err != nil {
		return nil, err
	}

	// In real implementation, you'd reconstruct the key manager
	// This is simplified for initial version
	return &Wallet{
		PublicKey: walletData.PublicKey,
	}, nil
}
