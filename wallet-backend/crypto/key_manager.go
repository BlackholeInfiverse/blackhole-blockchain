package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"

	bip39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
)

type KeyManager struct {
	privateKey *ecdsa.PrivateKey
}

func NewKeyManagerWithMnemonic() (*KeyManager, string, error) {
	entropy, err := bip39.NewEntropy(128) // 12-word mnemonic
	if err != nil {
		return nil, "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, "", err
	}

	seed := bip39.NewSeed(mnemonic, "") // No passphrase

	privKey, err := deriveKeyFromSeed(seed)
	if err != nil {
		return nil, "", err
	}

	return &KeyManager{privateKey: privKey}, mnemonic, nil
}

func RestoreKeyManagerFromMnemonic(mnemonic string) (*KeyManager, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("invalid mnemonic")
	}

	seed := bip39.NewSeed(mnemonic, "")
	privKey, err := deriveKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}
	return &KeyManager{privateKey: privKey}, nil
}

func deriveKeyFromSeed(seed []byte) (*ecdsa.PrivateKey, error) {
	hash := pbkdf2.Key(seed, []byte("blackhole-wallet"), 2048, 32, sha256.New)
	d := new(big.Int).SetBytes(hash)
	priv := new(ecdsa.PrivateKey)
	priv.D = d
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d.Bytes())
	return priv, nil
}

func (km *KeyManager) GetPublicKey() string {
	return hex.EncodeToString(elliptic.MarshalCompressed(
		elliptic.P256(),
		km.privateKey.PublicKey.X,
		km.privateKey.PublicKey.Y,
	))
}

func (km *KeyManager) GetAddress() string {
	pub := km.GetPublicKey()
	hash := sha256.Sum256([]byte(pub))
	return hex.EncodeToString(hash[:20]) // first 20 bytes of hash
}

func (km *KeyManager) GetPrivateKeyBytes() []byte {
	return km.privateKey.D.Bytes()
}
