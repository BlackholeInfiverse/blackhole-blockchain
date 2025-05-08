package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
)

type KeyManager struct {
	privateKey *ecdsa.PrivateKey
}

func NewKeyManager() (*KeyManager, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyManager{privateKey: privKey}, nil
}

func NewKeyManagerFromPrivateKeyHex(hexKey string) (*KeyManager, error) {
	bytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(bytes) != 32 {
		return nil, errors.New("invalid private key length")
	}

	privKey := new(ecdsa.PrivateKey)
	privKey.D = new(big.Int).SetBytes(bytes)
	privKey.PublicKey.Curve = elliptic.P256()
	privKey.PublicKey.X, privKey.PublicKey.Y = privKey.PublicKey.Curve.ScalarBaseMult(bytes)

	return &KeyManager{privateKey: privKey}, nil
}

func (km *KeyManager) GetPublicKey() string {
	return hex.EncodeToString(elliptic.MarshalCompressed(
		elliptic.P256(),
		km.privateKey.PublicKey.X,
		km.privateKey.PublicKey.Y,
	))
}

func (km *KeyManager) GetPrivateKeyHex() string {
	return hex.EncodeToString(km.privateKey.D.Bytes())
}

func DeriveAddress(publicKey string) string {
	// You can replace this with SHA256 + RIPEMD160, etc.
	// For now, we’ll just shorten the public key
	if len(publicKey) > 40 {
		return publicKey[len(publicKey)-40:]
	}
	return publicKey
}
