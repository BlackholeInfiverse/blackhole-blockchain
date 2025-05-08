package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
)

type KeyManager struct {
	privateKey *ecdsa.PrivateKey
}

func (km *KeyManager) Sign(data []byte) (string, error) {
	panic("unimplemented")
}

func NewKeyManager() (*KeyManager, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyManager{privateKey: privateKey}, nil
}

func (km *KeyManager) GetPublicKey() string {
	return hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(),
		km.privateKey.PublicKey.X,
		km.privateKey.PublicKey.Y))
}
