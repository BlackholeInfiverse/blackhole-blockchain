package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"

	"errors"
)

func GenerateKeyPair() (*ecdsa.PrivateKey, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, "", err
	}

	return privateKey, hex.EncodeToString(pubKeyBytes), nil
}
func ParsePublicKey(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	pubInterface, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not ECDSA public key")
	}
	return pubKey, nil
}
func PublicKeyToString(pubKey *ecdsa.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pubKeyBytes), nil
}
