package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	//"encoding/pem"
	"errors"
	"fmt"
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

func ParsePublicKey(pubKeyHex string) (*ecdsa.PublicKey, error) {
	if pubKeyHex == "" {
		return nil, errors.New("empty public key")
	}

	keyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return ecdsaPubKey, nil
}

func PrivateKeyToString(privateKey *ecdsa.PrivateKey) (string, error) {
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(keyBytes), nil
}

func StringToPrivateKey(keyStr string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, err
	}
	return x509.ParseECPrivateKey(keyBytes)
}