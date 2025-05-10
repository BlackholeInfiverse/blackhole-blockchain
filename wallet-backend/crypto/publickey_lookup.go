package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
)

// Temporary mapping; in production this would be from chain state or address book
var addressToPubKeyMap = map[string]string{}

// Call this after creating a wallet or transaction
func RegisterPublicKey(address, pubKey string) {
	addressToPubKeyMap[address] = pubKey
}

// Convert stored public key back to *ecdsa.PublicKey
func GetPublicKeyFromAddress(address string) (*ecdsa.PublicKey, error) {
	pubHex, ok := addressToPubKeyMap[address]
	if !ok {
		return nil, errors.New("public key not registered")
	}

	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, err
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubBytes)
	if x == nil || y == nil {
		return nil, errors.New("failed to unmarshal public key")
	}

	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
