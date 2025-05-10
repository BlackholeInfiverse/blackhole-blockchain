package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	bip39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
)

// KeyManager manages cryptographic keys for the wallet
type KeyManager struct {
	privateKey *ecdsa.PrivateKey
}

// NewKeyManagerWithMnemonic creates a new key manager with a generated mnemonic
func NewKeyManagerWithMnemonic() (*KeyManager, string, error) {
	entropy, err := bip39.NewEntropy(128) // 12-word mnemonic
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate entropy: %v", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate mnemonic: %v", err)
	}

	km, err := deriveKeyManagerFromMnemonic(mnemonic)
	if err != nil {
		return nil, "", err
	}

	return km, mnemonic, nil
}

// RestoreKeyManagerFromMnemonic restores a key manager from mnemonic phrase
func RestoreKeyManagerFromMnemonic(mnemonic string) (*KeyManager, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("invalid mnemonic phrase")
	}
	return deriveKeyManagerFromMnemonic(mnemonic)
}

func deriveKeyManagerFromMnemonic(mnemonic string) (*KeyManager, error) {
	seed := bip39.NewSeed(mnemonic, "") // No passphrase
	privKey, err := deriveKeyFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key from seed: %v", err)
	}
	return &KeyManager{privateKey: privKey}, nil
}

func deriveKeyFromSeed(seed []byte) (*ecdsa.PrivateKey, error) {
	// Use PBKDF2 to derive a deterministic private key from the seed
	hash := pbkdf2.Key(seed, []byte("blackhole-wallet-salt"), 2048, 32, sha256.New)
	d := new(big.Int).SetBytes(hash)

	// Ensure the derived key is valid for P256 curve
	curve := elliptic.P256()
	if d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("derived private key is too large")
	}

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: d,
	}
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return priv, nil
}

// GetPublicKey returns the compressed public key in hex format
func (km *KeyManager) GetPublicKey() string {
	if km.privateKey == nil {
		return ""
	}
	return hex.EncodeToString(elliptic.MarshalCompressed(
		km.privateKey.PublicKey.Curve,
		km.privateKey.PublicKey.X,
		km.privateKey.PublicKey.Y,
	))
}

// GetAddress generates an Ethereum-style address from the public key
func (km *KeyManager) GetAddress() string {
	pubKey := km.GetPublicKey()
	if pubKey == "" {
		return ""
	}

	// Hash the public key
	pubBytes, _ := hex.DecodeString(pubKey)
	hash := sha256.Sum256(pubBytes)

	// Take last 20 bytes as address (Ethereum-style)
	addressBytes := hash[len(hash)-20:]
	return hex.EncodeToString(addressBytes)
}

// Sign signs arbitrary data using ECDSA
func (km *KeyManager) Sign(data []byte) ([]byte, error) {
	if km.privateKey == nil {
		return nil, errors.New("private key not initialized")
	}

	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, km.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %v", err)
	}

	// Encode the signature as R || S
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

// Verify verifies a signature against the public key
func (km *KeyManager) Verify(data, signature []byte) (bool, error) {
	if km.privateKey == nil {
		return false, errors.New("private key not initialized")
	}
	if len(signature) != 64 { // 32 bytes for R + 32 bytes for S
		return false, errors.New("invalid signature length")
	}

	hash := sha256.Sum256(data)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return ecdsa.Verify(&km.privateKey.PublicKey, hash[:], r, s), nil
}

// GetPrivateKey returns the ECDSA private key
func (km *KeyManager) GetPrivateKey() *ecdsa.PrivateKey {
	return km.privateKey
}

// GetPublicKeyObject returns the ECDSA public key
func (km *KeyManager) GetPublicKeyObject() *ecdsa.PublicKey {
	if km.privateKey == nil {
		return nil
	}
	return &km.privateKey.PublicKey
}

// NewKeyManagerFromPublicKey creates a key manager from public key hex string
func NewKeyManagerFromPublicKey(publicKeyHex string) (*KeyManager, error) {
	if publicKeyHex == "" {
		return nil, errors.New("empty public key")
	}

	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %v", err)
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubBytes)
	if x == nil {
		return nil, errors.New("invalid public key format")
	}

	return &KeyManager{
		privateKey: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     x,
				Y:     y,
			},
		},
	}, nil
}
