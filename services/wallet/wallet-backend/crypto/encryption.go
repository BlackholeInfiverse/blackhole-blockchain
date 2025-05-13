package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

const (
	keyDerivationIterations = 100000
	saltSize                = 32
)

// EncryptPrivateKey encrypts the private key from KeyManager using AES-256-GCM
func EncryptPrivateKey(km *KeyManager, password string) (string, error) {
	if km == nil || km.privateKey == nil {
		return "", errors.New("invalid key manager or private key")
	}

	// Convert private key to bytes
	privateKeyBytes := km.privateKey.D.Bytes()

	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	// Derive encryption key from password
	key := pbkdf2.Key([]byte(password), salt, keyDerivationIterations, 32, sha256.New)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the private key
	ciphertext := gcm.Seal(nil, nonce, privateKeyBytes, nil)

	// Combine salt + nonce + ciphertext
	encryptedData := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	encryptedData = append(encryptedData, salt...)
	encryptedData = append(encryptedData, nonce...)
	encryptedData = append(encryptedData, ciphertext...)

	return hex.EncodeToString(encryptedData), nil
}

// DecryptPrivateKey decrypts the private key and returns a KeyManager
func DecryptPrivateKey(encryptedHex string, password string) (*KeyManager, error) {
	// Decode hex string
	encryptedData, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %v", err)
	}

	// Check minimum length (salt + nonce)
	if len(encryptedData) < saltSize+12 {
		return nil, errors.New("invalid encrypted data length")
	}

	// Extract components
	salt := encryptedData[:saltSize]
	encryptedData = encryptedData[saltSize:]

	// Derive encryption key
	key := pbkdf2.Key([]byte(password), salt, keyDerivationIterations, 32, sha256.New)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("invalid encrypted data length")
	}

	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	// Decrypt the private key
	privateKeyBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	// Reconstruct ECDSA private key
	d := new(big.Int).SetBytes(privateKeyBytes)
	priv := &ecdsa.PrivateKey{
		D: d,
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d.Bytes())

	return &KeyManager{privateKey: priv}, nil
}
