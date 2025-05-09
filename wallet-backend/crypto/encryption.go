package crypto
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
)

var encryptionKey = []byte("0123456789abcdef0123456789abcdef") // 32 bytes = AES-256

func EncryptPrivateKey(km *KeyManager) (string, error) {
	plainBytes := km.GetPrivateKeyBytes()

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plainBytes))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainBytes)

	return hex.EncodeToString(ciphertext), nil
}

func DecryptPrivateKey(encryptedHex string) (*KeyManager, error) {
	ciphertext, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	d := new(big.Int).SetBytes(ciphertext)
	priv := new(ecdsa.PrivateKey)
	priv.D = d
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d.Bytes())

	return &KeyManager{privateKey: priv}, nil
}
