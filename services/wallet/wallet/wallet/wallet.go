package wallet

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

// User represents a registered user in DB
type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Username     string             `bson:"username"`
	PasswordHash string             `bson:"password_hash"` // Argon2id hashed password
	PasswordSalt string             `bson:"password_salt"` // base64 salt for password hashing
	CreatedAt    time.Time          `bson:"created_at"`
}

// Wallet represents a wallet belonging to a user
type Wallet struct {
	ID                primitive.ObjectID `bson:"_id,omitempty"`
	UserID            primitive.ObjectID `bson:"user_id"`     // Reference to User
	WalletName        string             `bson:"wallet_name"` // User-friendly name
	Address           string             `bson:"address"`     // Public address
	PublicKey         string             `bson:"public_key"`
	EncryptedPrivKey  string             `bson:"encrypted_priv_key"` // base64 encrypted
	EncryptedMnemonic string             `bson:"encrypted_mnemonic"` // base64 encrypted
	CreatedAt         time.Time          `bson:"created_at"`
}

// Constants for Argon2id parameters (tunable)
const (
	ArgonTime    = 3
	ArgonMemory  = 64 * 1024
	ArgonThreads = 4
	ArgonKeyLen  = 32
)

// MongoDB collections (set these when initializing)
var (
	UserCollection   *mongo.Collection
	WalletCollection *mongo.Collection
)

// InitMongo initializes the MongoDB collections
func InitMongo(client *mongo.Client, dbName string) {
	UserCollection = client.Database(dbName).Collection("users")
	WalletCollection = client.Database(dbName).Collection("wallets")

	// Create indexes for better query performance
	UserCollection.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys:    bson.M{"username": 1},
		Options: options.Index().SetUnique(true),
	})
	WalletCollection.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.M{"user_id": 1},
	})
}

// HashPassword hashes a plain password using Argon2id with a random salt
func HashPassword(password string) (hashBase64, saltBase64 string, err error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	hash := argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)
	hashBase64 = base64.RawStdEncoding.EncodeToString(hash)
	saltBase64 = base64.RawStdEncoding.EncodeToString(salt)
	return hashBase64, saltBase64, nil
}

// VerifyPassword checks password validity against hash+salt
func VerifyPassword(password, hashBase64, saltBase64 string) bool {
	salt, err := base64.RawStdEncoding.DecodeString(saltBase64)
	if err != nil {
		return false
	}
	hash, err := base64.RawStdEncoding.DecodeString(hashBase64)
	if err != nil {
		return false
	}
	computedHash := argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, uint32(len(hash)))
	return subtleCompare(hash, computedHash)
}

// subtleCompare performs constant-time comparison to prevent timing attacks
func subtleCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte = 0
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// deriveEncryptionKey derives a symmetric key from password + salt (used for encrypting wallet keys)
// Here we use Argon2id again but with different salt to separate from password hash
func DeriveEncryptionKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)
}

// EncryptData encrypts plaintext using AES-256-GCM
func EncryptData(key []byte, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts AES-256-GCM ciphertext (base64 encoded)
func DecryptData(key []byte, ciphertextBase64 string) ([]byte, error) {
	ciphertext, err := base64.RawStdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aesGCM.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:aesGCM.NonceSize()]
	ciphertext = ciphertext[aesGCM.NonceSize():]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// RegisterUser registers a new user with hashed password
func RegisterUser(ctx context.Context, username, password string) (*User, error) {
	// Check if username exists
	count, err := UserCollection.CountDocuments(ctx, bson.M{"username": username})
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, errors.New("username already exists")
	}

	hash, salt, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := &User{
		Username:     username,
		PasswordHash: hash,
		PasswordSalt: salt,
		CreatedAt:    time.Now(),
	}
	res, err := UserCollection.InsertOne(ctx, user)
	if err != nil {
		return nil, err
	}
	user.ID = res.InsertedID.(primitive.ObjectID)
	return user, nil
}

// AuthenticateUser verifies username and password and returns the user
func AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	var user User
	err := UserCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		return nil, errors.New("invalid username or password")
	}
	if !VerifyPassword(password, user.PasswordHash, user.PasswordSalt) {
		return nil, errors.New("invalid username or password")
	}
	return &user, nil
}

// SerializeCompressedHex serializes a btcec/v2 PublicKey to a compressed hexadecimal string
func SerializeCompressedHex(pubKey *btcec.PublicKey) string {
	return hex.EncodeToString(pubKey.SerializeCompressed())
}

func GenerateWalletFromMnemonic(ctx context.Context, user *User, password string, walletName string) (*Wallet, error) {
	// 1. Generate mnemonic (12 words)
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return nil, err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, err
	}

	// 2. Derive seed from mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	// 3. Create master key (BIP32)
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	// 4. Derive purpose/account/address keys using hardened derivation
	accountKey, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 44) // purpose
	if err != nil {
		return nil, err
	}
	accountKey, err = accountKey.NewChildKey(bip32.FirstHardenedChild + 999) // coin_type (replace 999 with your coin type)
	if err != nil {
		return nil, err
	}
	accountKey, err = accountKey.NewChildKey(bip32.FirstHardenedChild + 0) // account
	if err != nil {
		return nil, err
	}
	changeKey, err := accountKey.NewChildKey(0) // external chain
	if err != nil {
		return nil, err
	}
	addressKey, err := changeKey.NewChildKey(0) // address index 0
	if err != nil {
		return nil, err
	}

	// 5. Extract private key bytes and generate priv/pub keys using btcec
	privKey, _ := btcec.PrivKeyFromBytes(addressKey.Key)
	pubKey := privKey.PubKey()

	// 6. Serialize keys
	publicKeyHex := SerializeCompressedHex(pubKey) // Implement this function to hex-encode compressed pubkey
	privateKeyBytes := privKey.Serialize()

	// 7. Create wallet (assuming CreateWallet accepts these keys and mnemonic bytes)
	return CreateWallet(ctx, user, password, walletName, publicKeyHex, publicKeyHex, privateKeyBytes, []byte(mnemonic))
}

// CreateWallet creates and stores a new wallet encrypted with key derived from password + salt
func CreateWallet(ctx context.Context, user *User, password string, walletName string, address string, publicKey string, privKey []byte, mnemonic []byte) (*Wallet, error) {
	// Derive a separate encryption key using user's password and user's password salt + some wallet-specific salt (for demo, use user salt)
	encryptionSalt := blake2b.Sum256([]byte(user.PasswordSalt + walletName))
	encryptionKey := DeriveEncryptionKey(password, encryptionSalt[:])

	encPrivKey, err := EncryptData(encryptionKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %v", err)
	}
	encMnemonic, err := EncryptData(encryptionKey, mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt mnemonic: %v", err)
	}

	wallet := &Wallet{
		UserID:            user.ID,
		WalletName:        walletName,
		Address:           address,
		PublicKey:         publicKey,
		EncryptedPrivKey:  encPrivKey,
		EncryptedMnemonic: encMnemonic,
		CreatedAt:         time.Now(),
	}
	res, err := WalletCollection.InsertOne(ctx, wallet)
	if err != nil {
		return nil, err
	}
	wallet.ID = res.InsertedID.(primitive.ObjectID)
	return wallet, nil
}

// GetUserWallets retrieves all wallets of a user, decrypting keys using password
func GetUserWallets(ctx context.Context, user *User, password string) ([]*Wallet, error) {
	cursor, err := WalletCollection.Find(ctx, bson.M{"user_id": user.ID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var wallets []*Wallet
	for cursor.Next(ctx) {
		var wallet Wallet
		if err := cursor.Decode(&wallet); err != nil {
			return nil, err
		}

		// Derive encryption key per wallet (same method as CreateWallet)
		encryptionSalt := blake2b.Sum256([]byte(user.PasswordSalt + wallet.WalletName))
		encryptionKey := DeriveEncryptionKey(password, encryptionSalt[:])

		privKeyBytes, err := DecryptData(encryptionKey, wallet.EncryptedPrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key for wallet %s: %v", wallet.WalletName, err)
		}
		mnemonicBytes, err := DecryptData(encryptionKey, wallet.EncryptedMnemonic)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt mnemonic for wallet %s: %v", wallet.WalletName, err)
		}

		// For security, do not store decrypted keys in struct; handle as needed for display or use
		fmt.Printf("Wallet %s: PrivateKey=%x, Mnemonic=%s\n", wallet.WalletName, privKeyBytes, mnemonicBytes)

		wallets = append(wallets, &wallet)
	}
	return wallets, nil
}

func GetWalletDetails(ctx context.Context, user *User, walletName string, password string) (*Wallet, []byte, []byte, error) {
	// Find the wallet with matching name and user ID
	var wallet Wallet
	err := WalletCollection.FindOne(ctx, bson.M{
		"user_id":     user.ID,
		"wallet_name": walletName,
	}).Decode(&wallet)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("wallet not found: %v", err)
	}

	// Derive encryption key
	encryptionSalt := blake2b.Sum256([]byte(user.PasswordSalt + wallet.WalletName))
	encryptionKey := DeriveEncryptionKey(password, encryptionSalt[:])

	// Decrypt private key and mnemonic
	privKeyBytes, err := DecryptData(encryptionKey, wallet.EncryptedPrivKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt private key: %v", err)
	}
	mnemonicBytes, err := DecryptData(encryptionKey, wallet.EncryptedMnemonic)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt mnemonic: %v", err)
	}

	return &wallet, privKeyBytes, mnemonicBytes, nil
}
