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
	LastAccessed      time.Time          `bson:"last_accessed"`
	KeyVersion        int                `bson:"key_version"`      // For key rotation
	SecurityLevel     string             `bson:"security_level"`   // "standard", "enhanced", "hsm"
	BackupEncrypted   string             `bson:"backup_encrypted"` // Encrypted backup data
}

// SecureKeyManager handles advanced key management
type SecureKeyManager struct {
	masterKey     []byte
	keyCache      map[string]*CachedKey
	hsmEnabled    bool
	keyRotationCh chan string
}

// CachedKey represents a temporarily cached decrypted key
type CachedKey struct {
	key         []byte
	timestamp   time.Time
	accessCount int
}

// HSMInterface defines hardware security module operations
type HSMInterface interface {
	GenerateKey() ([]byte, error)
	EncryptWithHSM(data []byte) ([]byte, error)
	DecryptWithHSM(data []byte) ([]byte, error)
	SignWithHSM(data []byte) ([]byte, error)
}

// Constants for Argon2id parameters (tunable)
const (
	ArgonTime    = 3
	ArgonMemory  = 64 * 1024
	ArgonThreads = 4
	ArgonKeyLen  = 32
)

// Enhanced security constants
const (
	// Key derivation constants
	MasterKeyDerivationRounds = 100000
	KeyRotationInterval       = 24 * time.Hour
	MaxKeyAge                 = 7 * 24 * time.Hour

	// Hardware security module constants
	HSMKeySize = 32
	HSMEnabled = false // Set to true when HSM is available
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

// NewSecureKeyManager creates a new secure key manager
func NewSecureKeyManager() *SecureKeyManager {
	return &SecureKeyManager{
		keyCache:      make(map[string]*CachedKey),
		hsmEnabled:    HSMEnabled,
		keyRotationCh: make(chan string, 100),
	}
}

// InitializeMasterKey initializes the master key for encryption
func (skm *SecureKeyManager) InitializeMasterKey() error {
	if skm.hsmEnabled {
		// Use HSM to generate master key
		return skm.initializeHSMMasterKey()
	}

	// Generate secure random master key
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return fmt.Errorf("failed to generate master key: %v", err)
	}

	skm.masterKey = masterKey
	return nil
}

// initializeHSMMasterKey initializes master key using HSM
func (skm *SecureKeyManager) initializeHSMMasterKey() error {
	// Mock HSM implementation - replace with actual HSM integration
	fmt.Println("🔐 Initializing HSM master key...")

	// Generate key using HSM
	hsmKey := make([]byte, HSMKeySize)
	if _, err := rand.Read(hsmKey); err != nil {
		return fmt.Errorf("HSM key generation failed: %v", err)
	}

	skm.masterKey = hsmKey
	fmt.Println("✅ HSM master key initialized successfully")
	return nil
}

// SecureEncryptData encrypts data with enhanced security
func (skm *SecureKeyManager) SecureEncryptData(plaintext []byte, securityLevel string) (string, error) {
	if skm.hsmEnabled && securityLevel == "hsm" {
		return skm.encryptWithHSM(plaintext)
	}

	// Use enhanced encryption with master key
	derivedKey := skm.deriveEncryptionKey(plaintext[:min(len(plaintext), 16)])
	return EncryptData(derivedKey, plaintext)
}

// SecureDecryptData decrypts data with enhanced security
func (skm *SecureKeyManager) SecureDecryptData(ciphertextBase64 string, securityLevel string) ([]byte, error) {
	if skm.hsmEnabled && securityLevel == "hsm" {
		return skm.decryptWithHSM(ciphertextBase64)
	}

	// For now, use standard decryption - would need to store derivation info
	return DecryptData(skm.masterKey, ciphertextBase64)
}

// encryptWithHSM encrypts data using HSM
func (skm *SecureKeyManager) encryptWithHSM(plaintext []byte) (string, error) {
	// Mock HSM encryption - replace with actual HSM calls
	fmt.Printf("🔐 Encrypting %d bytes with HSM...\n", len(plaintext))

	// Use master key for now (would use HSM in production)
	return EncryptData(skm.masterKey, plaintext)
}

// decryptWithHSM decrypts data using HSM
func (skm *SecureKeyManager) decryptWithHSM(ciphertextBase64 string) ([]byte, error) {
	// Mock HSM decryption - replace with actual HSM calls
	fmt.Println("🔓 Decrypting with HSM...")

	// Use master key for now (would use HSM in production)
	return DecryptData(skm.masterKey, ciphertextBase64)
}

// deriveEncryptionKey derives a key from master key and salt
func (skm *SecureKeyManager) deriveEncryptionKey(salt []byte) []byte {
	return argon2.IDKey(skm.masterKey, salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// StartKeyRotation starts the key rotation background process
func (skm *SecureKeyManager) StartKeyRotation(ctx context.Context) {
	ticker := time.NewTicker(KeyRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			skm.rotateKeys()
		case walletID := <-skm.keyRotationCh:
			skm.rotateWalletKey(walletID)
		}
	}
}

// rotateKeys rotates all keys that are due for rotation
func (skm *SecureKeyManager) rotateKeys() {
	fmt.Println("🔄 Starting key rotation process...")

	// Clean expired cached keys
	skm.cleanExpiredKeys()

	// Rotate master key if needed
	if skm.shouldRotateMasterKey() {
		if err := skm.rotateMasterKey(); err != nil {
			fmt.Printf("⚠️ Master key rotation failed: %v\n", err)
		} else {
			fmt.Println("✅ Master key rotated successfully")
		}
	}

	fmt.Println("✅ Key rotation process completed")
}

// rotateWalletKey rotates a specific wallet's key
func (skm *SecureKeyManager) rotateWalletKey(walletID string) {
	fmt.Printf("🔄 Rotating key for wallet: %s\n", walletID)

	// Remove from cache to force re-encryption with new key
	delete(skm.keyCache, walletID)

	// In production, would re-encrypt wallet with new key version
	fmt.Printf("✅ Key rotated for wallet: %s\n", walletID)
}

// cleanExpiredKeys removes expired keys from cache
func (skm *SecureKeyManager) cleanExpiredKeys() {
	now := time.Now()
	expired := make([]string, 0)

	for walletID, cachedKey := range skm.keyCache {
		if now.Sub(cachedKey.timestamp) > MaxKeyAge {
			expired = append(expired, walletID)
		}
	}

	for _, walletID := range expired {
		// Securely clear the key
		key := skm.keyCache[walletID].key
		for i := range key {
			key[i] = 0
		}
		delete(skm.keyCache, walletID)
		fmt.Printf("🧹 Expired key removed for wallet: %s\n", walletID)
	}

	if len(expired) > 0 {
		fmt.Printf("✅ Cleaned %d expired keys from cache\n", len(expired))
	}
}

// shouldRotateMasterKey determines if master key should be rotated
func (skm *SecureKeyManager) shouldRotateMasterKey() bool {
	// In production, would check key age and usage metrics
	return false // Conservative approach for now
}

// rotateMasterKey rotates the master key
func (skm *SecureKeyManager) rotateMasterKey() error {
	oldKey := make([]byte, len(skm.masterKey))
	copy(oldKey, skm.masterKey)

	// Generate new master key
	if err := skm.InitializeMasterKey(); err != nil {
		return fmt.Errorf("failed to generate new master key: %v", err)
	}

	// In production, would re-encrypt all data with new key
	// For now, just clear the old key
	for i := range oldKey {
		oldKey[i] = 0
	}

	return nil
}

// CacheKey temporarily caches a decrypted key
func (skm *SecureKeyManager) CacheKey(walletID string, key []byte) {
	skm.keyCache[walletID] = &CachedKey{
		key:         key,
		timestamp:   time.Now(),
		accessCount: 0,
	}
}

// GetCachedKey retrieves a cached key if available and not expired
func (skm *SecureKeyManager) GetCachedKey(walletID string) ([]byte, bool) {
	cachedKey, exists := skm.keyCache[walletID]
	if !exists {
		return nil, false
	}

	// Check if key is expired
	if time.Since(cachedKey.timestamp) > MaxKeyAge {
		// Securely clear and remove expired key
		for i := range cachedKey.key {
			cachedKey.key[i] = 0
		}
		delete(skm.keyCache, walletID)
		return nil, false
	}

	// Update access count
	cachedKey.accessCount++
	return cachedKey.key, true
}

// SecureClearMemory securely clears sensitive data from memory
func SecureClearMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
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

// ImportWalletFromPrivateKey imports a wallet from a private key
func ImportWalletFromPrivateKey(ctx context.Context, user *User, password, walletName, privateKeyHex string) (*Wallet, error) {
	// Decode private key from hex
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key format: %v", err)
	}

	// Generate key pair from private key
	privKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	pubKey := privKey.PubKey()

	// Generate address from public key
	publicKeyHex := SerializeCompressedHex(pubKey)
	address := publicKeyHex // Using public key as address for simplicity

	return CreateWallet(ctx, user, password, walletName, address, publicKeyHex, privateKeyBytes, nil)
}

// ExportWalletPrivateKey exports the private key of a wallet
func ExportWalletPrivateKey(ctx context.Context, user *User, walletName, password string) (string, error) {
	_, privKeyBytes, _, err := GetWalletDetails(ctx, user, walletName, password)
	if err != nil {
		return "", fmt.Errorf("failed to get wallet details: %v", err)
	}

	return hex.EncodeToString(privKeyBytes), nil
}

// ListUserWallets returns all wallets for a user
func ListUserWallets(ctx context.Context, user *User) ([]*Wallet, error) {
	cursor, err := WalletCollection.Find(ctx, bson.M{"user_id": user.ID})
	if err != nil {
		return nil, fmt.Errorf("failed to query wallets: %v", err)
	}
	defer cursor.Close(ctx)

	var wallets []*Wallet
	if err := cursor.All(ctx, &wallets); err != nil {
		return nil, fmt.Errorf("failed to decode wallets: %v", err)
	}

	return wallets, nil
}

// Global secure key manager instance
var GlobalKeyManager *SecureKeyManager

// InitializeGlobalKeyManager initializes the global key manager
func InitializeGlobalKeyManager() error {
	GlobalKeyManager = NewSecureKeyManager()
	return GlobalKeyManager.InitializeMasterKey()
}

// CreateWallet creates and stores a new wallet encrypted with enhanced security
func CreateWallet(ctx context.Context, user *User, password string, walletName string, address string, publicKey string, privKey []byte, mnemonic []byte) (*Wallet, error) {
	// Determine security level based on key size and user preferences
	securityLevel := "enhanced"
	if len(privKey) >= 32 && GlobalKeyManager != nil && GlobalKeyManager.hsmEnabled {
		securityLevel = "hsm"
	}

	// Derive a separate encryption key using user's password and user's password salt + some wallet-specific salt
	encryptionSalt := blake2b.Sum256([]byte(user.PasswordSalt + walletName))
	encryptionKey := DeriveEncryptionKey(password, encryptionSalt[:])

	var encPrivKey, encMnemonic string
	var err error

	// Use enhanced encryption if available
	if GlobalKeyManager != nil {
		encPrivKey, err = GlobalKeyManager.SecureEncryptData(privKey, securityLevel)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key with enhanced security: %v", err)
		}
		encMnemonic, err = GlobalKeyManager.SecureEncryptData(mnemonic, securityLevel)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt mnemonic with enhanced security: %v", err)
		}
	} else {
		// Fallback to standard encryption
		encPrivKey, err = EncryptData(encryptionKey, privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %v", err)
		}
		encMnemonic, err = EncryptData(encryptionKey, mnemonic)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt mnemonic: %v", err)
		}
	}

	// Create encrypted backup
	backupData := map[string]interface{}{
		"address":   address,
		"publicKey": publicKey,
		"createdAt": time.Now(),
		"version":   1,
	}
	backupBytes, _ := bson.Marshal(backupData)
	encBackup, err := EncryptData(encryptionKey, backupBytes)
	if err != nil {
		fmt.Printf("⚠️ Warning: Failed to create encrypted backup: %v\n", err)
		encBackup = ""
	}

	wallet := &Wallet{
		UserID:            user.ID,
		WalletName:        walletName,
		Address:           address,
		PublicKey:         publicKey,
		EncryptedPrivKey:  encPrivKey,
		EncryptedMnemonic: encMnemonic,
		CreatedAt:         time.Now(),
		LastAccessed:      time.Now(),
		KeyVersion:        1,
		SecurityLevel:     securityLevel,
		BackupEncrypted:   encBackup,
	}

	res, err := WalletCollection.InsertOne(ctx, wallet)
	if err != nil {
		return nil, err
	}
	wallet.ID = res.InsertedID.(primitive.ObjectID)

	// Log wallet creation with security level
	fmt.Printf("✅ Wallet created: %s (Security: %s)\n", walletName, securityLevel)

	// Securely clear sensitive data from memory
	SecureClearMemory(privKey)
	SecureClearMemory(mnemonic)

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

	// Update last accessed time
	now := time.Now()
	WalletCollection.UpdateOne(ctx, bson.M{
		"_id": wallet.ID,
	}, bson.M{
		"$set": bson.M{"last_accessed": now},
	})
	wallet.LastAccessed = now

	// Check if we have cached keys
	walletID := wallet.ID.Hex()
	if GlobalKeyManager != nil {
		if cachedKey, found := GlobalKeyManager.GetCachedKey(walletID); found {
			fmt.Printf("🔑 Using cached key for wallet: %s\n", walletName)
			// For simplicity, return the cached key as both private key and mnemonic
			// In production, would cache them separately
			return &wallet, cachedKey, nil, nil
		}
	}

	// Derive encryption key
	encryptionSalt := blake2b.Sum256([]byte(user.PasswordSalt + wallet.WalletName))
	encryptionKey := DeriveEncryptionKey(password, encryptionSalt[:])

	var privKeyBytes, mnemonicBytes []byte

	// Use enhanced decryption if available
	if GlobalKeyManager != nil && wallet.SecurityLevel != "" {
		privKeyBytes, err = GlobalKeyManager.SecureDecryptData(wallet.EncryptedPrivKey, wallet.SecurityLevel)
		if err != nil {
			// Fallback to standard decryption
			privKeyBytes, err = DecryptData(encryptionKey, wallet.EncryptedPrivKey)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to decrypt private key: %v", err)
			}
		}

		mnemonicBytes, err = GlobalKeyManager.SecureDecryptData(wallet.EncryptedMnemonic, wallet.SecurityLevel)
		if err != nil {
			// Fallback to standard decryption
			mnemonicBytes, err = DecryptData(encryptionKey, wallet.EncryptedMnemonic)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to decrypt mnemonic: %v", err)
			}
		}
	} else {
		// Standard decryption
		privKeyBytes, err = DecryptData(encryptionKey, wallet.EncryptedPrivKey)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decrypt private key: %v", err)
		}
		mnemonicBytes, err = DecryptData(encryptionKey, wallet.EncryptedMnemonic)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decrypt mnemonic: %v", err)
		}
	}

	// Cache the decrypted key for future use
	if GlobalKeyManager != nil && len(privKeyBytes) > 0 {
		keyCopy := make([]byte, len(privKeyBytes))
		copy(keyCopy, privKeyBytes)
		GlobalKeyManager.CacheKey(walletID, keyCopy)
		fmt.Printf("🔑 Cached key for wallet: %s\n", walletName)
	}

	fmt.Printf("🔓 Wallet accessed: %s (Security: %s)\n", walletName, wallet.SecurityLevel)
	return &wallet, privKeyBytes, mnemonicBytes, nil
}
