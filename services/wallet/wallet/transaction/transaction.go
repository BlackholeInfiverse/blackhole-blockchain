package transaction

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	// wallet_core "test/wallet"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/chain"
	wallet_core "github.com/Shivam-Patel-G/blackhole-blockchain/services/wallet/wallet/wallet"

	"golang.org/x/crypto/blake2b"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Transaction represents an OTC-style transaction
type Transaction struct {
	From      string  `json:"from"`
	To        string  `json:"to"`
	Amount    float64 `json:"amount"`
	Timestamp int64   `json:"timestamp"`
	Nonce     uint64  `json:"nonce"`
	Signature []byte  `json:"signature,omitempty"`
}

// SignTransaction signs a transaction using the sender's private key
func SignTransaction(tx *chain.Transaction, privKey *btcec.PrivateKey) ([]byte, error) {
	txCopy := *tx
	txCopy.Signature = nil

	txBytes, err := json.Marshal(txCopy)
	if err != nil {
		return nil, err
	}

	hash := blake2b.Sum256(txBytes)
	signature := ecdsa.Sign(privKey, hash[:])
	tx.Signature = signature.Serialize()
	return tx.Signature, nil
}

// VerifyTransactionSignature verifies a transaction's signature
func VerifyTransactionSignature(tx *chain.Transaction, pubKey *btcec.PublicKey) (bool, error) {
	if tx.Signature == nil {
		return false, fmt.Errorf("no signature found")
	}
	txCopy := *tx
	txCopy.Signature = nil

	txBytes, err := json.Marshal(txCopy)
	if err != nil {
		return false, err
	}
	hash := blake2b.Sum256(txBytes)
	sig, err := ecdsa.ParseDERSignature(tx.Signature)
	if err != nil {
		return false, err
	}

	return sig.Verify(hash[:], pubKey), nil
}

// UseWalletAndSignTx loads a wallet, decrypts the key, signs a transaction
func UseWalletAndSignTx(ctx context.Context, wallet *wallet_core.Wallet, password string, toAddress string, amount float64) {
	// Derive encryption key
	encryptionSalt := blake2b.Sum256([]byte(wallet.WalletName + wallet.Address)) // could also use user salt
	encryptionKey := wallet_core.DeriveEncryptionKey(password, encryptionSalt[:])

	// Decrypt private key
	decryptedPrivKeyBytes, err := wallet_core.DecryptData(encryptionKey, wallet.EncryptedPrivKey)
	if err != nil {
		log.Fatalf("Failed to decrypt private key: %v", err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(decryptedPrivKeyBytes)

	// Parse public key
	pubKey, err := btcec.ParsePubKey(privKey.PubKey().SerializeCompressed())
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
	}

	// Build transaction
	tx := &chain.Transaction{
		From:      wallet.PublicKey,
		To:        toAddress,
		Amount:    uint64(amount),
		Timestamp: time.Now().Unix(),
		Nonce:     uint64(time.Now().UnixNano()),
	}

	// Sign transaction
	_, err = SignTransaction(tx, privKey)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	// Verify
	valid, err := VerifyTransactionSignature(tx, pubKey)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	fmt.Printf("Transaction signature is valid: %v\n", valid)

	txJSON, _ := json.MarshalIndent(tx, "", "  ")
	fmt.Println("Signed Transaction:")
	fmt.Println(string(txJSON))
}

func IsValidAddress(ctx context.Context, address string) (bool, error) {
	if address == "" {
		return false, fmt.Errorf("address is empty")
	}

	filter := bson.M{"address": address}
	var result bson.M
	err := wallet_core.WalletCollection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, nil // Address does not exist
		}
		return false, err // Some DB error
	}

	return true, nil
}

type BlockchainProvider interface {
	GetBalance(address string) uint64
	GetNonce(address string) uint64
	ProcessTransaction(tx *chain.Transaction) error
}

// Example dummy implementation
type DummyBlockchain struct{}

func (d DummyBlockchain) GetBalance(address string) float64 {
	return 1000.0 // dummy balance
}

func (d DummyBlockchain) GetNonce(address string) int {
	return 1 // dummy nonce
}

func (d DummyBlockchain) ProcessTransaction(tx Transaction) bool {
	// In reality, broadcast tx to blockchain network and wait for success
	fmt.Println("Processing transaction on blockchain network...")
	time.Sleep(time.Second)
	return true
}
