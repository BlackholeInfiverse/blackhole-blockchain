package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	// transaction "test/transaction"
	transaction "github.com/Shivam-Patel-G/blackhole-blockchain/services/wallet/wallet/transaction"
	// wallet_core "test/wallet"
	"time"

	wallet_core "github.com/Shivam-Patel-G/blackhole-blockchain/services/wallet/wallet/wallet"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/chain"
	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/blake2b"
)

var (
	UserCollection *mongo.Collection
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatalf("Mongo connect error: %v", err)
	}

	// Initialize wallet_core collections here
	wallet_core.InitMongo(client, "walletdb")

	// Assign your user collection here, adjust db and collection names
	UserCollection = client.Database("walletdb").Collection("users")
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Enter password: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	// Authenticate user
	user, err := wallet_core.AuthenticateUser(ctx, username, password)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// Get user's wallets (private keys decrypted inside)
	wallets, err := wallet_core.GetUserWallets(ctx, user, password)
	if err != nil {
		log.Fatalf("Failed to get wallets: %v", err)
	}

	if len(wallets) == 0 {
		log.Fatalf("No wallets found for user %s", username)
	}

	// For simplicity, pick the first wallet
	wallet := wallets[0]

	// Derive encryption key again to decrypt priv key for signing
	saltInput := []byte(user.PasswordSalt + wallet.WalletName)
	encryptionSalt := blake2b.Sum256(saltInput)
	encryptionKey := wallet_core.DeriveEncryptionKey(password, encryptionSalt[:])

	privKeyBytes, err := wallet_core.DecryptData(encryptionKey, wallet.EncryptedPrivKey)
	if err != nil {
		log.Fatalf("Failed to decrypt private key: %v", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// Build a transaction to sign
	tx := &chain.Transaction{
		From:      wallet.PublicKey,
		To:        "recipient_address_here",
		Amount:    10.0,
		Timestamp: time.Now().Unix(),
		Nonce:     uint64(time.Now().UnixNano()),
	}

	// Sign transaction
	_, err = transaction.SignTransaction(tx, privKey)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	// Verify signature
	pubKey, _ := btcec.ParsePubKey(privKey.PubKey().SerializeCompressed())
	valid, err := transaction.VerifyTransactionSignature(tx, pubKey)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}

	fmt.Printf("Transaction signed and verified successfully: %v\n", valid)
	fmt.Printf("Signed transaction:\n%+v\n", tx)
}
