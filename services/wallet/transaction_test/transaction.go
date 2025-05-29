package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"

	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	// transaction "test/transaction"
	transaction "github.com/Shivam-Patel-G/blackhole-blockchain/services/wallet/transaction"
	// wallet_core "test/wallet"
	wallet_core "github.com/Shivam-Patel-G/blackhole-blockchain/services/wallet/wallet"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal("MongoDB connection error:", err)
	}
	wallet_core.InitMongo(client, "walletdb")

	reader := bufio.NewReader(os.Stdin)

	// Step 1: Authenticate User
	fmt.Print("Enter username: ")
	usernameInput, _ := reader.ReadString('\n')
	username := strings.TrimSpace(usernameInput)

	fmt.Print("Enter password: ")
	passwordInput, _ := reader.ReadString('\n')
	password := strings.TrimSpace(passwordInput)

	user, err := wallet_core.AuthenticateUser(ctx, username, password)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}
	fmt.Printf("Welcome %s!\n", user.Username)

	// Step 2: Fetch wallets for user
	wallets, err := wallet_core.GetUserWallets(ctx, user, password)
	if err != nil {
		log.Fatalf("Failed to fetch wallets: %v", err)
	}
	if len(wallets) == 0 {
		log.Fatalf("No wallets found for user")
	}

	// List wallets
	fmt.Println("Your wallets:")
	for i, w := range wallets {
		fmt.Printf("%d) %s - Address: %s\n", i+1, w.WalletName, w.Address)
	}

	// Step 3: User selects wallet
	fmt.Print("Select wallet by number: ")
	walletChoiceStr, _ := reader.ReadString('\n')
	walletChoiceStr = strings.TrimSpace(walletChoiceStr)
	walletChoice, err := strconv.Atoi(walletChoiceStr)
	if err != nil || walletChoice < 1 || walletChoice > len(wallets) {
		log.Fatalf("Invalid wallet choice")
	}
	selectedWallet := wallets[walletChoice-1]

	// Step 4: Get decrypted private key of selected wallet
	_, privKeyBytes, _, err := wallet_core.GetWalletDetails(ctx, user, selectedWallet.WalletName, password)
	if err != nil {
		log.Fatalf("Failed to decrypt wallet keys: %v", err)
	}

	// Step 5: Input transaction details
	fmt.Print("Enter recipient address: ")
	toAddrInput, _ := reader.ReadString('\n')
	toAddr := strings.TrimSpace(toAddrInput)
	if toAddr == "" {
		log.Fatalf("Recipient address cannot be empty")
	}

	fmt.Print("Enter amount to send: ")
	amountInput, _ := reader.ReadString('\n')
	amountInput = strings.TrimSpace(amountInput)
	amount, err := strconv.ParseFloat(amountInput, 64)
	if err != nil || amount <= 0 {
		log.Fatalf("Invalid amount")
	}

	// Step 6: Interact with blockchain provider
	// port := 3000
	blockchain, _ := chain.NewBlockchain(3001)
	// blockchain := transaction.DummyBlockchain{} // Replace with your real provider

	balance := blockchain.GetBalance(selectedWallet.Address)
	fmt.Printf("Your balance: %d\n", balance)
	// if amount > float64(balance) {
	// 	log.Fatalf("Insufficient balance")
	// }

	nonce := blockchain.GetNonce(selectedWallet.Address)

	// Step 7: Create and sign transaction
	tx := &chain.Transaction{
		From:      selectedWallet.Address,
		To:        toAddr,
		Amount:    uint64(amount),
		Nonce:     uint64(nonce),
		Timestamp: time.Now().Unix(), // Set timestamp explicitly
	}
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	sig, err := transaction.SignTransaction(tx, privKey)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}
	tx.Signature = sig
	pubKeyBytes := privKey.PubKey().SerializeCompressed()
	tx.PublicKey = pubKeyBytes

	// Step 6: Verify the transaction signature

	pubKey := privKey.PubKey()
	valid, err := transaction.VerifyTransactionSignature(tx, pubKey)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}
	fmt.Println("valid :", valid)

	// ✅ Check if recipient address exists
	ctx1, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	valid_address, err := transaction.IsValidAddress(ctx1, toAddr)
	if err != nil {
		log.Fatalf("Failed to validate recipient address: %v", err)
	}
	if !valid_address {
		log.Fatalf("Invalid recipient address: %s does not exist", toAddr)
	}

	// Show transaction JSON
	txJSON, _ := json.MarshalIndent(tx, "", "  ")
	fmt.Println("Signed transaction:")
	fmt.Println(string(txJSON))

	// // Step 8: Send transaction to blockchain network
	// success := blockchain.ProcessTransaction(tx)
	// if success != nil {
	// 	log.Println("Transaction failed to process", success)
	// }

	// Create a temporary libp2p host
	ctx2 := context.Background()
	host, err := libp2p.New()
	if err != nil {
		log.Fatal("Failed to create libp2p host:", err)
	}

	// Replace with the actual peer ID and address of your running node
	peerAddr := "/ip4/192.168.0.73/tcp/3000/p2p/12D3KooWAJ7A2akZFNGzgwFKK3H78HydTozbkNmQjkKC82pAmTDN"
	maddr, err := multiaddr.NewMultiaddr(peerAddr)
	if err != nil {
		log.Fatal("Invalid multiaddr:", err)
	}

	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		log.Fatal("Failed to get peer info:", err)
	}

	// Connect to peer
	if err := host.Connect(ctx2, *info); err != nil {
		log.Println("the info :", info)
		log.Fatal("Failed to connect to peer:", err)
	}

	// Open stream
	stream, err := host.NewStream(ctx2, info.ID, "/blackhole/1.0.0")
	if err != nil {
		log.Fatal("Failed to open stream:", err)
	}

	// Step 2: Encode the transaction to bytes
	var txBuf bytes.Buffer
	txEncoder := gob.NewEncoder(&txBuf)
	if err := txEncoder.Encode(tx); err != nil {
		log.Fatalf("❌ Failed to encode transaction: %v", err)
	}

	// Step 3: Wrap it in a Message
	msg := &chain.Message{
		Type:    chain.MessageTypeTx, // ✅ Use your constant
		Data:    txBuf.Bytes(),
		Version: chain.ProtocolVersion, // e.g., 2
	}

	// Step 4: Send the message
	encoder := gob.NewEncoder(stream)
	if err := encoder.Encode(msg); err != nil {
		log.Fatalf("❌ Failed to encode message: %v", err)
	}

	fmt.Println("✅ Transaction sent to peer.")

	fmt.Println("✅ Transaction (as part of a Message) sent to peer using GOB.")

}
