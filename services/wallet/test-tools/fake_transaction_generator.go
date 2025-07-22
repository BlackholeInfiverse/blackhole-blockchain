package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	wallet "github.com/Shivam-Patel-G/blackhole-blockchain/services/wallet/wallet"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Wallet addresses provided by the user
const (
	SHIVAM_ADDRESS  = "03d0f85fe18231c5aa28cb3b405652a9f3ee1e9ef08aad36ad4c850c52f7bed10f"
	SHIVAM2_ADDRESS = "02dc2e3faa525d9a343742e625a1e192560100288635d803a8883e22f7b65eef59"
)

// Transaction types and tokens for variety
var (
	TOKEN_SYMBOLS = []string{"BHX", "USDT", "ETH", "BTC", "DOT"}
	TX_TYPES      = []int{chain.TokenTransfer, chain.RegularTransfer, chain.StakeDeposit}
	TX_TYPE_NAMES = map[int]string{
		chain.TokenTransfer:   "Token Transfer",
		chain.RegularTransfer: "Regular Transfer",
		chain.StakeDeposit:    "Stake Deposit",
	}
)

// FakeTransactionGenerator handles the generation of fake transactions
type FakeTransactionGenerator struct {
	mongoClient      *mongo.Client
	blockchainClient *wallet.BlockchainClient
	ctx              context.Context
	peerAddr         string
}

// TransactionStats tracks generated transaction statistics
type TransactionStats struct {
	TotalGenerated int
	ByType         map[string]int
	ByToken        map[string]int
	StartTime      time.Time
}

func NewFakeTransactionGenerator(peerAddr string) (*FakeTransactionGenerator, error) {
	ctx := context.Background()

	// Connect to MongoDB
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	// Test connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %v", err)
	}

	// Initialize wallet collections
	db := client.Database("walletdb")
	wallet.UserCollection = db.Collection("users")
	wallet.WalletCollection = db.Collection("wallets")
	wallet.TransactionCollection = db.Collection("transactions")

	// Initialize blockchain client
	fmt.Println("🔗 Initializing blockchain client...")
	if err := wallet.InitBlockchainClient(5000); err != nil { // Use port 5000 for generator
		return nil, fmt.Errorf("failed to initialize blockchain client: %v", err)
	}

	// Connect to blockchain node if peer address provided
	if peerAddr != "" {
		fmt.Printf("🌐 Connecting to blockchain node: %s\n", peerAddr)
		if err := wallet.DefaultBlockchainClient.ConnectToBlockchain(peerAddr); err != nil {
			return nil, fmt.Errorf("failed to connect to blockchain node: %v", err)
		}
		fmt.Println("✅ Successfully connected to blockchain node!")
	} else {
		return nil, fmt.Errorf("peer address is required for transaction generation")
	}

	return &FakeTransactionGenerator{
		mongoClient:      client,
		blockchainClient: wallet.DefaultBlockchainClient,
		ctx:              ctx,
		peerAddr:         peerAddr,
	}, nil
}

// generateRandomAmount creates a random amount between 1 and 10000
func (ftg *FakeTransactionGenerator) generateRandomAmount() uint64 {
	max := big.NewInt(10000)
	min := big.NewInt(1)

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 100 // fallback amount
	}

	return n.Uint64() + min.Uint64()
}

// generateRandomNonce creates a random nonce
func (ftg *FakeTransactionGenerator) generateRandomNonce() uint64 {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return uint64(time.Now().UnixNano())
	}
	return n.Uint64()
}

// generateRandomHex creates a random hex string of specified length
func (ftg *FakeTransactionGenerator) generateRandomHex(length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// createFakeTransaction generates a single fake transaction
func (ftg *FakeTransactionGenerator) createFakeTransaction(fromShivam bool) *chain.Transaction {
	var from, to string

	if fromShivam {
		from = SHIVAM_ADDRESS
		to = SHIVAM2_ADDRESS
	} else {
		from = SHIVAM2_ADDRESS
		to = SHIVAM_ADDRESS
	}

	// Random transaction type
	txType := TX_TYPES[time.Now().UnixNano()%int64(len(TX_TYPES))]

	// Random token symbol
	tokenSymbol := TOKEN_SYMBOLS[time.Now().UnixNano()%int64(len(TOKEN_SYMBOLS))]

	// Create transaction
	tx := &chain.Transaction{
		Type:      txType,
		From:      from,
		To:        to,
		Amount:    ftg.generateRandomAmount(),
		TokenID:   tokenSymbol,
		Timestamp: time.Now().Unix(),
		Nonce:     ftg.generateRandomNonce(),
		Fee:       uint64(10 + (time.Now().UnixNano() % 90)), // Random fee 10-99
		GasLimit:  21000,
		GasPrice:  20,
		PublicKey: []byte(ftg.generateRandomHex(66)), // Mock public key
	}

	// Generate transaction ID
	tx.ID = tx.CalculateHash()

	// Generate mock signature
	tx.Signature = []byte(ftg.generateRandomHex(128))

	return tx
}

// createTransactionRecord creates a database record for the transaction
func (ftg *FakeTransactionGenerator) createTransactionRecord(tx *chain.Transaction, userID string) *wallet.TransactionRecord {
	return &wallet.TransactionRecord{
		UserID:      userID,
		TxHash:      tx.ID,
		Type:        TX_TYPE_NAMES[tx.Type],
		From:        tx.From,
		To:          tx.To,
		Amount:      tx.Amount,
		TokenSymbol: tx.TokenID,
		Status:      "completed", // Mock as completed
		Timestamp:   time.Now(),
		BlockHeight: uint64(1000 + (time.Now().UnixNano() % 5000)), // Mock block height
	}
}

// saveTransactionToDatabase saves the transaction record to MongoDB
func (ftg *FakeTransactionGenerator) saveTransactionToDatabase(txRecord *wallet.TransactionRecord) error {
	_, err := wallet.TransactionCollection.InsertOne(ftg.ctx, txRecord)
	if err != nil {
		return fmt.Errorf("failed to save transaction to database: %v", err)
	}
	return nil
}

// generateTransaction creates and submits a single fake transaction to the blockchain network
func (ftg *FakeTransactionGenerator) generateTransaction(stats *TransactionStats) error {
	// Alternate between shivam -> shivam2 and shivam2 -> shivam
	fromShivam := stats.TotalGenerated%2 == 0

	// Create fake transaction
	tx := ftg.createFakeTransaction(fromShivam)

	// Submit transaction to blockchain network
	fmt.Printf("📡 Submitting transaction to blockchain network...\n")
	var err error

	// Generate mock private key for transaction signing (in real scenario, this would be the actual private key)
	mockPrivateKey := make([]byte, 32)
	rand.Read(mockPrivateKey)

	// Submit transaction based on type
	switch tx.Type {
	case chain.TokenTransfer, chain.RegularTransfer:
		err = ftg.blockchainClient.TransferTokens(tx.From, tx.To, tx.TokenID, tx.Amount, mockPrivateKey)
	case chain.StakeDeposit:
		err = ftg.blockchainClient.StakeTokens(tx.From, tx.TokenID, tx.Amount, mockPrivateKey)
	default:
		err = fmt.Errorf("unsupported transaction type: %d", tx.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to submit transaction to blockchain: %v", err)
	}

	// Create transaction record for local database tracking
	mockUserID := "fake_user_" + fmt.Sprintf("%d", time.Now().UnixNano()%1000)
	txRecord := ftg.createTransactionRecord(tx, mockUserID)

	// Save to local database for tracking
	if err := ftg.saveTransactionToDatabase(txRecord); err != nil {
		fmt.Printf("⚠️ Warning: Failed to save transaction record to database: %v\n", err)
		// Don't return error as the transaction was successfully submitted to blockchain
	}

	// Update statistics
	stats.TotalGenerated++
	stats.ByType[TX_TYPE_NAMES[tx.Type]]++
	stats.ByToken[tx.TokenID]++

	// Log transaction details
	direction := "shivam → shivam2"
	if !fromShivam {
		direction = "shivam2 → shivam"
	}

	fmt.Printf("✅ Transaction Submitted #%d\n", stats.TotalGenerated)
	fmt.Printf("   🔄 Direction: %s\n", direction)
	fmt.Printf("   💰 Amount: %d %s\n", tx.Amount, tx.TokenID)
	fmt.Printf("   📝 Type: %s\n", TX_TYPE_NAMES[tx.Type])
	fmt.Printf("   🆔 TX ID: %s\n", tx.ID[:16]+"...")
	fmt.Printf("   🌐 Network: Submitted to blockchain\n")
	fmt.Printf("   ⏰ Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Println()

	return nil
}

// printStatistics displays current generation statistics
func (ftg *FakeTransactionGenerator) printStatistics(stats *TransactionStats) {
	elapsed := time.Since(stats.StartTime)
	rate := float64(stats.TotalGenerated) / elapsed.Seconds()

	fmt.Println("📊 === TRANSACTION GENERATION STATISTICS ===")
	fmt.Printf("⏱️  Runtime: %v\n", elapsed.Round(time.Second))
	fmt.Printf("📈 Total Generated: %d transactions\n", stats.TotalGenerated)
	fmt.Printf("🚀 Generation Rate: %.2f tx/sec\n", rate)
	fmt.Println()

	fmt.Println("📋 By Transaction Type:")
	for txType, count := range stats.ByType {
		fmt.Printf("   %s: %d\n", txType, count)
	}
	fmt.Println()

	fmt.Println("🪙 By Token Symbol:")
	for token, count := range stats.ByToken {
		fmt.Printf("   %s: %d\n", token, count)
	}
	fmt.Println("=" + string(make([]byte, 45)) + "=")
	fmt.Println()
}

// RunWithRate starts the fake transaction generation process with custom rate
func (ftg *FakeTransactionGenerator) RunWithRate(ctx context.Context, rate float64) {
	fmt.Println("🚀 Starting Fake Transaction Generator")
	fmt.Printf("📍 Shivam Wallet: %s\n", SHIVAM_ADDRESS)
	fmt.Printf("📍 Shivam2 Wallet: %s\n", SHIVAM2_ADDRESS)
	fmt.Printf("🌐 Connected to: %s\n", ftg.peerAddr)
	fmt.Printf("🎯 Target rate: %.1f transactions per second\n", rate)
	fmt.Println()

	// Initialize statistics
	stats := &TransactionStats{
		TotalGenerated: 0,
		ByType:         make(map[string]int),
		ByToken:        make(map[string]int),
		StartTime:      time.Now(),
	}

	// Calculate interval from rate
	interval := time.Duration(float64(time.Second) / rate)
	fmt.Printf("📊 Generation interval: %v\n", interval)
	fmt.Println()

	// Create ticker for transaction generation
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Create ticker for statistics display (every 10 seconds)
	statsTicker := time.NewTicker(10 * time.Second)
	defer statsTicker.Stop()

	fmt.Println("🎬 Generation started! Press Ctrl+C to stop...")
	fmt.Println()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("🛑 Context cancelled, stopping generation...")
			ftg.printFinalStatistics(stats)
			return

		case <-ticker.C:
			if err := ftg.generateTransaction(stats); err != nil {
				log.Printf("❌ Error generating transaction: %v", err)
			}

		case <-statsTicker.C:
			ftg.printStatistics(stats)
		}
	}
}

// printFinalStatistics displays final generation statistics
func (ftg *FakeTransactionGenerator) printFinalStatistics(stats *TransactionStats) {
	elapsed := time.Since(stats.StartTime)
	rate := float64(stats.TotalGenerated) / elapsed.Seconds()

	fmt.Println()
	fmt.Println("🏁 === FINAL TRANSACTION GENERATION STATISTICS ===")
	fmt.Printf("⏱️  Total Runtime: %v\n", elapsed.Round(time.Second))
	fmt.Printf("📈 Total Generated: %d transactions\n", stats.TotalGenerated)
	fmt.Printf("🚀 Average Rate: %.2f tx/sec\n", rate)
	fmt.Println()

	fmt.Println("📋 By Transaction Type:")
	for txType, count := range stats.ByType {
		fmt.Printf("   %s: %d\n", txType, count)
	}
	fmt.Println()

	fmt.Println("🪙 By Token Symbol:")
	for token, count := range stats.ByToken {
		fmt.Printf("   %s: %d\n", token, count)
	}
	fmt.Println("=" + string(make([]byte, 53)) + "=")
	fmt.Println("✅ Generator shutdown complete")
}

func main() {
	// Parse command-line flags
	var peerAddr = flag.String("peerAddr", "", "Blockchain node peer address (e.g., /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R)")
	var rate = flag.Float64("rate", 4.0, "Transaction generation rate per second (default: 4.0)")
	flag.Parse()

	fmt.Println("🌌 Blackhole Blockchain - Fake Transaction Generator")
	fmt.Println("=" + string(make([]byte, 58)) + "=")
	fmt.Println()

	// Validate peer address
	if *peerAddr == "" {
		fmt.Println("❌ Error: Peer address is required!")
		fmt.Println("📝 Usage: go run fake_transaction_generator.go -peerAddr <peer_address>")
		fmt.Println("📝 Example: go run fake_transaction_generator.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R")
		fmt.Println()
		fmt.Println("🔧 To get the peer address:")
		fmt.Println("   1. Start a blockchain node: go run blackhole-blockchain/core/relay-chain/cmd/relay/main.go")
		fmt.Println("   2. Copy the peer multiaddr from the output")
		fmt.Println("   3. Use that address with this generator")
		os.Exit(1)
	}

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\n🛑 Shutdown signal received, stopping generator...")
		cancel()
	}()

	// Create generator
	fmt.Printf("🔧 Initializing generator with peer: %s\n", *peerAddr)
	fmt.Printf("🎯 Target rate: %.1f transactions per second\n", *rate)
	fmt.Println()

	generator, err := NewFakeTransactionGenerator(*peerAddr)
	if err != nil {
		log.Fatalf("❌ Failed to initialize generator: %v", err)
	}
	defer generator.mongoClient.Disconnect(generator.ctx)

	// Start generation with custom rate
	generator.RunWithRate(ctx, *rate)
}
