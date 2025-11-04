package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	TX_TYPES      = []string{"Token Transfer", "Regular Transfer", "Stake Deposit"}
)

// SimpleTransaction represents a simplified transaction structure
type SimpleTransaction struct {
	ID          string    `bson:"_id,omitempty"`
	TxHash      string    `bson:"tx_hash"`
	Type        string    `bson:"type"`
	From        string    `bson:"from"`
	To          string    `bson:"to"`
	Amount      uint64    `bson:"amount"`
	TokenSymbol string    `bson:"token_symbol"`
	Fee         uint64    `bson:"fee"`
	Status      string    `bson:"status"`
	Timestamp   time.Time `bson:"timestamp"`
	BlockHeight uint64    `bson:"block_height"`
	Nonce       uint64    `bson:"nonce"`
	UserID      string    `bson:"user_id"`
}

// SimpleFakeGenerator handles the generation of fake transactions
type SimpleFakeGenerator struct {
	mongoClient *mongo.Client
	collection  *mongo.Collection
	ctx         context.Context
}

// TransactionStats tracks generated transaction statistics
type TransactionStats struct {
	TotalGenerated int
	ByType         map[string]int
	ByToken        map[string]int
	StartTime      time.Time
}

func NewSimpleFakeGenerator() (*SimpleFakeGenerator, error) {
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

	// Initialize collection
	db := client.Database("walletdb")
	collection := db.Collection("transactions")

	return &SimpleFakeGenerator{
		mongoClient: client,
		collection:  collection,
		ctx:         ctx,
	}, nil
}

// generateRandomAmount creates a random amount between 1 and 10000
func (sfg *SimpleFakeGenerator) generateRandomAmount() uint64 {
	max := big.NewInt(10000)
	min := big.NewInt(1)
	
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 100 // fallback amount
	}
	
	return n.Uint64() + min.Uint64()
}

// generateRandomNonce creates a random nonce
func (sfg *SimpleFakeGenerator) generateRandomNonce() uint64 {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return uint64(time.Now().UnixNano())
	}
	return n.Uint64()
}

// generateTxHash creates a transaction hash
func (sfg *SimpleFakeGenerator) generateTxHash(tx *SimpleTransaction) string {
	data := fmt.Sprintf("%s%s%d%s%d", tx.From, tx.To, tx.Amount, tx.TokenSymbol, tx.Timestamp.Unix())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// createFakeTransaction generates a single fake transaction
func (sfg *SimpleFakeGenerator) createFakeTransaction(fromShivam bool) *SimpleTransaction {
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
	tx := &SimpleTransaction{
		Type:        txType,
		From:        from,
		To:          to,
		Amount:      sfg.generateRandomAmount(),
		TokenSymbol: tokenSymbol,
		Timestamp:   time.Now(),
		Nonce:       sfg.generateRandomNonce(),
		Fee:         uint64(10 + (time.Now().UnixNano() % 90)), // Random fee 10-99
		Status:      "completed",
		BlockHeight: uint64(1000 + (time.Now().UnixNano() % 5000)), // Mock block height
		UserID:      fmt.Sprintf("fake_user_%d", time.Now().UnixNano()%1000),
	}

	// Generate transaction hash
	tx.TxHash = sfg.generateTxHash(tx)
	
	return tx
}

// saveTransactionToDatabase saves the transaction record to MongoDB
func (sfg *SimpleFakeGenerator) saveTransactionToDatabase(tx *SimpleTransaction) error {
	_, err := sfg.collection.InsertOne(sfg.ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to save transaction to database: %v", err)
	}
	return nil
}

// generateTransaction creates and saves a single fake transaction
func (sfg *SimpleFakeGenerator) generateTransaction(stats *TransactionStats) error {
	// Alternate between shivam -> shivam2 and shivam2 -> shivam
	fromShivam := stats.TotalGenerated%2 == 0
	
	// Create fake transaction
	tx := sfg.createFakeTransaction(fromShivam)
	
	// Save to database
	if err := sfg.saveTransactionToDatabase(tx); err != nil {
		return err
	}
	
	// Update statistics
	stats.TotalGenerated++
	stats.ByType[tx.Type]++
	stats.ByToken[tx.TokenSymbol]++
	
	// Log transaction details
	direction := "shivam → shivam2"
	if !fromShivam {
		direction = "shivam2 → shivam"
	}
	
	fmt.Printf("✅ Generated Transaction #%d\n", stats.TotalGenerated)
	fmt.Printf("   🔄 Direction: %s\n", direction)
	fmt.Printf("   💰 Amount: %d %s\n", tx.Amount, tx.TokenSymbol)
	fmt.Printf("   📝 Type: %s\n", tx.Type)
	fmt.Printf("   🆔 TX Hash: %s\n", tx.TxHash[:16]+"...")
	fmt.Printf("   ⏰ Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Println()
	
	return nil
}

// printStatistics displays current generation statistics
func (sfg *SimpleFakeGenerator) printStatistics(stats *TransactionStats) {
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

// Run starts the fake transaction generation process
func (sfg *SimpleFakeGenerator) Run() {
	fmt.Println("🚀 Starting Simple Fake Transaction Generator")
	fmt.Printf("📍 Shivam Wallet: %s\n", SHIVAM_ADDRESS)
	fmt.Printf("📍 Shivam2 Wallet: %s\n", SHIVAM2_ADDRESS)
	fmt.Println("🎯 Target: 3-5 transactions per second")
	fmt.Println()

	// Initialize statistics
	stats := &TransactionStats{
		TotalGenerated: 0,
		ByType:         make(map[string]int),
		ByToken:        make(map[string]int),
		StartTime:      time.Now(),
	}

	// Create ticker for transaction generation (200-333ms interval for 3-5 tx/sec)
	ticker := time.NewTicker(250 * time.Millisecond) // ~4 tx/sec
	defer ticker.Stop()

	// Create ticker for statistics display (every 10 seconds)
	statsTicker := time.NewTicker(10 * time.Second)
	defer statsTicker.Stop()

	fmt.Println("🎬 Generation started! Press Ctrl+C to stop...")
	fmt.Println()

	for {
		select {
		case <-ticker.C:
			if err := sfg.generateTransaction(stats); err != nil {
				log.Printf("❌ Error generating transaction: %v", err)
			}

		case <-statsTicker.C:
			sfg.printStatistics(stats)
		}
	}
}

func main() {
	fmt.Println("🌌 Blackhole Blockchain - Simple Fake Transaction Generator")
	fmt.Println("=" + string(make([]byte, 58)) + "=")
	fmt.Println()

	// Create generator
	generator, err := NewSimpleFakeGenerator()
	if err != nil {
		log.Fatalf("❌ Failed to initialize generator: %v", err)
	}
	defer generator.mongoClient.Disconnect(generator.ctx)

	// Start generation
	generator.Run()
}
