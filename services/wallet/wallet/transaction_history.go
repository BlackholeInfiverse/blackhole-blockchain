package wallet

import (
	"context"
	"fmt"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TransactionRecord represents a transaction record for wallet history
type TransactionRecord struct {
	ID          string    `bson:"_id,omitempty" json:"id"`
	UserID      string    `bson:"user_id" json:"user_id"`
	WalletAddr  string    `bson:"wallet_addr" json:"wallet_addr"`
	TxHash      string    `bson:"tx_hash" json:"tx_hash"`
	Type        string    `bson:"type" json:"type"` // "send", "receive", "stake", "unstake"
	From        string    `bson:"from" json:"from"`
	To          string    `bson:"to" json:"to"`
	Amount      uint64    `bson:"amount" json:"amount"`
	TokenSymbol string    `bson:"token_symbol" json:"token_symbol"`
	Status      string    `bson:"status" json:"status"` // "pending", "confirmed", "failed"
	Timestamp   time.Time `bson:"timestamp" json:"timestamp"`
	BlockHeight uint64    `bson:"block_height,omitempty" json:"block_height,omitempty"`
}

var TransactionCollection *mongo.Collection

// RecordTransaction records a transaction in the wallet history
func RecordTransaction(ctx context.Context, userID, walletAddr, txHash, txType, from, to string, amount uint64, tokenSymbol string) error {
	record := &TransactionRecord{
		UserID:      userID,
		WalletAddr:  walletAddr,
		TxHash:      txHash,
		Type:        txType,
		From:        from,
		To:          to,
		Amount:      amount,
		TokenSymbol: tokenSymbol,
		Status:      "pending",
		Timestamp:   time.Now(),
	}

	_, err := TransactionCollection.InsertOne(ctx, record)
	if err != nil {
		return fmt.Errorf("failed to record transaction: %v", err)
	}

	return nil
}

// UpdateTransactionStatus updates the status of a transaction
func UpdateTransactionStatus(ctx context.Context, txHash, status string, blockHeight uint64) error {
	update := bson.M{
		"$set": bson.M{
			"status":       status,
			"block_height": blockHeight,
		},
	}

	_, err := TransactionCollection.UpdateOne(ctx, bson.M{"tx_hash": txHash}, update)
	if err != nil {
		return fmt.Errorf("failed to update transaction status: %v", err)
	}

	return nil
}

// GetWalletTransactionHistory returns transaction history for a wallet
func GetWalletTransactionHistory(ctx context.Context, userID, walletAddr string, limit int) ([]*TransactionRecord, error) {
	filter := bson.M{
		"user_id":     userID,
		"wallet_addr": walletAddr,
	}

	opts := options.Find().SetSort(bson.D{{"timestamp", -1}}).SetLimit(int64(limit))
	cursor, err := TransactionCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query transaction history: %v", err)
	}
	defer cursor.Close(ctx)

	var transactions []*TransactionRecord
	if err := cursor.All(ctx, &transactions); err != nil {
		return nil, fmt.Errorf("failed to decode transactions: %v", err)
	}

	return transactions, nil
}

// GetAllUserTransactions returns all transactions for a user across all wallets
func GetAllUserTransactions(ctx context.Context, userID string, limit int) ([]*TransactionRecord, error) {
	filter := bson.M{"user_id": userID}

	opts := options.Find().SetSort(bson.D{{"timestamp", -1}}).SetLimit(int64(limit))
	cursor, err := TransactionCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to query user transactions: %v", err)
	}
	defer cursor.Close(ctx)

	var transactions []*TransactionRecord
	if err := cursor.All(ctx, &transactions); err != nil {
		return nil, fmt.Errorf("failed to decode transactions: %v", err)
	}

	return transactions, nil
}

// Enhanced transfer function with transaction recording
func TransferTokensWithHistory(ctx context.Context, user *User, walletName, password, toAddress, tokenSymbol string, amount uint64) error {
	// Get wallet details
	wallet, privKey, _, err := GetWalletDetails(ctx, user, walletName, password)
	if err != nil {
		return fmt.Errorf("failed to get wallet: %v", err)
	}

	// Create transaction
	tx := &chain.Transaction{
		Type:      chain.TokenTransfer,
		From:      wallet.Address,
		To:        toAddress,
		Amount:    amount,
		TokenID:   tokenSymbol,
		Fee:       0,
		Nonce:     uint64(time.Now().UnixNano()),
		Timestamp: time.Now().Unix(),
	}
	tx.ID = tx.CalculateHash()

	// Record transaction in history (pending)
	err = RecordTransaction(ctx, user.ID.Hex(), wallet.Address, tx.ID, "send", wallet.Address, toAddress, amount, tokenSymbol)
	if err != nil {
		fmt.Printf("⚠️ Failed to record transaction history: %v\n", err)
		// Continue with transfer even if history recording fails
	}

	// Also record for receiver if they have a wallet in our system
	err = RecordTransaction(ctx, "", toAddress, tx.ID, "receive", wallet.Address, toAddress, amount, tokenSymbol)
	if err != nil {
		// This is expected to fail if receiver is not in our system
		fmt.Printf("📝 Receiver not in our system, skipping history record\n")
	}

	// Transfer tokens via blockchain
	err = DefaultBlockchainClient.TransferTokens(wallet.Address, toAddress, tokenSymbol, amount, privKey)
	if err != nil {
		// Update transaction status to failed
		UpdateTransactionStatus(ctx, tx.ID, "failed", 0)
		return fmt.Errorf("failed to transfer tokens: %v", err)
	}

	fmt.Printf("✅ Transaction recorded with ID: %s\n", tx.ID)
	return nil
}

// Enhanced staking function with transaction recording
func StakeTokensWithHistory(ctx context.Context, user *User, walletName, password, tokenSymbol string, amount uint64) error {
	// Get wallet details
	wallet, privKey, _, err := GetWalletDetails(ctx, user, walletName, password)
	if err != nil {
		return fmt.Errorf("failed to get wallet: %v", err)
	}

	// Create transaction
	tx := &chain.Transaction{
		Type:      chain.StakeDeposit,
		From:      wallet.Address,
		To:        "staking_contract",
		Amount:    amount,
		TokenID:   tokenSymbol,
		Fee:       0,
		Nonce:     uint64(time.Now().UnixNano()),
		Timestamp: time.Now().Unix(),
	}
	tx.ID = tx.CalculateHash()

	// Record transaction in history (pending)
	err = RecordTransaction(ctx, user.ID.Hex(), wallet.Address, tx.ID, "stake", wallet.Address, "staking_contract", amount, tokenSymbol)
	if err != nil {
		fmt.Printf("⚠️ Failed to record transaction history: %v\n", err)
	}

	// Stake tokens via blockchain
	err = DefaultBlockchainClient.StakeTokens(wallet.Address, tokenSymbol, amount, privKey)
	if err != nil {
		// Update transaction status to failed
		UpdateTransactionStatus(ctx, tx.ID, "failed", 0)
		return fmt.Errorf("failed to stake tokens: %v", err)
	}

	fmt.Printf("✅ Staking transaction recorded with ID: %s\n", tx.ID)
	return nil
}
