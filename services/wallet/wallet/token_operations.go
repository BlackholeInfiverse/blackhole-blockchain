package wallet

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

// Global blockchain client variable
var DefaultBlockchainClient *BlockchainClient

// InitBlockchainClient initializes the blockchain client
func InitBlockchainClient(port int) error {
	var err error
	DefaultBlockchainClient, err = NewBlockchainClient(port)
	return err
}

// CheckTokenBalance displays the token balance for a wallet
func CheckTokenBalance(ctx context.Context, user *User, walletName, password, tokenSymbol string) (uint64, error) {
	// Query the wallet directly from DB to get address without decrypting keys
	var wallet Wallet
	err := WalletCollection.FindOne(ctx, bson.M{
		"user_id":     user.ID,
		"wallet_name": walletName,
	}).Decode(&wallet)
	if err != nil {
		return 0, fmt.Errorf("failed to get wallet: %v", err)
	}

	// Update last accessed time
	now := time.Now()
	WalletCollection.UpdateOne(ctx, bson.M{
		"_id": wallet.ID,
	}, bson.M{
		"$set": bson.M{"last_accessed": now},
	})

	// Get token balance
	balance, err := DefaultBlockchainClient.GetTokenBalance(wallet.Address, tokenSymbol)
	if err != nil {
		return 0, fmt.Errorf("failed to get token balance: %v", err)
	}

	return balance, nil
}

// TransferTokens transfers tokens from one wallet to another with enhanced validation
func TransferTokens(ctx context.Context, user *User, walletName, password, toAddress, tokenSymbol string, amount uint64) error {
	// Get wallet
	wallet, privKey, _, err := GetWalletDetails(ctx, user, walletName, password)
	if err != nil {
		return fmt.Errorf("failed to get wallet: %v", err)
	}

	fmt.Printf("🚀 Initiating token transfer from wallet: %s\n", walletName)
	fmt.Printf("   📍 From: %s\n", wallet.Address)
	fmt.Printf("   📍 To: %s\n", toAddress)
	fmt.Printf("   💰 Amount: %d %s\n", amount, tokenSymbol)

	// Transfer tokens (now includes enhanced validation)
	err = DefaultBlockchainClient.TransferTokens(wallet.Address, toAddress, tokenSymbol, amount, privKey)
	if err != nil {
		return fmt.Errorf("failed to transfer tokens: %v", err)
	}

	fmt.Printf("✅ Token transfer completed successfully\n")
	return nil
}

// TransferTokensWithEscrow transfers tokens using escrow for added security
func TransferTokensWithEscrow(ctx context.Context, user *User, walletName, password, toAddress, arbitratorAddress, tokenSymbol string, amount uint64, expirationHours int, description string) (string, error) {
	// Get wallet
	wallet, privKey, _, err := GetWalletDetails(ctx, user, walletName, password)
	if err != nil {
		return "", fmt.Errorf("failed to get wallet: %v", err)
	}

	fmt.Printf("🔒 Initiating escrow transfer from wallet: %s\n", walletName)
	fmt.Printf("   📍 From: %s\n", wallet.Address)
	fmt.Printf("   📍 To: %s\n", toAddress)
	fmt.Printf("   👨‍⚖️ Arbitrator: %s\n", arbitratorAddress)
	fmt.Printf("   💰 Amount: %d %s\n", amount, tokenSymbol)
	fmt.Printf("   ⏰ Expires in: %d hours\n", expirationHours)

	// Create escrow transfer
	contract, err := DefaultBlockchainClient.TransferTokensWithEscrow(
		wallet.Address,
		toAddress,
		arbitratorAddress,
		tokenSymbol,
		amount,
		expirationHours,
		description,
		privKey,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create escrow transfer: %v", err)
	}

	fmt.Printf("✅ Escrow transfer created successfully: %s\n", contract.ID)
	return contract.ID, nil
}

// StakeTokens stakes tokens for validation
func StakeTokens(ctx context.Context, user *User, walletName, password, tokenSymbol string, amount uint64) error {
	// Get wallet
	wallet, privKey, _, err := GetWalletDetails(ctx, user, walletName, password)
	if err != nil {
		return fmt.Errorf("failed to get wallet: %v", err)
	}

	// Stake tokens
	err = DefaultBlockchainClient.StakeTokens(wallet.Address, tokenSymbol, amount, privKey)
	if err != nil {
		return fmt.Errorf("failed to stake tokens: %v", err)
	}

	return nil
}
