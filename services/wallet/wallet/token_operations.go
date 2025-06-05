package wallet

import (
    "context"
    "fmt"
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
    // Get wallet
    wallet, _, _, err := GetWalletDetails(ctx, user, walletName, password)
    if err != nil {
        return 0, fmt.Errorf("failed to get wallet: %v", err)
    }
    
    // Get token balance
    balance, err := DefaultBlockchainClient.GetTokenBalance(wallet.Address, tokenSymbol)
    if err != nil {
        return 0, fmt.Errorf("failed to get token balance: %v", err)
    }
    
    return balance, nil
}

// TransferTokens transfers tokens from one wallet to another
func TransferTokens(ctx context.Context, user *User, walletName, password, toAddress, tokenSymbol string, amount uint64) error {
    // Get wallet
    wallet, privKey, _, err := GetWalletDetails(ctx, user, walletName, password)
    if err != nil {
        return fmt.Errorf("failed to get wallet: %v", err)
    }
    
    // Transfer tokens
    err = DefaultBlockchainClient.TransferTokens(wallet.Address, toAddress, tokenSymbol, amount, privKey)
    if err != nil {
        return fmt.Errorf("failed to transfer tokens: %v", err)
    }
    
    return nil
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





