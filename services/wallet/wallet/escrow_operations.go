package wallet

import (
    "context"
    "fmt"

    "github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/escrow"
)

// CreateEscrowTransfer initiates an escrow transfer from the wallet
func CreateEscrowTransfer(ctx context.Context, user *User, walletName, password, receiverAddress, arbitratorAddress, tokenSymbol string, amount uint64, expirationHours int, description string) (*escrow.EscrowContract, error) {
    // Get wallet details
    wallet, privKey, _, err := GetWalletDetails(ctx, user, walletName, password)
    if err != nil {
        return nil, fmt.Errorf("failed to get wallet: %v", err)
    }

    // Validate receiver address
    if receiverAddress == "" {
        return nil, fmt.Errorf("receiver address cannot be empty")
    }

    // Check if user has sufficient balance
    balance, err := DefaultBlockchainClient.GetTokenBalance(wallet.Address, tokenSymbol)
    if err != nil {
        return nil, fmt.Errorf("failed to check balance: %v", err)
    }

    if balance < amount {
        return nil, fmt.Errorf("insufficient balance: has %d, needs %d", balance, amount)
    }

    // Create escrow contract
    escrowContract, err := DefaultBlockchainClient.CreateEscrow(
        wallet.Address,
        receiverAddress,
        arbitratorAddress,
        tokenSymbol,
        amount,
        expirationHours,
        description,
        privKey,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create escrow: %v", err)
    }

    return escrowContract, nil
}

// ConfirmEscrow confirms an escrow contract
func ConfirmEscrow(ctx context.Context, user *User, walletName, password, escrowID string) error {
    // Get wallet details
    wallet, privKey, _, err := GetWalletDetails(ctx, user, walletName, password)
    if err != nil {
        return fmt.Errorf("failed to get wallet: %v", err)
    }

    // Confirm escrow
    err = DefaultBlockchainClient.ConfirmEscrow(escrowID, wallet.Address, privKey)
    if err != nil {
        return fmt.Errorf("failed to confirm escrow: %v", err)
    }

    return nil
}

// ReleaseEscrow releases funds from an escrow to the receiver
func ReleaseEscrow(ctx context.Context, user *User, walletName, password, escrowID string) error {
    // Get wallet details
    wallet, privKey, _, err := GetWalletDetails(ctx, user, walletName, password)
    if err != nil {
        return fmt.Errorf("failed to get wallet: %v", err)
    }

    // Release escrow
    err = DefaultBlockchainClient.ReleaseEscrow(escrowID, wallet.Address, privKey)
    if err != nil {
        return fmt.Errorf("failed to release escrow: %v", err)
    }

    return nil
}

// CancelEscrow cancels an escrow and returns funds to the sender
func CancelEscrow(ctx context.Context, user *User, walletName, password, escrowID string) error {
    // Get wallet details
    wallet, privKey, _, err := GetWalletDetails(ctx, user, walletName, password)
    if err != nil {
        return fmt.Errorf("failed to get wallet: %v", err)
    }

    // Cancel escrow
    err = DefaultBlockchainClient.CancelEscrow(escrowID, wallet.Address, privKey)
    if err != nil {
        return fmt.Errorf("failed to cancel escrow: %v", err)
    }

    return nil
}

// GetEscrowDetails gets details of an escrow contract
func GetEscrowDetails(ctx context.Context, escrowID string) (*escrow.EscrowContract, error) {
    // Get escrow details
    contract, err := DefaultBlockchainClient.GetEscrowDetails(escrowID)
    if err != nil {
        return nil, fmt.Errorf("failed to get escrow details: %v", err)
    }

    return contract, nil
}

// ListUserEscrows lists all escrows where the user is involved
func ListUserEscrows(ctx context.Context, userAddress string) ([]*escrow.EscrowContract, error) {
    // Get all escrows for the user
    contracts, err := DefaultBlockchainClient.GetUserEscrows(userAddress)
    if err != nil {
        return nil, fmt.Errorf("failed to list user escrows: %v", err)
    }

    return contracts, nil
}