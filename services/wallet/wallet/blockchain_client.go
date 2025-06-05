package wallet

import (
    "fmt"
    "time"

    "github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// BlockchainClient handles communication with the blockchain
type BlockchainClient struct {
	Blockchain *chain.Blockchain
}

// NewBlockchainClient creates a new client to interact with the blockchain
func NewBlockchainClient(port int) (*BlockchainClient, error) {
    bc, err := chain.NewBlockchain(port)
    if err != nil {
        return nil, fmt.Errorf("failed to create blockchain: %v", err)
    }
    
    return &BlockchainClient{
        Blockchain: bc,
    }, nil
}

// GetTokenBalance returns the balance of a specific token for an address
func (client *BlockchainClient) GetTokenBalance(address, tokenSymbol string) (uint64, error) {
    token, exists := client.Blockchain.TokenRegistry[tokenSymbol]
    if !exists {
        return 0, fmt.Errorf("token %s not found", tokenSymbol)
    }
    
    return token.BalanceOf(address)
}

// TransferTokens transfers tokens from one address to another
func (client *BlockchainClient) TransferTokens(from, to, tokenSymbol string, amount uint64, privateKey []byte) error {
    _, exists := client.Blockchain.TokenRegistry[tokenSymbol]
    if !exists {
        return fmt.Errorf("token %s not found", tokenSymbol)
    }
    
    // Create and sign transaction
    tx := &chain.Transaction{
        Type:      chain.TokenTransfer,
        From:      from,
        To:        to,
        Amount:    amount,
        TokenID:   tokenSymbol,
        Fee:       0,
        Nonce:     client.Blockchain.GetNonce(from),
        Timestamp: time.Now().Unix(),
    }
    
    // Sign transaction (simplified - would need actual signing logic)
    // tx.Sign(privateKey)
    
    // Submit to transaction pool
    err := client.Blockchain.ProcessTransaction(tx)
    if err != nil {
        return fmt.Errorf("failed to process transaction: %v", err)
    }
    
    return nil
}

// StakeTokens stakes tokens for validation
func (client *BlockchainClient) StakeTokens(address, tokenSymbol string, amount uint64, privateKey []byte) error {
    _, exists := client.Blockchain.TokenRegistry[tokenSymbol]
    if !exists {
        return fmt.Errorf("token %s not found", tokenSymbol)
    }
    
    // Create staking transaction
    tx := &chain.Transaction{
        Type:      chain.StakeDeposit,
        From:      address,
        To:        "staking_contract",
        Amount:    amount,
        TokenID:   tokenSymbol,
        Fee:       0,
        Nonce:     client.Blockchain.GetNonce(address),
        Timestamp: time.Now().Unix(),
    }
    
    // Sign transaction (simplified - would need actual signing logic)
    // tx.Sign(privateKey)
    
    // Submit to transaction pool
    err := client.Blockchain.ProcessTransaction(tx)
    if err != nil {
        return fmt.Errorf("failed to process transaction: %v", err)
    }
    
    return nil
}


