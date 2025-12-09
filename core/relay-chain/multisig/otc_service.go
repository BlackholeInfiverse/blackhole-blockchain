package multisig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/dex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// OTCTrade represents a pending OTC trade
type OTCTrade struct {
	ID           string                 `json:"id"`
	WalletID     string                 `json:"wallet_id"`
	TradePayload map[string]interface{} `json:"trade_payload"`
	RequiredSigs int                    `json:"required_sigs"`
	Executed     bool                   `json:"executed"`
	CreatedAt    int64                  `json:"created_at"`
	ExpiresAt    int64                  `json:"expires_at"`
	mu           sync.RWMutex
}

// OTCService provides OTC multisig trading functionality
type OTCService struct {
	registry *OTCRegistry
	hooks    *OTCHooks
	dex      *dex.DEX
	trades   map[string]*OTCTrade
	mu       sync.RWMutex
}

// NewOTCService creates a new OTC service
func NewOTCService(registry *OTCRegistry, hooks *OTCHooks, dex *dex.DEX) *OTCService {
	return &OTCService{
		registry: registry,
		hooks:    hooks,
		dex:      dex,
		trades:   make(map[string]*OTCTrade),
	}
}

// RequestOTC creates a new OTC trade request
func (os *OTCService) RequestOTC(walletID string, tradePayload map[string]interface{}) (string, error) {
	os.mu.Lock()
	defer os.mu.Unlock()

	// Validate wallet exists and get required sigs
	wallet, err := os.hooks.MultiSigMgr.GetWallet(walletID)
	if err != nil {
		return "", fmt.Errorf("wallet not found: %v", err)
	}

	// For 3-of-5 multisig
	if len(wallet.Owners) != 5 || wallet.RequiredSigs != 3 {
		return "", fmt.Errorf("OTC requires 3-of-5 multisig wallet, got %d-of-%d", wallet.RequiredSigs, len(wallet.Owners))
	}

	// Generate trade ID
	tradeID := fmt.Sprintf("otc_trade_%d", time.Now().UnixNano())

	// Create OTC trade
	trade := &OTCTrade{
		ID:           tradeID,
		WalletID:     walletID,
		TradePayload: tradePayload,
		RequiredSigs: wallet.RequiredSigs,
		Executed:     false,
		CreatedAt:    time.Now().Unix(),
		ExpiresAt:    time.Now().Add(24 * time.Hour).Unix(), // 24 hour expiry
	}

	os.trades[tradeID] = trade

	fmt.Printf("✅ OTC trade requested: %s for wallet %s\n", tradeID, walletID)
	return tradeID, nil
}

// ApproveOTC approves an OTC trade with a signature
func (os *OTCService) ApproveOTC(tradeId, signatureHex string) error {
	os.mu.Lock()
	defer os.mu.Unlock()

	trade, exists := os.trades[tradeId]
	if !exists {
		return fmt.Errorf("OTC trade %s not found", tradeId)
	}

	trade.mu.Lock()
	defer trade.mu.Unlock()

	if trade.Executed {
		return fmt.Errorf("OTC trade already executed")
	}

	if time.Now().Unix() > trade.ExpiresAt {
		return fmt.Errorf("OTC trade has expired")
	}

	// Verify signature and extract approver
	approver, err := os.verifySignature(trade.WalletID, tradeId, signatureHex)
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	// Check if approver is an owner of the wallet
	wallet, err := os.hooks.MultiSigMgr.GetWallet(trade.WalletID)
	if err != nil {
		return fmt.Errorf("wallet not found: %v", err)
	}

	isOwner := false
	for _, owner := range wallet.Owners {
		if owner == approver {
			isOwner = true
			break
		}
	}
	if !isOwner {
		return fmt.Errorf("approver %s is not an owner of wallet %s", approver, trade.WalletID)
	}

	// Record the approval
	err = os.hooks.RecordOTCApproval(trade.WalletID, tradeId, approver, map[string]interface{}{
		"signature": signatureHex,
		"timestamp": time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("failed to record approval: %v", err)
	}

	// Check if we have enough approvals to execute
	approved, _, current, err := os.hooks.CheckOTCApprovalStatus(trade.WalletID, tradeId)
	if err != nil {
		return fmt.Errorf("failed to check approval status: %v", err)
	}

	fmt.Printf("✅ OTC trade %s approved by %s - %d/%d signatures\n", tradeId, approver, current, trade.RequiredSigs)

	// If approved, execute the trade
	if approved {
		return os.executeOTCTrade(trade)
	}

	return nil
}

// verifySignature verifies the signature and returns the approver address
func (os *OTCService) verifySignature(walletID, tradeId, signatureHex string) (string, error) {
	// Get wallet to check owners
	wallet, err := os.hooks.MultiSigMgr.GetWallet(walletID)
	if err != nil {
		return "", fmt.Errorf("wallet not found: %v", err)
	}

	// Decode signature
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return "", fmt.Errorf("invalid signature hex: %v", err)
	}

	// Assume compact signature format (64 bytes: r + s)
	if len(sigBytes) != 64 {
		return "", fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(sigBytes))
	}

	// Hash the trade ID
	hash := sha256.Sum256([]byte(tradeId))
	messageHash := hash[:]

	// Try to verify against each owner's public key
	// Assume owner addresses are hex-encoded public keys
	for _, owner := range wallet.Owners {
		pubKeyBytes, err := hex.DecodeString(owner)
		if err != nil {
			continue // Skip invalid addresses
		}

		pubKey, err := btcec.ParsePubKey(pubKeyBytes)
		if err != nil {
			continue
		}

		// Parse signature
		r := sigBytes[:32]
		s := sigBytes[32:]
		sig := ecdsa.NewSignature(new(big.Int).SetBytes(r), new(big.Int).SetBytes(s))

		// Verify signature
		if sig.Verify(messageHash, pubKey) {
			return owner, nil
		}
	}

	return "", fmt.Errorf("signature verification failed: no matching owner")
}

// executeOTCTrade executes the OTC trade via the DEX
func (os *OTCService) executeOTCTrade(trade *OTCTrade) error {
	// Extract trade parameters from payload
	tokenIn, ok := trade.TradePayload["token_in"].(string)
	if !ok {
		return fmt.Errorf("invalid token_in in trade payload")
	}

	tokenOut, ok := trade.TradePayload["token_out"].(string)
	if !ok {
		return fmt.Errorf("invalid token_out in trade payload")
	}

	amountIn, ok := trade.TradePayload["amount_in"].(uint64)
	if !ok {
		return fmt.Errorf("invalid amount_in in trade payload")
	}

	minAmountOut, ok := trade.TradePayload["min_amount_out"].(uint64)
	if !ok {
		return fmt.Errorf("invalid min_amount_out in trade payload")
	}

	trader, ok := trade.TradePayload["trader"].(string)
	if !ok {
		return fmt.Errorf("invalid trader in trade payload")
	}

	// Execute the swap
	amountOut, err := os.dex.ExecuteSwap(tokenIn, tokenOut, amountIn, minAmountOut, trader)
	if err != nil {
		return fmt.Errorf("failed to execute OTC trade: %v", err)
	}

	// Mark as executed
	trade.Executed = true

	fmt.Printf("✅ OTC trade %s executed: %d %s → %d %s\n", trade.ID, amountIn, tokenIn, amountOut, tokenOut)
	return nil
}

// GetOTCTrade retrieves an OTC trade
func (os *OTCService) GetOTCTrade(tradeId string) (*OTCTrade, error) {
	os.mu.RLock()
	defer os.mu.RUnlock()

	trade, exists := os.trades[tradeId]
	if !exists {
		return nil, fmt.Errorf("OTC trade %s not found", tradeId)
	}

	// Return a copy
	tradeCopy := *trade
	return &tradeCopy, nil
}

// CleanupExpiredTrades removes expired OTC trades
func (os *OTCService) CleanupExpiredTrades() {
	os.mu.Lock()
	defer os.mu.Unlock()

	currentTime := time.Now().Unix()
	for tradeId, trade := range os.trades {
		if !trade.Executed && currentTime > trade.ExpiresAt {
			delete(os.trades, tradeId)
			fmt.Printf("🗑️ Expired OTC trade %s removed\n", tradeId)
		}
	}
}