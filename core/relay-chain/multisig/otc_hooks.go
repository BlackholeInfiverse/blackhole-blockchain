package multisig

import (
	"fmt"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// OTCHooks provides hooks for OTC multisig operations
type OTCHooks struct {
	Registry     *OTCRegistry
	MultiSigMgr  *MultiSigManager
}

// NewOTCHooks creates new OTC hooks
func NewOTCHooks(registry *OTCRegistry, multiSigMgr *MultiSigManager) *OTCHooks {
	return &OTCHooks{
		Registry:    registry,
		MultiSigMgr: multiSigMgr,
	}
}

// RecordOTCApproval records an OTC approval in the registry
// This hook is called when a multisig approval is made for OTC purposes
func (oh *OTCHooks) RecordOTCApproval(walletID, tradeID, approver string, approvalData map[string]interface{}) error {
	// Check if the approver is actually an owner of the wallet
	wallet, err := oh.MultiSigMgr.GetWallet(walletID)
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
		return fmt.Errorf("approver %s is not an owner of wallet %s", approver, walletID)
	}

	approval := &OTCApproval{
		ID:           fmt.Sprintf("otc_%s_%s_%s_%d", walletID, tradeID, approver, time.Now().Unix()),
		WalletID:     walletID,
		TradeID:      tradeID,
		Approver:     approver,
		Approved:     true,
		ApprovalData: approvalData,
		ExpiresAt:    time.Now().Add(24 * time.Hour).Unix(), // Default 24h expiry
	}

	return oh.Registry.StoreApproval(approval)
}

// CheckOTCApprovalStatus checks if an OTC trade has sufficient approvals
// This hook reads from the registry without modifying multisig state
func (oh *OTCHooks) CheckOTCApprovalStatus(walletID, tradeID string) (approved bool, required int, current int, err error) {
	wallet, err := oh.MultiSigMgr.GetWallet(walletID)
	if err != nil {
		return false, 0, 0, fmt.Errorf("wallet not found: %v", err)
	}

	approvals, err := oh.Registry.GetTradeApprovals(walletID, tradeID)
	if err != nil {
		return false, wallet.RequiredSigs, 0, err
	}

	// Count valid approvals (not expired)
	currentTime := time.Now().Unix()
	validApprovals := 0
	for _, approval := range approvals {
		if approval.Approved && (approval.ExpiresAt == 0 || currentTime <= approval.ExpiresAt) {
			validApprovals++
		}
	}

	approved = validApprovals >= wallet.RequiredSigs
	return approved, wallet.RequiredSigs, validApprovals, nil
}

// GetOTCTradeDetails retrieves detailed OTC trade approval information
// This hook provides read-only access to approval data
func (oh *OTCHooks) GetOTCTradeDetails(walletID, tradeID string) (*OTCTradeDetails, error) {
	wallet, err := oh.MultiSigMgr.GetWallet(walletID)
	if err != nil {
		return nil, fmt.Errorf("wallet not found: %v", err)
	}

	approvals, err := oh.Registry.GetTradeApprovals(walletID, tradeID)
	if err != nil {
		return nil, err
	}

	details := &OTCTradeDetails{
		WalletID:     walletID,
		TradeID:      tradeID,
		WalletOwners: wallet.Owners,
		RequiredSigs: wallet.RequiredSigs,
		Approvals:    approvals,
	}

	// Calculate approval status
	currentTime := time.Now().Unix()
	validApprovals := 0
	for _, approval := range approvals {
		if approval.Approved && (approval.ExpiresAt == 0 || currentTime <= approval.ExpiresAt) {
			validApprovals++
		}
	}

	details.Approved = validApprovals >= wallet.RequiredSigs
	details.CurrentApprovals = validApprovals

	return details, nil
}

// RevokeOTCApproval revokes a previously recorded OTC approval
// This hook allows revoking approvals without affecting core multisig
func (oh *OTCHooks) RevokeOTCApproval(walletID, tradeID, approver string) error {
	// Check if the approver is actually an owner
	wallet, err := oh.MultiSigMgr.GetWallet(walletID)
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
		return fmt.Errorf("approver %s is not an owner of wallet %s", approver, walletID)
	}

	return oh.Registry.DeleteApproval(walletID, tradeID, approver)
}

// GetWalletOTCActivity retrieves all OTC activity for a wallet
// This hook provides comprehensive read access to OTC data
func (oh *OTCHooks) GetWalletOTCActivity(walletID string) ([]*OTCTradeDetails, error) {
	wallet, err := oh.MultiSigMgr.GetWallet(walletID)
	if err != nil {
		return nil, fmt.Errorf("wallet not found: %v", err)
	}

	approvals, err := oh.Registry.GetWalletApprovals(walletID)
	if err != nil {
		return nil, err
	}

	// Group approvals by trade ID
	tradeMap := make(map[string][]*OTCApproval)
	for _, approval := range approvals {
		tradeMap[approval.TradeID] = append(tradeMap[approval.TradeID], approval)
	}

	var trades []*OTCTradeDetails
	for tradeID, tradeApprovals := range tradeMap {
		details := &OTCTradeDetails{
			WalletID:     walletID,
			TradeID:      tradeID,
			WalletOwners: wallet.Owners,
			RequiredSigs: wallet.RequiredSigs,
			Approvals:    tradeApprovals,
		}

		// Calculate approval status
		currentTime := time.Now().Unix()
		validApprovals := 0
		for _, approval := range tradeApprovals {
			if approval.Approved && (approval.ExpiresAt == 0 || currentTime <= approval.ExpiresAt) {
				validApprovals++
			}
		}

		details.Approved = validApprovals >= wallet.RequiredSigs
		details.CurrentApprovals = validApprovals

		trades = append(trades, details)
	}

	return trades, nil
}

// OTCTradeDetails represents detailed information about an OTC trade's approval status
type OTCTradeDetails struct {
	WalletID         string           `json:"wallet_id"`
	TradeID          string           `json:"trade_id"`
	WalletOwners     []string         `json:"wallet_owners"`
	RequiredSigs     int              `json:"required_sigs"`
	CurrentApprovals int              `json:"current_approvals"`
	Approved         bool             `json:"approved"`
	Approvals        []*OTCApproval   `json:"approvals"`
}

// CleanupExpiredOTCHooks performs cleanup of expired OTC approvals
// This hook should be called periodically to maintain registry health
func (oh *OTCHooks) CleanupExpiredOTCHooks() error {
	return oh.Registry.CleanupExpiredApprovals()
}

// ValidateOTCAccess validates if a user has access to OTC operations for a wallet
// This hook provides access control without modifying multisig logic
func (oh *OTCHooks) ValidateOTCAccess(walletID, userAddress string) error {
	wallet, err := oh.MultiSigMgr.GetWallet(walletID)
	if err != nil {
		return fmt.Errorf("wallet not found: %v", err)
	}

	for _, owner := range wallet.Owners {
		if owner == userAddress {
			return nil // User is an owner
		}
	}

	return fmt.Errorf("user %s is not authorized for OTC operations on wallet %s", userAddress, walletID)
}