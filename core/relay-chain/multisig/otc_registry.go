package multisig

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

// OTCApproval represents an OTC trade approval stored in the registry
type OTCApproval struct {
	ID              string            `json:"id"`
	WalletID        string            `json:"wallet_id"`
	TradeID         string            `json:"trade_id"`
	Approver        string            `json:"approver"`
	Approved        bool              `json:"approved"`
	ApprovalData    map[string]interface{} `json:"approval_data,omitempty"`
	Timestamp       int64             `json:"timestamp"`
	ExpiresAt       int64             `json:"expires_at"`
	mu              sync.RWMutex
}

// OTCRegistry manages OTC multisig approvals using LevelDB
type OTCRegistry struct {
	db     *leveldb.DB
	dbPath string
	mu     sync.RWMutex
}

// NewOTCRegistry creates a new OTC registry with LevelDB backend
func NewOTCRegistry(dbPath string) (*OTCRegistry, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open OTC registry database: %v", err)
	}

	registry := &OTCRegistry{
		db:     db,
		dbPath: dbPath,
	}

	fmt.Printf("✅ OTC Registry initialized with LevelDB at %s\n", dbPath)
	return registry, nil
}

// StoreApproval stores an OTC approval in the registry
func (or *OTCRegistry) StoreApproval(approval *OTCApproval) error {
	or.mu.Lock()
	defer or.mu.Unlock()

	approval.Timestamp = time.Now().Unix()
	key := fmt.Sprintf("otc_approval:%s:%s:%s", approval.WalletID, approval.TradeID, approval.Approver)

	data, err := json.Marshal(approval)
	if err != nil {
		return fmt.Errorf("failed to marshal approval: %v", err)
	}

	if err := or.db.Put([]byte(key), data, nil); err != nil {
		return fmt.Errorf("failed to store approval in database: %v", err)
	}

	fmt.Printf("✅ OTC approval stored: wallet=%s, trade=%s, approver=%s\n",
		approval.WalletID, approval.TradeID, approval.Approver)
	return nil
}

// GetApproval retrieves an OTC approval from the registry
func (or *OTCRegistry) GetApproval(walletID, tradeID, approver string) (*OTCApproval, error) {
	or.mu.RLock()
	defer or.mu.RUnlock()

	key := fmt.Sprintf("otc_approval:%s:%s:%s", walletID, tradeID, approver)
	data, err := or.db.Get([]byte(key), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return nil, fmt.Errorf("approval not found")
		}
		return nil, fmt.Errorf("failed to retrieve approval: %v", err)
	}

	var approval OTCApproval
	if err := json.Unmarshal(data, &approval); err != nil {
		return nil, fmt.Errorf("failed to unmarshal approval: %v", err)
	}

	return &approval, nil
}

// GetTradeApprovals retrieves all approvals for a specific trade
func (or *OTCRegistry) GetTradeApprovals(walletID, tradeID string) ([]*OTCApproval, error) {
	or.mu.RLock()
	defer or.mu.RUnlock()

	var approvals []*OTCApproval
	prefix := fmt.Sprintf("otc_approval:%s:%s:", walletID, tradeID)

	iter := or.db.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			var approval OTCApproval
			if err := json.Unmarshal(iter.Value(), &approval); err != nil {
				continue // Skip corrupted entries
			}
			approvals = append(approvals, &approval)
		}
	}

	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterator error: %v", err)
	}

	return approvals, nil
}

// GetWalletApprovals retrieves all approvals for a wallet
func (or *OTCRegistry) GetWalletApprovals(walletID string) ([]*OTCApproval, error) {
	or.mu.RLock()
	defer or.mu.RUnlock()

	var approvals []*OTCApproval
	prefix := fmt.Sprintf("otc_approval:%s:", walletID)

	iter := or.db.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			var approval OTCApproval
			if err := json.Unmarshal(iter.Value(), &approval); err != nil {
				continue // Skip corrupted entries
			}
			approvals = append(approvals, &approval)
		}
	}

	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterator error: %v", err)
	}

	return approvals, nil
}

// UpdateApproval updates an existing approval
func (or *OTCRegistry) UpdateApproval(walletID, tradeID, approver string, approved bool, approvalData map[string]interface{}) error {
	approval, err := or.GetApproval(walletID, tradeID, approver)
	if err != nil {
		return err
	}

	approval.mu.Lock()
	approval.Approved = approved
	approval.ApprovalData = approvalData
	approval.Timestamp = time.Now().Unix()
	approval.mu.Unlock()

	return or.StoreApproval(approval)
}

// DeleteApproval removes an approval from the registry
func (or *OTCRegistry) DeleteApproval(walletID, tradeID, approver string) error {
	or.mu.Lock()
	defer or.mu.Unlock()

	key := fmt.Sprintf("otc_approval:%s:%s:%s", walletID, tradeID, approver)
	if err := or.db.Delete([]byte(key), nil); err != nil {
		return fmt.Errorf("failed to delete approval: %v", err)
	}

	fmt.Printf("🗑️ OTC approval deleted: wallet=%s, trade=%s, approver=%s\n",
		walletID, tradeID, approver)
	return nil
}

// CleanupExpiredApprovals removes expired approvals
func (or *OTCRegistry) CleanupExpiredApprovals() error {
	or.mu.Lock()
	defer or.mu.Unlock()

	currentTime := time.Now().Unix()
	deletedCount := 0

	iter := or.db.NewIterator(nil, nil)
	defer iter.Release()

	batch := new(leveldb.Batch)

	for iter.Next() {
		key := string(iter.Key())
		if len(key) > 12 && key[:12] == "otc_approval:" {
			var approval OTCApproval
			if err := json.Unmarshal(iter.Value(), &approval); err != nil {
				continue
			}

			if approval.ExpiresAt > 0 && currentTime > approval.ExpiresAt {
				batch.Delete(iter.Key())
				deletedCount++
			}
		}
	}

	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterator error: %v", err)
	}

	if deletedCount > 0 {
		if err := or.db.Write(batch, nil); err != nil {
			return fmt.Errorf("failed to write batch deletions: %v", err)
		}
		fmt.Printf("🗑️ Cleaned up %d expired OTC approvals\n", deletedCount)
	}

	return nil
}

// Close closes the registry database
func (or *OTCRegistry) Close() error {
	if or.db != nil {
		if err := or.db.Close(); err != nil {
			return fmt.Errorf("failed to close OTC registry database: %v", err)
		}
		fmt.Printf("✅ OTC Registry database closed\n")
	}
	return nil
}