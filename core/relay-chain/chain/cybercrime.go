package chain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AIFraudChecker handles integration with external AI fraud detection service
type AIFraudChecker struct {
	ServiceURL    string            `json:"service_url"`
	FlaggedCache  map[string]bool   `json:"flagged_cache"`
	CacheTimeout  time.Duration     `json:"cache_timeout"`
	LastCacheTime map[string]time.Time `json:"last_cache_time"`
	mu            sync.RWMutex
	Enabled       bool              `json:"enabled"`
}

// TransactionData represents transaction data sent to AI service
type TransactionData struct {
	FromAddress string  `json:"from_address"`
	ToAddress   string  `json:"to_address"`
	Amount      uint64  `json:"amount"`
	Token       string  `json:"token"`
	Timestamp   int64   `json:"timestamp"`
	TxHash      string  `json:"tx_hash"`
	TxType      int     `json:"tx_type"`
}

// WalletData represents the full data from Keval & Aryan's service
type WalletData struct {
	Wallet            string        `json:"wallet"`
	Reports           []FraudReport `json:"reports"`
	TotalReports      int           `json:"totalReports"`
	ApprovedReports   int           `json:"approvedReports"`
	PendingReports    int           `json:"pendingReports"`
	RejectedReports   int           `json:"rejectedReports"`
	EscalatedReports  int           `json:"escalatedReports"`
	HighestRiskScore  int           `json:"highestRiskScore"`  // 0-100 scale
	HighestSeverity   int           `json:"highestSeverity"`   // 1-5 scale
	CommonTags        []string      `json:"commonTags"`
	LastReportDate    string        `json:"lastReportDate"`
	HasHighRiskReports bool         `json:"hasHighRiskReports"`
	HasPhishingTags   bool          `json:"hasPhishingTags"`
	HasBotnetTags     bool          `json:"hasBotnetTags"`
}

// FraudReport represents individual report from their MongoDB
type FraudReport struct {
	Reason    string   `json:"reason"`
	Severity  int      `json:"severity"`  // 1-5
	Status    string   `json:"status"`    // pending, approved, rejected, escalated
	RiskLevel string   `json:"riskLevel"` // low, medium, high
	RiskScore int      `json:"riskScore"` // 0-100
	Tags      []string `json:"tags"`
	Source    string   `json:"source"`    // admin, contract
	CreatedAt string   `json:"createdAt"`
}

// NewAIFraudChecker creates a new AI fraud detection checker
func NewAIFraudChecker() *AIFraudChecker {
	return &AIFraudChecker{
		ServiceURL:    "http://localhost:9090", // Default - UPDATE with Keval & Aryan's ngrok URL
		FlaggedCache:  make(map[string]bool),
		LastCacheTime: make(map[string]time.Time),
		CacheTimeout:  5 * time.Minute, // Cache results for 5 minutes
		Enabled:       true,
	}
}

// SendTransactionData sends transaction data to AI service for analysis (async)
func (ai *AIFraudChecker) SendTransactionData(tx *Transaction) {
	if !ai.Enabled {
		return
	}

	txData := TransactionData{
		FromAddress: tx.From,
		ToAddress:   tx.To,
		Amount:      tx.Amount,
		Token:       tx.TokenID,
		Timestamp:   time.Now().Unix(),
		TxHash:      tx.ID,
		TxType:      int(tx.Type),
	}

	// Send to AI service (non-blocking)
	go ai.sendToAIService("/api/analyze", txData)
}

// IsWalletFlagged checks if a wallet is flagged by AI (with caching)
func (ai *AIFraudChecker) IsWalletFlagged(address string) bool {
	if !ai.Enabled {
		return false
	}

	ai.mu.RLock()
	// Check cache first
	if flagged, exists := ai.FlaggedCache[address]; exists {
		if lastCheck, timeExists := ai.LastCacheTime[address]; timeExists {
			if time.Since(lastCheck) < ai.CacheTimeout {
				ai.mu.RUnlock()
				return flagged
			}
		}
	}
	ai.mu.RUnlock()

	// Cache miss or expired - check AI service
	flagged := ai.checkAIService(address)

	// Update cache
	ai.mu.Lock()
	ai.FlaggedCache[address] = flagged
	ai.LastCacheTime[address] = time.Now()
	ai.mu.Unlock()

	return flagged
}

// checkAIService makes HTTP call to get full wallet data and decides if should block
func (ai *AIFraudChecker) checkAIService(address string) bool {
	url := fmt.Sprintf("%s/api/wallet-data/%s", ai.ServiceURL, address)

	resp, err := http.Get(url)
	if err != nil {
		// If AI service is down, log error but don't block transactions
		fmt.Printf("⚠️ AI fraud service unavailable: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var walletData WalletData
	if err := json.NewDecoder(resp.Body).Decode(&walletData); err != nil {
		fmt.Printf("⚠️ Failed to parse wallet data: %v\n", err)
		return false
	}

	// OUR DECISION LOGIC - using their rich data
	shouldBlock := ai.shouldBlockWallet(&walletData)

	if shouldBlock {
		fmt.Printf("🚨 BLOCKING wallet %s: %s\n", address, ai.getBlockReason(&walletData))
	}

	return shouldBlock
}

// shouldBlockWallet decides if wallet should be blocked based on their data
func (ai *AIFraudChecker) shouldBlockWallet(data *WalletData) bool {
	// Rule 1: Block if 2+ approved reports
	if data.ApprovedReports >= 2 {
		return true
	}

	// Rule 2: Block if highest risk score >= 90 (their 0-100 scale)
	if data.HighestRiskScore >= 90 {
		return true
	}

	// Rule 3: Block if severity 5 (max) and approved
	if data.HighestSeverity >= 5 && data.ApprovedReports > 0 {
		return true
	}

	// Rule 4: Block if has phishing or botnet tags
	if data.HasPhishingTags || data.HasBotnetTags {
		return true
	}

	// Rule 5: Block if high risk reports exist
	if data.HasHighRiskReports && data.ApprovedReports > 0 {
		return true
	}

	return false
}

// getBlockReason returns human-readable reason for blocking
func (ai *AIFraudChecker) getBlockReason(data *WalletData) string {
	reasons := []string{}

	if data.ApprovedReports >= 2 {
		reasons = append(reasons, fmt.Sprintf("%d approved reports", data.ApprovedReports))
	}

	if data.HighestRiskScore >= 90 {
		reasons = append(reasons, fmt.Sprintf("risk score %d/100", data.HighestRiskScore))
	}

	if data.HasPhishingTags {
		reasons = append(reasons, "phishing tags")
	}

	if data.HasBotnetTags {
		reasons = append(reasons, "botnet tags")
	}

	if len(reasons) == 0 {
		return "high risk profile"
	}

	return fmt.Sprintf("Blocked due to: %s", strings.Join(reasons, ", "))
}

// sendToAIService sends data to AI service (helper method)
func (ai *AIFraudChecker) sendToAIService(endpoint string, data interface{}) {
	url := ai.ServiceURL + endpoint

	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}

	// Send HTTP POST request (non-blocking)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		// Log error but don't block blockchain operation
		fmt.Printf("⚠️ Failed to send data to AI service: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Log successful data transmission
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("📊 Transaction data sent to AI fraud detection service\n")
	}
}

// SetServiceURL updates the AI service URL
func (ai *AIFraudChecker) SetServiceURL(url string) {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	ai.ServiceURL = url
}

// SetEnabled enables or disables AI fraud checking
func (ai *AIFraudChecker) SetEnabled(enabled bool) {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	ai.Enabled = enabled
}

// ClearCache clears the flagged wallet cache
func (ai *AIFraudChecker) ClearCache() {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	ai.FlaggedCache = make(map[string]bool)
	ai.LastCacheTime = make(map[string]time.Time)
}
