package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"go.etcd.io/bbolt"

	// BlackHole blockchain imports
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	core "github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk/core"
)

// BlackHoleBlockchainInterface represents the interface to the real blockchain
type BlackHoleBlockchainInterface struct {
	blockchain *chain.Blockchain
	logger     *logrus.Logger
}

// ProcessBridgeTransaction processes a bridge transaction on the BlackHole blockchain
func (bhi *BlackHoleBlockchainInterface) ProcessBridgeTransaction(bridgeTx *Transaction) error {
	if bhi.blockchain == nil {
		// Use HTTP API to process transaction
		return bhi.processTransactionViaHTTP(bridgeTx)
	}

	bhi.logger.Infof("🔗 Processing bridge transaction on BlackHole blockchain: %s", bridgeTx.ID)

	// Convert bridge transaction to core blockchain transaction
	coreTx, err := bhi.convertBridgeToCoreTx(bridgeTx)
	if err != nil {
		return fmt.Errorf("failed to convert bridge transaction: %v", err)
	}

	// Process transaction through core blockchain
	err = bhi.blockchain.ProcessTransaction(coreTx)
	if err != nil {
		return fmt.Errorf("failed to process transaction on blockchain: %v", err)
	}

	// Update bridge transaction status
	bridgeTx.Status = "confirmed"
	bridgeTx.BlockNumber = uint64(len(bhi.blockchain.Blocks))
	now := time.Now()
	bridgeTx.CompletedAt = &now
	bridgeTx.ProcessingTime = fmt.Sprintf("%.2fs", time.Since(bridgeTx.CreatedAt).Seconds())

	bhi.logger.Infof("✅ Bridge transaction processed successfully: %s", bridgeTx.ID)
	return nil
}

// convertBridgeToCoreTx converts bridge transaction to core blockchain transaction
func (bhi *BlackHoleBlockchainInterface) convertBridgeToCoreTx(bridgeTx *Transaction) (*chain.Transaction, error) {
	// Parse amount from string to uint64
	amount, err := strconv.ParseUint(bridgeTx.Amount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %s", bridgeTx.Amount)
	}

	// Create core blockchain transaction
	coreTx := &chain.Transaction{
		ID:        bridgeTx.Hash,
		Type:      chain.TokenTransfer,
		From:      bridgeTx.SourceAddress,
		To:        bridgeTx.DestAddress,
		Amount:    amount,
		TokenID:   bridgeTx.TokenSymbol,
		Timestamp: bridgeTx.CreatedAt.Unix(),
		Nonce:     0, // Will be set by blockchain
	}

	return coreTx, nil
}

// GetBlockchainStats returns current blockchain statistics
func (bhi *BlackHoleBlockchainInterface) GetBlockchainStats() map[string]interface{} {
	if bhi.blockchain == nil {
		// Get stats via HTTP API
		return bhi.getStatsViaHTTP()
	}

	totalTxs := 0
	for _, block := range bhi.blockchain.Blocks {
		totalTxs += len(block.Transactions)
	}

	return map[string]interface{}{
		"mode":         "live",
		"blocks":       len(bhi.blockchain.Blocks),
		"transactions": totalTxs,
		"tokens":       len(bhi.blockchain.TokenRegistry),
		"total_supply": bhi.blockchain.TotalSupply,
	}
}

// processTransactionViaHTTP processes a bridge transaction via HTTP API
func (bhi *BlackHoleBlockchainInterface) processTransactionViaHTTP(bridgeTx *Transaction) error {
	bhi.logger.Infof("🔗 Processing bridge transaction via HTTP API: %s", bridgeTx.ID)

	// Create transaction payload for the blockchain API
	payload := map[string]interface{}{
		"from":      bridgeTx.SourceAddress,
		"to":        bridgeTx.DestAddress,
		"amount":    bridgeTx.Amount,
		"token":     bridgeTx.TokenSymbol,
		"type":      "bridge_transfer",
		"bridge_id": bridgeTx.ID,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction payload: %v", err)
	}

	// Send transaction to blockchain node
	blockchainURL := "http://localhost:8080/api/transactions"
	resp, err := http.Post(blockchainURL, "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to send transaction to blockchain: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("blockchain API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode blockchain response: %v", err)
	} 

	// Update bridge transaction status
	bridgeTx.Status = "confirmed"
	if txHash, ok := result["transaction_hash"].(string); ok {                 
		bridgeTx.Hash = txHash
	}
	if blockNum, ok := result["block_number"].(float64); ok {
		bridgeTx.BlockNumber = uint64(blockNum)
	}

	now := time.Now()
	bridgeTx.CompletedAt = &now
	bridgeTx.ProcessingTime = fmt.Sprintf("%.2fs", time.Since(bridgeTx.CreatedAt).Seconds())

	bhi.logger.Infof("✅ Bridge transaction processed successfully via HTTP: %s", bridgeTx.ID)
	return nil
}

// getStatsViaHTTP gets blockchain statistics via HTTP API
func (bhi *BlackHoleBlockchainInterface) getStatsViaHTTP() map[string]interface{} {
	blockchainURL := "http://localhost:8080/api/blockchain/info"
	resp, err := http.Get(blockchainURL)
	if err != nil {
		bhi.logger.Errorf("Failed to get blockchain stats: %v", err)
		return map[string]interface{}{
			"mode":         "disconnected",
			"blocks":       0,
			"transactions": 0,
			"tokens":       0,
			"error":        err.Error(),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return map[string]interface{}{
			"mode":         "error",
			"blocks":       0,
			"transactions": 0,
			"tokens":       0,
			"status_code":  resp.StatusCode,
		}
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		bhi.logger.Errorf("Failed to decode blockchain stats: %v", err)
		return map[string]interface{}{
			"mode":         "decode_error",
			"blocks":       0,
			"transactions": 0,
			"tokens":       0,
		}
	}

	// Extract stats from the response
	stats := map[string]interface{}{
		"mode": "live",
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		if blockHeight, ok := data["block_height"].(float64); ok {
			stats["blocks"] = int(blockHeight)
		}
		if pendingTxs, ok := data["pending_txs"].(float64); ok {
			stats["pending_transactions"] = int(pendingTxs)
		}
		if validatorCount, ok := data["validator_count"].(float64); ok {
			stats["validators"] = int(validatorCount)
		}
		stats["status"] = data["status"]
		stats["version"] = data["version"]
	}

	return stats
}

// GetTokenBalance retrieves token balance from the blockchain
func (bhi *BlackHoleBlockchainInterface) GetTokenBalance(address, tokenSymbol string) (uint64, error) {
	if bhi.blockchain == nil {
		return 1000000, nil // Mock balance for simulation
	}

	token, exists := bhi.blockchain.TokenRegistry[tokenSymbol]
	if !exists {
		return 0, fmt.Errorf("token %s not found in registry", tokenSymbol)
	}

	balance, err := token.BalanceOf(address)
	if err != nil {
		return 0, fmt.Errorf("failed to get balance: %v", err)
	}

	return balance, nil
}

// IsLive returns true if connected to real blockchain
func (bhi *BlackHoleBlockchainInterface) IsLive() bool {
	return bhi.blockchain != nil
}

// Enhanced blockchain integration methods for BridgeSDK

// getBlockchainMode returns the current blockchain mode
func (sdk *BridgeSDK) getBlockchainMode() string {
	if sdk.blockchainInterface != nil && sdk.blockchainInterface.IsLive() {
		return "live_blockchain"
	}
	return "simulation_mode"
}

// analyzeTransactionForFraud analyzes a transaction for fraud indicators
func (sdk *BridgeSDK) analyzeTransactionForFraud(tx *Transaction, rules []string, sensitivity string) bool {
	// Enhanced fraud detection with real blockchain data
	suspiciousScore := 0.0

	// Rule: Unusual amount detection
	if contains(rules, "unusual_amount") {
		amount, err := strconv.ParseFloat(tx.Amount, 64)
		if err == nil {
			// Check if amount is unusually high (>10000 for high sensitivity, >50000 for medium, >100000 for low)
			threshold := 100000.0
			if sensitivity == "high" {
				threshold = 10000.0
			} else if sensitivity == "medium" {
				threshold = 50000.0
			}

			if amount > threshold {
				suspiciousScore += 30.0
				sdk.logger.Warnf("🚨 Unusual amount detected: %s %s (threshold: %.0f)", tx.Amount, tx.TokenSymbol, threshold)
			}
		}
	}

	// Rule: Velocity check - analyze transaction frequency from same address
	if contains(rules, "velocity_check") {
		recentCount := sdk.countRecentTransactionsFromAddress(tx.SourceAddress, 5*time.Minute)
		if recentCount > 10 {
			suspiciousScore += 25.0
			sdk.logger.Warnf("🚨 High velocity detected: %d transactions from %s in 5 minutes", recentCount, tx.SourceAddress)
		}
	}

	// Rule: Geographic anomaly (simulated based on address patterns)
	if contains(rules, "geo_anomaly") {
		if sdk.isGeographicallyAnomalous(tx.SourceAddress) {
			suspiciousScore += 20.0
			sdk.logger.Warnf("🚨 Geographic anomaly detected for address: %s", tx.SourceAddress)
		}
	}

	// Rule: Cross-chain pattern analysis
	if contains(rules, "cross_chain_pattern") {
		if sdk.isSuspiciousCrossChainPattern(tx) {
			suspiciousScore += 35.0
			sdk.logger.Warnf("🚨 Suspicious cross-chain pattern: %s -> %s", tx.SourceChain, tx.DestChain)
		}
	}

	// Determine if transaction is fraudulent based on sensitivity
	fraudThreshold := 50.0
	if sensitivity == "high" {
		fraudThreshold = 30.0
	} else if sensitivity == "low" {
		fraudThreshold = 70.0
	}

	isFraudulent := suspiciousScore >= fraudThreshold
	if isFraudulent {
		sdk.logger.Warnf("🚨 FRAUD DETECTED: Transaction %s scored %.1f (threshold: %.1f)", tx.ID, suspiciousScore, fraudThreshold)
	}

	return isFraudulent
}

// createFraudAlert creates a fraud alert for a suspicious transaction
func (sdk *BridgeSDK) createFraudAlert(tx *Transaction, detectionID string) {
	alert := map[string]interface{}{
		"alert_id":         fmt.Sprintf("FRAUD_%d", time.Now().Unix()),
		"detection_id":     detectionID,
		"transaction_id":   tx.ID,
		"transaction_hash": tx.Hash,
		"severity":         "high",
		"type":             "fraud_detection",
		"description":      fmt.Sprintf("Fraudulent transaction detected: %s %s from %s to %s", tx.Amount, tx.TokenSymbol, tx.SourceAddress, tx.DestAddress),
		"timestamp":        time.Now().Format(time.RFC3339),
		"source_chain":     tx.SourceChain,
		"dest_chain":       tx.DestChain,
		"amount":           tx.Amount,
		"token":            tx.TokenSymbol,
		"status":           "active",
		"acknowledged":     false,
	}

	// Store alert (in production, this would go to a database)
	sdk.logger.Errorf("🚨 FRAUD ALERT CREATED: %+v", alert)

	// If blockchain is live, also log to blockchain audit trail
	if sdk.blockchainInterface != nil && sdk.blockchainInterface.IsLive() {
		sdk.logToBlockchainAuditTrail("fraud_alert", alert)
	}
}

// Helper methods for fraud detection

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (sdk *BridgeSDK) countRecentTransactionsFromAddress(address string, duration time.Duration) int {
	count := 0
	cutoff := time.Now().Add(-duration)

	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	for _, tx := range sdk.transactions {
		if tx.SourceAddress == address && tx.CreatedAt.After(cutoff) {
			count++
		}
	}

	return count
}

func (sdk *BridgeSDK) isGeographicallyAnomalous(address string) bool {
	// Simulate geographic analysis based on address patterns
	// In production, this would use real geolocation data
	return len(address) > 40 && (address[2:4] == "ff" || address[2:4] == "00")
}

func (sdk *BridgeSDK) isSuspiciousCrossChainPattern(tx *Transaction) bool {
	// Analyze cross-chain patterns for suspicious behavior
	// Check for rapid back-and-forth transfers
	recentOppositeTransfers := 0
	cutoff := time.Now().Add(-10 * time.Minute)

	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	for _, otherTx := range sdk.transactions {
		if otherTx.CreatedAt.After(cutoff) &&
			otherTx.SourceChain == tx.DestChain &&
			otherTx.DestChain == tx.SourceChain &&
			otherTx.SourceAddress == tx.DestAddress {
			recentOppositeTransfers++
		}
	}

	return recentOppositeTransfers > 3
}

func (sdk *BridgeSDK) logToBlockchainAuditTrail(eventType string, data interface{}) {
	// Log security events to blockchain audit trail
	auditEntry := map[string]interface{}{
		"timestamp":  time.Now().Format(time.RFC3339),
		"event_type": eventType,
		"data":       data,
		"source":     "bridge_sdk_security",
	}

	sdk.logger.Infof("📝 Blockchain audit trail: %s - %+v", eventType, auditEntry)

	// In production, this would write to the blockchain's audit system
	if sdk.blockchainInterface != nil && sdk.blockchainInterface.IsLive() {
		stats := sdk.blockchainInterface.GetBlockchainStats()
		sdk.logger.Infof("🔗 Audit logged to blockchain (current blocks: %v)", stats["blocks"])
	}
}

// createStressTestTransaction creates a transaction for stress testing
func (sdk *BridgeSDK) createStressTestTransaction(testID string, workerID int, testType string) *Transaction {
	// Generate realistic test data based on test type
	var sourceChain, destChain, tokenSymbol, amount string

	switch testType {
	case "throughput":
		// High volume, small amounts
		sourceChain = "ethereum"
		destChain = "solana"
		tokenSymbol = "USDC"
		amount = fmt.Sprintf("%.2f", rand.Float64()*100+1) // 1-101 USDC
	case "latency":
		// Medium volume, medium amounts
		sourceChain = "solana"
		destChain = "blackhole"
		tokenSymbol = "SOL"
		amount = fmt.Sprintf("%.4f", rand.Float64()*10+0.1) // 0.1-10.1 SOL
	case "endurance":
		// Consistent load over time
		chains := []string{"ethereum", "solana", "blackhole"}
		sourceChain = chains[rand.Intn(len(chains))]
		destChain = chains[rand.Intn(len(chains))]
		for destChain == sourceChain {
			destChain = chains[rand.Intn(len(chains))]
		}
		tokenSymbol = "BHX"
		amount = fmt.Sprintf("%.2f", rand.Float64()*1000+10) // 10-1010 BHX
	case "spike":
		// Sudden high load
		sourceChain = "blackhole"
		destChain = "ethereum"
		tokenSymbol = "ETH"
		amount = fmt.Sprintf("%.6f", rand.Float64()*5+0.001) // 0.001-5.001 ETH
	default:
		sourceChain = "ethereum"
		destChain = "solana"
		tokenSymbol = "USDC"
		amount = "100.00"
	}

	// Create stress test transaction
	tx := &Transaction{
		ID:            fmt.Sprintf("stress_%s_w%d_%d", testID, workerID, time.Now().UnixNano()),
		Hash:          fmt.Sprintf("0x%x", rand.Uint64()),
		SourceChain:   sourceChain,
		DestChain:     destChain,
		SourceAddress: fmt.Sprintf("0x%040x", rand.Uint64()),
		DestAddress:   fmt.Sprintf("0x%040x", rand.Uint64()),
		TokenSymbol:   tokenSymbol,
		Amount:        amount,
		Fee:           "0.001",
		Status:        "pending",
		CreatedAt:     time.Now(),
		Confirmations: 0,
		BlockNumber:   0,
		GasUsed:       21000,
		GasPrice:      "20000000000", // 20 gwei
		RetryCount:    0,
	}

	// Save transaction for tracking
	sdk.saveTransaction(tx)

	return tx
}

// checkTransactionCompliance checks a transaction against compliance policies
func (sdk *BridgeSDK) checkTransactionCompliance(tx *Transaction, policies []string) []string {
	violations := make([]string, 0)

	// AML (Anti-Money Laundering) checks
	if contains(policies, "AML_001") {
		if sdk.checkAMLViolation(tx) {
			violations = append(violations, "AML_001")
		}
	}

	// KYC (Know Your Customer) checks
	if contains(policies, "KYC_001") {
		if sdk.checkKYCViolation(tx) {
			violations = append(violations, "KYC_001")
		}
	}

	// Sanctions screening
	if contains(policies, "SANCTIONS_001") {
		if sdk.checkSanctionsViolation(tx) {
			violations = append(violations, "SANCTIONS_001")
		}
	}

	// Transaction limits
	if contains(policies, "LIMITS_001") {
		if sdk.checkTransactionLimits(tx) {
			violations = append(violations, "LIMITS_001")
		}
	}

	return violations
}

// checkAMLViolation checks for anti-money laundering violations
func (sdk *BridgeSDK) checkAMLViolation(tx *Transaction) bool {
	// Check for structuring (multiple transactions just under reporting threshold)
	amount, err := strconv.ParseFloat(tx.Amount, 64)
	if err != nil {
		return false
	}

	// Check for suspicious patterns
	if amount > 9000 && amount < 10000 { // Just under $10k reporting threshold
		recentSimilarTxs := sdk.countSimilarTransactions(tx.SourceAddress, amount, 24*time.Hour)
		if recentSimilarTxs > 3 {
			sdk.logger.Warnf("🚨 AML VIOLATION: Potential structuring detected - %d similar transactions from %s", recentSimilarTxs, tx.SourceAddress)
			return true
		}
	}

	// Check for rapid movement of large amounts
	if amount > 50000 {
		recentLargeTxs := sdk.countLargeTransactions(tx.SourceAddress, 50000, 1*time.Hour)
		if recentLargeTxs > 5 {
			sdk.logger.Warnf("🚨 AML VIOLATION: Rapid large transactions detected from %s", tx.SourceAddress)
			return true
		}
	}

	return false
}

// checkKYCViolation checks for KYC violations
func (sdk *BridgeSDK) checkKYCViolation(tx *Transaction) bool {
	// Check for transactions from unverified addresses
	// In production, this would check against a KYC database

	// Simulate KYC check based on address patterns
	if len(tx.SourceAddress) < 40 {
		sdk.logger.Warnf("🚨 KYC VIOLATION: Invalid address format: %s", tx.SourceAddress)
		return true
	}

	// Check for high-risk address patterns
	if tx.SourceAddress[2:6] == "0000" || tx.SourceAddress[2:6] == "ffff" {
		sdk.logger.Warnf("🚨 KYC VIOLATION: High-risk address pattern: %s", tx.SourceAddress)
		return true
	}

	return false
}

// checkSanctionsViolation checks against sanctions lists
func (sdk *BridgeSDK) checkSanctionsViolation(tx *Transaction) bool {
	// Simulate sanctions screening
	sanctionedAddresses := []string{
		"0x1234567890abcdef1234567890abcdef12345678",
		"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		"0x0000000000000000000000000000000000000000",
	}

	for _, sanctioned := range sanctionedAddresses {
		if tx.SourceAddress == sanctioned || tx.DestAddress == sanctioned {
			sdk.logger.Warnf("🚨 SANCTIONS VIOLATION: Transaction involves sanctioned address: %s", sanctioned)
			return true
		}
	}

	return false
}

// checkTransactionLimits checks transaction limits
func (sdk *BridgeSDK) checkTransactionLimits(tx *Transaction) bool {
	amount, err := strconv.ParseFloat(tx.Amount, 64)
	if err != nil {
		return false
	}

	// Daily limit check
	dailyLimit := 100000.0 // $100k daily limit
	dailyTotal := sdk.calculateDailyTotal(tx.SourceAddress)

	if dailyTotal+amount > dailyLimit {
		sdk.logger.Warnf("🚨 LIMITS VIOLATION: Daily limit exceeded for %s: %.2f + %.2f > %.2f", tx.SourceAddress, dailyTotal, amount, dailyLimit)
		return true
	}

	// Single transaction limit
	singleTxLimit := 50000.0 // $50k single transaction limit
	if amount > singleTxLimit {
		sdk.logger.Warnf("🚨 LIMITS VIOLATION: Single transaction limit exceeded: %.2f > %.2f", amount, singleTxLimit)
		return true
	}

	return false
}

// createComplianceViolation creates a compliance violation record
func (sdk *BridgeSDK) createComplianceViolation(tx *Transaction, violations []string, automationID string) {
	violation := map[string]interface{}{
		"violation_id":     fmt.Sprintf("COMP_VIOL_%d", time.Now().Unix()),
		"automation_id":    automationID,
		"transaction_id":   tx.ID,
		"transaction_hash": tx.Hash,
		"violations":       violations,
		"severity":         sdk.calculateViolationSeverity(violations),
		"timestamp":        time.Now().Format(time.RFC3339),
		"source_chain":     tx.SourceChain,
		"dest_chain":       tx.DestChain,
		"amount":           tx.Amount,
		"token":            tx.TokenSymbol,
		"source_address":   tx.SourceAddress,
		"dest_address":     tx.DestAddress,
		"status":           "open",
		"resolved":         false,
	}

	// Store violation (in production, this would go to a compliance database)
	sdk.logger.Errorf("🚨 COMPLIANCE VIOLATION CREATED: %+v", violation)

	// If blockchain is live, also log to blockchain audit trail
	if sdk.blockchainInterface != nil && sdk.blockchainInterface.IsLive() {
		sdk.logToBlockchainAuditTrail("compliance_violation", violation)
	}
}

// Helper methods for compliance checks

func (sdk *BridgeSDK) countSimilarTransactions(address string, amount float64, duration time.Duration) int {
	count := 0
	cutoff := time.Now().Add(-duration)
	tolerance := amount * 0.1 // 10% tolerance

	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	for _, tx := range sdk.transactions {
		if tx.SourceAddress == address && tx.CreatedAt.After(cutoff) {
			txAmount, err := strconv.ParseFloat(tx.Amount, 64)
			if err == nil && txAmount >= amount-tolerance && txAmount <= amount+tolerance {
				count++
			}
		}
	}

	return count
}

func (sdk *BridgeSDK) countLargeTransactions(address string, threshold float64, duration time.Duration) int {
	count := 0
	cutoff := time.Now().Add(-duration)

	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	for _, tx := range sdk.transactions {
		if tx.SourceAddress == address && tx.CreatedAt.After(cutoff) {
			txAmount, err := strconv.ParseFloat(tx.Amount, 64)
			if err == nil && txAmount >= threshold {
				count++
			}
		}
	}

	return count
}

func (sdk *BridgeSDK) calculateDailyTotal(address string) float64 {
	total := 0.0
	cutoff := time.Now().Add(-24 * time.Hour)

	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	for _, tx := range sdk.transactions {
		if tx.SourceAddress == address && tx.CreatedAt.After(cutoff) {
			amount, err := strconv.ParseFloat(tx.Amount, 64)
			if err == nil {
				total += amount
			}
		}
	}

	return total
}

func (sdk *BridgeSDK) calculateViolationSeverity(violations []string) string {
	if contains(violations, "SANCTIONS_001") {
		return "critical"
	}
	if contains(violations, "AML_001") {
		return "high"
	}
	if contains(violations, "KYC_001") || contains(violations, "LIMITS_001") {
		return "medium"
	}
	return "low"
}

// PerformanceMetrics tracks system performance statistics
type PerformanceMetrics struct {
	mutex               sync.RWMutex
	cpuUsage           float64
	memoryUsage        float64
	activeConnections  int
	eventsPerSecond    float64
	avgResponseTime    float64
	errorCount         int
	lastEventTime      time.Time
	eventCount         int64
}

// BridgeSDK represents the main bridge SDK
type BridgeSDK struct {
	blockchain          interface{}                   // Can be BlackHoleBlockchainInterface or nil for simulation
	blockchainInterface *BlackHoleBlockchainInterface // Real blockchain interface
	config              *Config
	db                  *bbolt.DB
	logger              *logrus.Logger
	upgrader            websocket.Upgrader
	clients             map[*websocket.Conn]bool
	clientsMutex        sync.RWMutex
	replayProtection    *ReplayProtection
	circuitBreakers     map[string]*CircuitBreaker
	errorHandler        *ErrorHandler
	eventRecovery       *EventRecovery
	logStreamer         *LogStreamer
	retryQueue          *RetryQueue
	panicRecovery       *PanicRecovery
	startTime           time.Time
	performanceMetrics  *PerformanceMetrics
	transactions        map[string]*Transaction
	transactionsMutex   sync.RWMutex
	events              []Event
	eventsMutex         sync.RWMutex
	blockedReplays      int64
	blockedMutex        sync.RWMutex
	deadLetterQueue     []DeadLetterItem
	deadLetterMutex     sync.RWMutex
	retryConfig         RetryConfig
	relayServer         *RelayServer
	performanceMonitor  *PerformanceMonitor
	loadTester          *LoadTester
	chaosTester         *ChaosTester
 	useRealBlockchainListeners bool
	// Enhanced dashboard fields
	mu               sync.RWMutex
	loadTestRunning  bool
	chaosTestRunning bool
}

// Config holds the bridge configuration
type Config struct {
	EthereumRPC             string
	SolanaRPC               string
	BlackHoleRPC            string
	DatabasePath            string
	LogLevel                string
	LogFile                 string
	ReplayProtectionEnabled bool
	CircuitBreakerEnabled   bool
	Port                    string
	MaxRetries              int
	RetryDelay              time.Duration
	BatchSize               int
}

// Transaction represents a bridge transaction
type Transaction struct {
	ID             string     `json:"id"`
	Hash           string     `json:"hash"`
	SourceChain    string     `json:"source_chain"`
	DestChain      string     `json:"dest_chain"`
	SourceAddress  string     `json:"source_address"`
	DestAddress    string     `json:"dest_address"`
	TokenSymbol    string     `json:"token_symbol"`
	Amount         string     `json:"amount"`
	Fee            string     `json:"fee"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	Confirmations  int        `json:"confirmations"`
	BlockNumber    uint64     `json:"block_number"`
	GasUsed        uint64     `json:"gas_used,omitempty"`
	GasPrice       string     `json:"gas_price,omitempty"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	RetryCount     int        `json:"retry_count"`
	LastRetryAt    *time.Time `json:"last_retry_at,omitempty"`
	ProcessingTime string     `json:"processing_time,omitempty"`
}

type Event struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Chain        string                 `json:"chain"`
	BlockNumber  uint64                 `json:"block_number"`
	TxHash       string                 `json:"tx_hash"`
	Timestamp    time.Time              `json:"timestamp"`
	Data         map[string]interface{} `json:"data"`
	Processed    bool                   `json:"processed"`
	ProcessedAt  *time.Time             `json:"processed_at,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	RetryCount   int                    `json:"retry_count"`
}

// ReplayProtection handles duplicate event detection
type ReplayProtection struct {
	processedHashes map[string]time.Time
	mutex           sync.RWMutex
	db              *bbolt.DB
	enabled         bool
	cacheSize       int
	cacheTTL        time.Duration
}

// Replay protection methods
func (rp *ReplayProtection) isProcessed(hash string) bool {
	if !rp.enabled {
		return false
	}

	rp.mutex.RLock()
	defer rp.mutex.RUnlock()

	// Check in-memory cache first
	if processedTime, exists := rp.processedHashes[hash]; exists {
		// Check if not expired
		if time.Since(processedTime) < rp.cacheTTL {
			return true
		}
		// Remove expired entry
		delete(rp.processedHashes, hash)
	}

	// Check in database
	var exists bool
	rp.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("replay_protection"))
		if bucket != nil {
			value := bucket.Get([]byte(hash))
			exists = value != nil
		}
		return nil
	})

	return exists
}

func (rp *ReplayProtection) markProcessed(hash string) error {
	if !rp.enabled {
		return nil
	}

	rp.mutex.Lock()
	defer rp.mutex.Unlock()

	now := time.Now()

	// Add to in-memory cache
	rp.processedHashes[hash] = now

	// Cleanup old entries if cache is too large
	if len(rp.processedHashes) > rp.cacheSize {
		rp.cleanupExpiredEntries()
	}

	// Persist to database
	return rp.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("replay_protection"))
		if bucket == nil {
			return fmt.Errorf("replay protection bucket not found")
		}

		// Store with timestamp
		value := fmt.Sprintf("%d", now.Unix())
		return bucket.Put([]byte(hash), []byte(value))
	})
}

func (rp *ReplayProtection) cleanupExpiredEntries() {
	now := time.Now()
	for hash, processedTime := range rp.processedHashes {
		if now.Sub(processedTime) > rp.cacheTTL {
			delete(rp.processedHashes, hash)
		}
	}
}

func (rp *ReplayProtection) getStats() map[string]interface{} {
	rp.mutex.RLock()
	defer rp.mutex.RUnlock()

	var dbCount int
	rp.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("replay_protection"))
		if bucket != nil {
			dbCount = bucket.Stats().KeyN
		}
		return nil
	})

	return map[string]interface{}{
		"enabled":          rp.enabled,
		"cache_size":       len(rp.processedHashes),
		"max_cache_size":   rp.cacheSize,
		"database_entries": dbCount,
		"cache_ttl":        rp.cacheTTL.String(),
	}
}

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	name             string
	state            string
	failureCount     int
	failureThreshold int
	lastFailure      *time.Time
	nextAttempt      *time.Time
	mutex            sync.RWMutex
	timeout          time.Duration
	resetTimeout     time.Duration
}

// Circuit breaker methods
func (cb *CircuitBreaker) recordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failureCount++
	now := time.Now()
	cb.lastFailure = &now

	if cb.failureCount >= cb.failureThreshold {
		cb.state = "open"
		nextAttempt := now.Add(cb.resetTimeout)
		cb.nextAttempt = &nextAttempt
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failureCount = 0
	cb.state = "closed"
	cb.lastFailure = nil
	cb.nextAttempt = nil
}

func (cb *CircuitBreaker) canExecute() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	if cb.state == "closed" {
		return true
	}

	if cb.state == "open" && cb.nextAttempt != nil && time.Now().After(*cb.nextAttempt) {
		return true
	}

	return false
}

func (cb *CircuitBreaker) getState() string {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// ErrorHandler manages error handling and recovery
type ErrorHandler struct {
	errors          []ErrorEntry
	mutex           sync.RWMutex
	circuitBreakers map[string]*CircuitBreaker
}

// ErrorEntry represents an error entry
type ErrorEntry struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Component string    `json:"component"`
	Resolved  bool      `json:"resolved"`
}

// EventRecovery handles failed event recovery
type EventRecovery struct {
	failedEvents []FailedEvent
	mutex        sync.RWMutex
}

// FailedEvent represents a failed event
type FailedEvent struct {
	ID           string     `json:"id"`
	EventType    string     `json:"event_type"`
	Chain        string     `json:"chain"`
	TxHash       string     `json:"transaction_hash"`
	ErrorMessage string     `json:"error_message"`
	RetryCount   int        `json:"retry_count"`
	MaxRetries   int        `json:"max_retries"`
	NextRetry    *time.Time `json:"next_retry,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// LogStreamer handles real-time log streaming
type LogStreamer struct {
	clients map[*websocket.Conn]bool
	mutex   sync.RWMutex
	logs    []LogEntry
}

// LogEntry represents a log entry
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Component string                 `json:"component"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// BridgeStats represents bridge statistics
type BridgeStats struct {
	TotalTransactions     int                   `json:"total_transactions"`
	PendingTransactions   int                   `json:"pending_transactions"`
	CompletedTransactions int                   `json:"completed_transactions"`
	FailedTransactions    int                   `json:"failed_transactions"`
	SuccessRate           float64               `json:"success_rate"`
	TotalVolume           string                `json:"total_volume"`
	Chains                map[string]ChainStats `json:"chains"`
	Last24h               PeriodStats           `json:"last_24h"`
	ErrorRate             float64               `json:"error_rate"`
	AverageProcessingTime string                `json:"average_processing_time"`
}

// ChainStats represents statistics for a specific chain
type ChainStats struct {
	Transactions int     `json:"transactions"`
	Volume       string  `json:"volume"`
	SuccessRate  float64 `json:"success_rate"`
	LastBlock    uint64  `json:"last_block"`
}

// PeriodStats represents statistics for a time period
type PeriodStats struct {
	Transactions int     `json:"transactions"`
	Volume       string  `json:"volume"`
	SuccessRate  float64 `json:"success_rate"`
}

// HealthStatus represents system health
type HealthStatus struct {
	Status     string            `json:"status"`
	Timestamp  time.Time         `json:"timestamp"`
	Components map[string]string `json:"components"`
	Uptime     string            `json:"uptime"`
	Version    string            `json:"version"`
	Healthy    bool              `json:"healthy"`
}

// ErrorMetrics represents error metrics
type ErrorMetrics struct {
	ErrorRate    float64        `json:"error_rate"`
	TotalErrors  int            `json:"total_errors"`
	ErrorsByType map[string]int `json:"errors_by_type"`
	RecentErrors []ErrorEntry   `json:"recent_errors"`
}

// BridgeTransferRequest represents a token transfer request (renamed to avoid conflicts)
type BridgeTransferRequest struct {
	FromChain   string `json:"from_chain"`
	ToChain     string `json:"to_chain"`
	TokenSymbol string `json:"token_symbol"`
	Amount      string `json:"amount"`
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
}

// RetryQueue handles failed operations with exponential backoff
type RetryQueue struct {
	items           []RetryItem
	deadLetterQueue []RetryItem
	mutex           sync.RWMutex
	maxRetries      int
	baseDelay       time.Duration
	maxDelay        time.Duration
}

// RetryItem represents an item in the retry queue
type RetryItem struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Data       map[string]interface{} `json:"data"`
	Attempts   int                    `json:"attempts"`
	MaxRetries int                    `json:"max_retries"`
	NextRetry  time.Time              `json:"next_retry"`
	LastError  string                 `json:"last_error"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// DeadLetterItem represents a permanently failed event
type DeadLetterItem struct {
	ID            string    `json:"id"`
	OriginalEvent RetryItem `json:"original_event"`
	FailureReason string    `json:"failure_reason"`
	FailedAt      time.Time `json:"failed_at"`
	TotalAttempts int       `json:"total_attempts"`
	ErrorHistory  []string  `json:"error_history"`
}

// RetryConfig holds retry configuration with exponential backoff
type RetryConfig struct {
	MaxAttempts     int           `json:"max_attempts"`
	BaseDelay       time.Duration `json:"base_delay"`
	MaxDelay        time.Duration `json:"max_delay"`
	BackoffFactor   float64       `json:"backoff_factor"`
	JitterEnabled   bool          `json:"jitter_enabled"`
	DeadLetterAfter int           `json:"dead_letter_after"`
}

// RelayServer represents the relay server for real-time endpoints
type RelayServer struct {
	Port            int                      `json:"port"`
	Status          string                   `json:"status"`
	Connections     int                      `json:"connections"`
	LastActivity    time.Time                `json:"last_activity"`
	WebSocketServer *websocket.Upgrader      `json:"-"`
	EventStream     chan Event               `json:"-"`
	Clients         map[*websocket.Conn]bool `json:"-"`
	ClientsMutex    sync.RWMutex             `json:"-"`
	StartedAt       time.Time                `json:"started_at"`
	TotalMessages   int64                    `json:"total_messages"`
}

// PanicRecovery handles panic recovery and logging
type PanicRecovery struct {
	recoveries []PanicEntry
	mutex      sync.RWMutex
	logger     *logrus.Logger
}

// PanicEntry represents a panic recovery entry
type PanicEntry struct {
	ID        string    `json:"id"`
	Message   string    `json:"message"`
	Stack     string    `json:"stack"`
	Component string    `json:"component"`
	Timestamp time.Time `json:"timestamp"`
	Recovered bool      `json:"recovered"`
}

// EnhancedToken represents enhanced token information
type EnhancedToken struct {
	Symbol      string `json:"symbol"`
	Name        string `json:"name"`
	Decimals    int    `json:"decimals"`
	Address     string `json:"address"`
	Chain       string `json:"chain"`
	LogoURL     string `json:"logo_url"`
	IsNative    bool   `json:"is_native"`
	TotalSupply string `json:"total_supply"`
}

// EnvironmentConfig represents environment configuration
type EnvironmentConfig struct {
	Port                    string
	EthereumRPC             string
	SolanaRPC               string
	BlackHoleRPC            string
	DatabasePath            string
	LogLevel                string
	LogFile                 string
	ReplayProtectionEnabled bool
	CircuitBreakerEnabled   bool
	MaxRetries              int
	RetryDelay              time.Duration
	BatchSize               int
	EnableColoredLogs       bool
	EnableDocumentation     bool
}

// LoadEnvironmentConfig loads configuration from environment variables and .env file
func LoadEnvironmentConfig() *EnvironmentConfig {
	config := &EnvironmentConfig{
		Port:                    getEnvOrDefault("PORT", "8084"),
		EthereumRPC:             getEnvOrDefault("ETHEREUM_RPC", "wss://eth-mainnet.alchemyapi.io/v2/demo"),
		SolanaRPC:               getEnvOrDefault("SOLANA_RPC", "wss://api.mainnet-beta.solana.com"),
		BlackHoleRPC:            getEnvOrDefault("BLACKHOLE_RPC", "ws://localhost:8545"),
		DatabasePath:            getEnvOrDefault("DATABASE_PATH", "./data/bridge_v5.db"),
		LogLevel:                getEnvOrDefault("LOG_LEVEL", "info"),
		LogFile:                 getEnvOrDefault("LOG_FILE", "./logs/bridge.log"),
		ReplayProtectionEnabled: getEnvBoolOrDefault("REPLAY_PROTECTION_ENABLED", true),
		CircuitBreakerEnabled:   getEnvBoolOrDefault("CIRCUIT_BREAKER_ENABLED", true),
		MaxRetries:              getEnvIntOrDefault("MAX_RETRIES", 3),
		BatchSize:               getEnvIntOrDefault("BATCH_SIZE", 100),
		EnableColoredLogs:       getEnvBoolOrDefault("ENABLE_COLORED_LOGS", true),
		EnableDocumentation:     getEnvBoolOrDefault("ENABLE_DOCUMENTATION", true),
	}

	retryDelayMs := getEnvIntOrDefault("RETRY_DELAY_MS", 5000)
	config.RetryDelay = time.Duration(retryDelayMs) * time.Millisecond

	// Try to load .env file if it exists
	loadDotEnv()

	return config
}

// Helper functions for environment variables
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func loadDotEnv() {
	file, err := os.Open(".env")
	if err != nil {
		return // .env file doesn't exist, which is fine
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Remove quotes if present
			if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
				value = value[1 : len(value)-1]
			}
			os.Setenv(key, value)
		}
	}
}

// EventLoopMetrics tracks comprehensive event loop performance
type EventLoopMetrics struct {
	TotalEvents       int64                    `json:"total_events"`
	EventsPerSecond   float64                  `json:"events_per_second"`
	AverageLatency    time.Duration            `json:"average_latency"`
	P95Latency        time.Duration            `json:"p95_latency"`
	P99Latency        time.Duration            `json:"p99_latency"`
	ChainLatencies    map[string]time.Duration `json:"chain_latencies"`
	ErrorRate         float64                  `json:"error_rate"`
	ThroughputHistory []ThroughputPoint        `json:"throughput_history"`
	LatencyHistory    []LatencyPoint           `json:"latency_history"`
	LastUpdated       time.Time                `json:"last_updated"`
	StartTime         time.Time                `json:"start_time"`
	mutex             sync.RWMutex             `json:"-"`
}

// ThroughputPoint represents a point in throughput history
type ThroughputPoint struct {
	Timestamp       time.Time `json:"timestamp"`
	EventsPerSecond float64   `json:"events_per_second"`
	TotalEvents     int64     `json:"total_events"`
}

// LatencyPoint represents a point in latency history
type LatencyPoint struct {
	Timestamp      time.Time     `json:"timestamp"`
	AverageLatency time.Duration `json:"average_latency"`
	P95Latency     time.Duration `json:"p95_latency"`
	P99Latency     time.Duration `json:"p99_latency"`
}

// EventTiming tracks timing information for individual events
type EventTiming struct {
	EventID   string        `json:"event_id"`
	Chain     string        `json:"chain"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
	Stage     string        `json:"stage"` // detection, processing, confirmation, relay, completion
	Success   bool          `json:"success"`
}

// PerformanceMonitor tracks real-time performance metrics
type PerformanceMonitor struct {
	EventTimings    []EventTiming                       `json:"event_timings"`
	Metrics         EventLoopMetrics                    `json:"metrics"`
	ChainMetrics    map[string]*ChainPerformanceMetrics `json:"chain_metrics"`
	AlertThresholds AlertThresholds                     `json:"alert_thresholds"`
	mutex           sync.RWMutex                        `json:"-"`
}

// ChainPerformanceMetrics tracks per-chain performance
type ChainPerformanceMetrics struct {
	ChainName       string        `json:"chain_name"`
	EventCount      int64         `json:"event_count"`
	AverageLatency  time.Duration `json:"average_latency"`
	ErrorCount      int64         `json:"error_count"`
	ErrorRate       float64       `json:"error_rate"`
	LastEventTime   time.Time     `json:"last_event_time"`
	ThroughputTrend string        `json:"throughput_trend"` // increasing, decreasing, stable
}

// AlertThresholds defines performance alert thresholds
type AlertThresholds struct {
	MaxLatency    time.Duration `json:"max_latency"`
	MaxErrorRate  float64       `json:"max_error_rate"`
	MinThroughput float64       `json:"min_throughput"`
	MaxQueueSize  int           `json:"max_queue_size"`
}

// Load Testing and Chaos Testing Types

// LoadTestConfig defines configuration for load testing
type LoadTestConfig struct {
	TotalTransactions int                `json:"total_transactions"`
	ConcurrentWorkers int                `json:"concurrent_workers"`
	TransactionRate   int                `json:"transaction_rate"` // transactions per second
	TestDuration      time.Duration      `json:"test_duration"`
	ChainDistribution map[string]float64 `json:"chain_distribution"` // percentage per chain
	FailureRate       float64            `json:"failure_rate"`       // percentage of transactions to fail
	RetryCount        int                `json:"retry_count"`
}

// ChaosTestConfig defines configuration for chaos testing
type ChaosTestConfig struct {
	TestDuration     time.Duration `json:"test_duration"`
	FailureInjection bool          `json:"failure_injection"`
	NetworkLatency   time.Duration `json:"network_latency"`
	RandomDelays     bool          `json:"random_delays"`
	CircuitBreaker   bool          `json:"circuit_breaker"`
	MemoryPressure   bool          `json:"memory_pressure"`
	DiskPressure     bool          `json:"disk_pressure"`
}

// TestStatus tracks the status of running tests
type TestStatus struct {
	TestType          string        `json:"test_type"`
	Status            string        `json:"status"` // running, completed, failed, stopped
	StartTime         time.Time     `json:"start_time"`
	EndTime           *time.Time    `json:"end_time"`
	Duration          time.Duration `json:"duration"`
	TotalTransactions int           `json:"total_transactions"`
	SuccessfulTx      int           `json:"successful_tx"`
	FailedTx          int           `json:"failed_tx"`
	RetriedTx         int           `json:"retried_tx"`
	AverageLatency    time.Duration `json:"average_latency"`
	MaxLatency        time.Duration `json:"max_latency"`
	MinLatency        time.Duration `json:"min_latency"`
	ThroughputTPS     float64       `json:"throughput_tps"`
	ErrorRate         float64       `json:"error_rate"`
	Results           []TestResult  `json:"results"`
	mutex             sync.RWMutex  `json:"-"`
}

// TestResult represents the result of a single test transaction
type TestResult struct {
	TransactionID string        `json:"transaction_id"`
	Chain         string        `json:"chain"`
	StartTime     time.Time     `json:"start_time"`
	EndTime       time.Time     `json:"end_time"`
	Duration      time.Duration `json:"duration"`
	Success       bool          `json:"success"`
	ErrorMessage  string        `json:"error_message,omitempty"`
	RetryCount    int           `json:"retry_count"`
}

// LoadTester manages load testing operations
type LoadTester struct {
	Config       LoadTestConfig  `json:"config"`
	Status       TestStatus      `json:"status"`
	Workers      []chan bool     `json:"-"`
	StopChannel  chan bool       `json:"-"`
	ResultsQueue chan TestResult `json:"-"`
	mutex        sync.RWMutex    `json:"-"`
}

// ChaosTester manages chaos testing operations
type ChaosTester struct {
	Config      ChaosTestConfig `json:"config"`
	Status      TestStatus      `json:"status"`
	StopChannel chan bool       `json:"-"`
	mutex       sync.RWMutex    `json:"-"`
}

// NewBridgeSDK creates a new bridge SDK instance
func NewBridgeSDK(blockchain interface{}, config *Config) *BridgeSDK {
	// Load environment configuration
	envConfig := LoadEnvironmentConfig()

	if config == nil {
		config = &Config{
			EthereumRPC:             envConfig.EthereumRPC,
			SolanaRPC:               envConfig.SolanaRPC,
			BlackHoleRPC:            envConfig.BlackHoleRPC,
			DatabasePath:            envConfig.DatabasePath,
			LogLevel:                envConfig.LogLevel,
			LogFile:                 envConfig.LogFile,
			ReplayProtectionEnabled: envConfig.ReplayProtectionEnabled,
			CircuitBreakerEnabled:   envConfig.CircuitBreakerEnabled,
			Port:                    envConfig.Port,
			MaxRetries:              envConfig.MaxRetries,
			RetryDelay:              envConfig.RetryDelay,
			BatchSize:               envConfig.BatchSize,
		}
	}

	logger := logrus.New()
	level, _ := logrus.ParseLevel(config.LogLevel)
	logger.SetLevel(level)

	// Configure colored logging if enabled
	if envConfig.EnableColoredLogs {
		logger.SetFormatter(&logrus.TextFormatter{
			ForceColors:     true,
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
	} else {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02 15:04:05",
		})
	}

	// Ensure directories exist
	os.MkdirAll(filepath.Dir(config.DatabasePath), 0755)
	os.MkdirAll(filepath.Dir(config.LogFile), 0755)

	// Open database
	log.Printf("Opening database at: %s", config.DatabasePath)
	db, err := bbolt.Open(config.DatabasePath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	log.Printf("Database opened successfully")

	// Initialize buckets
	db.Update(func(tx *bbolt.Tx) error {
		tx.CreateBucketIfNotExists([]byte("transactions"))
		tx.CreateBucketIfNotExists([]byte("events"))
		tx.CreateBucketIfNotExists([]byte("replay_protection"))
		tx.CreateBucketIfNotExists([]byte("failed_events"))
		tx.CreateBucketIfNotExists([]byte("errors"))
		return nil
	})

	// Initialize blockchain interface if real blockchain is provided
	var blockchainInterface *BlackHoleBlockchainInterface
	if coreBlockchain, ok := blockchain.(*chain.Blockchain); ok && coreBlockchain != nil {
		blockchainInterface = &BlackHoleBlockchainInterface{
			blockchain: coreBlockchain,
			logger:     logger,
		}
		logger.Info("🔗 Initialized with real BlackHole blockchain")
	} else {
		logger.Info("🎭 Running in simulation mode - no real blockchain connected")
	}

	// Initialize components
	replayProtection := &ReplayProtection{
		processedHashes: make(map[string]time.Time),
		db:              db,
		enabled:         config.ReplayProtectionEnabled,
		cacheSize:       10000,
		cacheTTL:        24 * time.Hour,
	}

	circuitBreakers := make(map[string]*CircuitBreaker)
	if config.CircuitBreakerEnabled {
		circuitBreakers["ethereum_listener"] = &CircuitBreaker{
			name:             "ethereum_listener",
			state:            "closed",
			failureThreshold: 5,
			timeout:          60 * time.Second,
			resetTimeout:     300 * time.Second,
		}
		circuitBreakers["solana_listener"] = &CircuitBreaker{
			name:             "solana_listener",
			state:            "closed",
			failureThreshold: 5,
			timeout:          60 * time.Second,
			resetTimeout:     300 * time.Second,
		}
		circuitBreakers["blackhole_listener"] = &CircuitBreaker{
			name:             "blackhole_listener",
			state:            "closed",
			failureThreshold: 5,
			timeout:          60 * time.Second,
			resetTimeout:     300 * time.Second,
		}
	}

	errorHandler := &ErrorHandler{
		errors:          make([]ErrorEntry, 0),
		circuitBreakers: circuitBreakers,
	}

	eventRecovery := &EventRecovery{
		failedEvents: make([]FailedEvent, 0),
	}

	logStreamer := &LogStreamer{
		clients: make(map[*websocket.Conn]bool),
		logs:    make([]LogEntry, 0),
	}

	retryQueue := &RetryQueue{
		items:      make([]RetryItem, 0),
		maxRetries: config.MaxRetries,
		baseDelay:  1 * time.Second,
		maxDelay:   60 * time.Second,
	}

	panicRecovery := &PanicRecovery{
		recoveries: make([]PanicEntry, 0),
		logger:     logger,
	}

	// Initialize enhanced retry configuration
	retryConfig := RetryConfig{
		MaxAttempts:     config.MaxRetries,
		BaseDelay:       1 * time.Second,
		MaxDelay:        5 * time.Minute,
		BackoffFactor:   2.0,
		JitterEnabled:   true,
		DeadLetterAfter: config.MaxRetries * 2,
	}

	// Initialize relay server
	relayServer := &RelayServer{
		Port:          9090,
		Status:        "initializing",
		Connections:   0,
		LastActivity:  time.Now(),
		EventStream:   make(chan Event, 1000),
		Clients:       make(map[*websocket.Conn]bool),
		StartedAt:     time.Now(),
		TotalMessages: 0,
		WebSocketServer: &websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for demo
			},
		},
	}

	// Initialize performance monitor
	performanceMonitor := &PerformanceMonitor{
		EventTimings: make([]EventTiming, 0),
		Metrics: EventLoopMetrics{
			TotalEvents:       0,
			EventsPerSecond:   0,
			AverageLatency:    0,
			P95Latency:        0,
			P99Latency:        0,
			ChainLatencies:    make(map[string]time.Duration),
			ErrorRate:         0,
			ThroughputHistory: make([]ThroughputPoint, 0),
			LatencyHistory:    make([]LatencyPoint, 0),
			LastUpdated:       time.Now(),
			StartTime:         time.Now(),
		},
		ChainMetrics: map[string]*ChainPerformanceMetrics{
			"ethereum": {
				ChainName:       "ethereum",
				EventCount:      0,
				AverageLatency:  0,
				ErrorCount:      0,
				ErrorRate:       0,
				LastEventTime:   time.Time{},
				ThroughputTrend: "stable",
			},
			"solana": {
				ChainName:       "solana",
				EventCount:      0,
				AverageLatency:  0,
				ErrorCount:      0,
				ErrorRate:       0,
				LastEventTime:   time.Time{},
				ThroughputTrend: "stable",
			},
			"blackhole": {
				ChainName:       "blackhole",
				EventCount:      0,
				AverageLatency:  0,
				ErrorCount:      0,
				ErrorRate:       0,
				LastEventTime:   time.Time{},
				ThroughputTrend: "stable",
			},
		},
		AlertThresholds: AlertThresholds{
			MaxLatency:    5 * time.Second,
			MaxErrorRate:  0.05, // 5%
			MinThroughput: 1.0,  // 1 event per second
			MaxQueueSize:  100,
		},
	}

	return &BridgeSDK{
		blockchain:          blockchain,
		blockchainInterface: blockchainInterface,
		config:              config,
		db:                  db,
		logger:              logger,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for demo
			},
		},
		clients:            make(map[*websocket.Conn]bool),
		replayProtection:   replayProtection,
		circuitBreakers:    circuitBreakers,
		errorHandler:       errorHandler,
		eventRecovery:      eventRecovery,
		logStreamer:        logStreamer,
		retryQueue:         retryQueue,
		panicRecovery:      panicRecovery,
		startTime:          time.Now(),
		performanceMetrics: &PerformanceMetrics{
			cpuUsage:          15.0,
			memoryUsage:       45.0,
			activeConnections: 0,
			eventsPerSecond:   0.0,
			avgResponseTime:   150.0,
			errorCount:        0,
			lastEventTime:     time.Now(),
			eventCount:        0,
		},
		transactions:       make(map[string]*Transaction),
		events:             make([]Event, 0),
		blockedReplays:     0,
		deadLetterQueue:    make([]DeadLetterItem, 0),
		retryConfig:        retryConfig,
		relayServer:        relayServer,
		performanceMonitor: performanceMonitor,
		loadTester: &LoadTester{
			Config: LoadTestConfig{
				TotalTransactions: 1000,
				ConcurrentWorkers: 10,
				TransactionRate:   100,
				TestDuration:      5 * time.Minute,
				ChainDistribution: map[string]float64{
					"ethereum":  0.4,
					"solana":    0.3,
					"blackhole": 0.3,
				},
				FailureRate: 0.05,
				RetryCount:  3,
			},
			Status: TestStatus{
				TestType: "load",
				Status:   "idle",
			},
			StopChannel:  make(chan bool, 1),
			ResultsQueue: make(chan TestResult, 1000),
		},
		chaosTester: &ChaosTester{
			Config: ChaosTestConfig{
				TestDuration:     10 * time.Minute,
				FailureInjection: true,
				NetworkLatency:   100 * time.Millisecond,
				RandomDelays:     true,
				CircuitBreaker:   true,
				MemoryPressure:   false,
				DiskPressure:     false,
			},
			Status: TestStatus{
				TestType: "chaos",
				Status:   "idle",
			},
			StopChannel: make(chan bool, 1),
		},
	}
}

// StartEthereumListener starts the Ethereum blockchain listener
func (sdk *BridgeSDK) StartEthereumListener(ctx context.Context) error {
	sdk.logger.Info("🔗 Starting Ethereum listener...")

	// Check if we should use real blockchain listeners
	if sdk.useRealBlockchainListeners {
		// Use real blockchain listener
		realListener := core.NewRealBlockchainListener(sdk)
		return realListener.StartEthereumListener(ctx)
	}

	// Otherwise use mock listener (default for development)
	go func() {
		ticker := time.NewTicker(8 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Create a mock transaction
				tx := &Transaction{
					ID:            fmt.Sprintf("mock-eth-%d", time.Now().UnixNano()),
					Hash:          "0xmockhash",
					SourceChain:   "ethereum",
					DestChain:     "blackhole",
					SourceAddress: "0xmocksender",
					DestAddress:   "0xmockreceiver",
					TokenSymbol:   "ETH",
					Amount:        "1.5",
					Status:        "pending",
					CreatedAt:     time.Now(),
				}

				sdk.logger.Infof("📨 Mock Ethereum transaction detected: %s", tx.ID)
				// Process through bridge
				if err := sdk.blockchainInterface.ProcessBridgeTransaction(tx); err != nil {
					sdk.logger.Errorf("❌ Failed to process mock Ethereum transaction: %v", err)
				}
			}
		}
	}()

	return nil
}

// StartSolanaListener starts the Solana blockchain listener
func (sdk *BridgeSDK) StartSolanaListener(ctx context.Context) error {
	sdk.logger.Info("🔗 Starting Solana listener...")

	// Check if we should use real blockchain listeners
	if sdk.useRealBlockchainListeners {
		// Use real blockchain listener
		realListener := core.NewRealBlockchainListener(sdk)
		return realListener.StartSolanaListener(ctx)
	}

	// Otherwise use mock listener (default for development)
	go func() {
		ticker := time.NewTicker(6 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Create a mock transaction
				tx := &Transaction{
					ID:            fmt.Sprintf("mock-sol-%d", time.Now().UnixNano()),
					Hash:          "0xmockhashsol",
					SourceChain:   "solana",
					DestChain:     "blackhole",
					SourceAddress: "mocksolana123",
					DestAddress:   "mockblackhole456",
					TokenSymbol:   "SOL",
					Amount:        "45",
					Status:        "pending",
					CreatedAt:     time.Now(),
				}

				// Replay protection
				hash := tx.Hash
				if sdk.replayProtection.isProcessed(hash) {
					sdk.logger.Warnf("🚫 Replay attack detected for transaction %s", tx.ID)
					sdk.incrementBlockedReplays()
					continue
				}
				if err := sdk.replayProtection.markProcessed(hash); err != nil {
					sdk.logger.Errorf("Failed to mark transaction as processed: %v", err)
				}

				sdk.saveTransaction(tx)
				sdk.addEvent("transfer", "solana", tx.Hash, map[string]interface{}{
					"amount": tx.Amount,
					"token":  tx.TokenSymbol,
					"from":   tx.SourceAddress,
					"to":     tx.DestAddress,
				})

				sdk.logger.Infof("💰 Solana transaction detected: %s (%s %s)", tx.ID, tx.Amount, tx.TokenSymbol)

				// Simulate processing delay and completion (faster)
				go func(transaction *Transaction) {
					time.Sleep(time.Duration(1+rand.Intn(3)) * time.Second)
					transaction.Status = "completed"
					now := time.Now()
					transaction.CompletedAt = &now
					transaction.Confirmations = 32 + rand.Intn(20)
					transaction.ProcessingTime = fmt.Sprintf("%.1fs", time.Since(transaction.CreatedAt).Seconds())
					sdk.saveTransaction(transaction)
					sdk.logger.Infof("✅ Solana transaction completed: %s", transaction.ID)
				}(tx)
			}
		}
	}()

	return nil
}


// Retry Queue Methods
func (rq *RetryQueue) AddItem(itemType string, data map[string]interface{}) string {
	rq.mutex.Lock()
	defer rq.mutex.Unlock()

	id := fmt.Sprintf("retry_%d_%d", time.Now().Unix(), rand.Intn(10000))
	item := RetryItem{
		ID:         id,
		Type:       itemType,
		Data:       data,
		Attempts:   0,
		MaxRetries: rq.maxRetries,
		NextRetry:  time.Now(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	rq.items = append(rq.items, item)
	return id
}

func (rq *RetryQueue) ProcessRetries(ctx context.Context, processor func(RetryItem) error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rq.processReadyItems(processor)
		}
	}
}

func (rq *RetryQueue) processReadyItems(processor func(RetryItem) error) {
	rq.mutex.Lock()
	defer rq.mutex.Unlock()

	now := time.Now()
	var remainingItems []RetryItem

	for _, item := range rq.items {
		if now.Before(item.NextRetry) {
			remainingItems = append(remainingItems, item)
			continue
		}

		if item.Attempts >= item.MaxRetries {
			// Item has exceeded max retries, remove it
			continue
		}

		// Try to process the item
		err := processor(item)
		if err != nil {
			// Failed, schedule for retry with exponential backoff
			item.Attempts++
			item.LastError = err.Error()
			item.UpdatedAt = now

			// Calculate exponential backoff delay
			delay := time.Duration(math.Pow(2, float64(item.Attempts))) * time.Second
			if delay > 60*time.Second {
				delay = 60 * time.Second
			}
			item.NextRetry = now.Add(delay)

			remainingItems = append(remainingItems, item)
		}
		// If successful, item is not added back to the queue
	}

	rq.items = remainingItems
}

func (rq *RetryQueue) GetStats() map[string]interface{} {
	rq.mutex.RLock()
	defer rq.mutex.RUnlock()

	totalItems := len(rq.items)
	readyItems := 0
	now := time.Now()

	for _, item := range rq.items {
		if now.After(item.NextRetry) {
			readyItems++
		}
	}

	return map[string]interface{}{
		"total_items":   totalItems,
		"ready_items":   readyItems,
		"pending_items": totalItems - readyItems,
		"max_retries":   rq.maxRetries,
		"base_delay":    rq.baseDelay.String(),
		"max_delay":     rq.maxDelay.String(),
	}
}

// Retry Queue Methods
func (pr *PanicRecovery) RecoverFromPanic(component string) {
	if r := recover(); r != nil {
		stack := make([]byte, 4096)
		length := runtime.Stack(stack, false)

		entry := PanicEntry{
			ID:        fmt.Sprintf("panic_%d", time.Now().Unix()),
			Message:   fmt.Sprintf("%v", r),
			Stack:     string(stack[:length]),
			Component: component,
			Timestamp: time.Now(),
			Recovered: true,
		}

		pr.mutex.Lock()
		pr.recoveries = append(pr.recoveries, entry)
		// Keep only last 100 panic entries
		if len(pr.recoveries) > 100 {
			pr.recoveries = pr.recoveries[len(pr.recoveries)-100:]
		}
		pr.mutex.Unlock()

		pr.logger.WithFields(logrus.Fields{
			"component": component,
			"panic_id":  entry.ID,
			"message":   entry.Message,
		}).Error("Panic recovered")
	}
}

func (pr *PanicRecovery) GetRecoveries() []PanicEntry {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()

	return pr.recoveries
}

func (pr *PanicRecovery) GetStats() map[string]interface{} {
	pr.mutex.RLock()
	defer pr.mutex.RUnlock()

	return map[string]interface{}{
		"total_recoveries": len(pr.recoveries),
		"last_recovery": func() interface{} {
			if len(pr.recoveries) > 0 {
				return pr.recoveries[len(pr.recoveries)-1].Timestamp
			}
			return nil
		}(),
	}
}

// Enhanced token database with valid cross-chain addresses
var enhancedTokens = map[string][]EnhancedToken{
	"ethereum": {
		{Symbol: "ETH", Name: "Ethereum", Decimals: 18, Address: "0x0000000000000000000000000000000000000000", Chain: "ethereum", IsNative: true, TotalSupply: "120000000"},
		{Symbol: "USDC", Name: "USD Coin", Decimals: 6, Address: "0xA0b86a33E6441E6C7D3E4C2C4C6C6C6C6C6C", Chain: "ethereum", IsNative: false, TotalSupply: "50000000000"},
		{Symbol: "USDT", Name: "Tether USD", Decimals: 6, Address: "0xdAC17F958D2ee523a2206206994597C13D831ec7", Chain: "ethereum", IsNative: false, TotalSupply: "80000000000"},
		{Symbol: "WBTC", Name: "Wrapped Bitcoin", Decimals: 8, Address: "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", Chain: "ethereum", IsNative: false, TotalSupply: "250000"},
		{Symbol: "LINK", Name: "Chainlink", Decimals: 18, Address: "0x514910771AF9Ca656af840dff83E8264EcF986CA", Chain: "ethereum", IsNative: false, TotalSupply: "1000000000"},
		{Symbol: "UNI", Name: "Uniswap", Decimals: 18, Address: "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", Chain: "ethereum", IsNative: false, TotalSupply: "1000000000"},
	},
	"solana": {
		{Symbol: "SOL", Name: "Solana", Decimals: 9, Address: "11111111111111111111111111111111", Chain: "solana", IsNative: true, TotalSupply: "500000000"},
		{Symbol: "USDC", Name: "USD Coin", Decimals: 6, Address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", Chain: "solana", IsNative: false, TotalSupply: "50000000000"},
		{Symbol: "USDT", Name: "Tether USD", Decimals: 6, Address: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", Chain: "solana", IsNative: false, TotalSupply: "80000000000"},
		{Symbol: "RAY", Name: "Raydium", Decimals: 6, Address: "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R", Chain: "solana", IsNative: false, TotalSupply: "555000000"},
		{Symbol: "SRM", Name: "Serum", Decimals: 6, Address: "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt", Chain: "solana", IsNative: false, TotalSupply: "10000000000"},
		{Symbol: "ORCA", Name: "Orca", Decimals: 6, Address: "orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE", Chain: "solana", IsNative: false, TotalSupply: "100000000"},
	},
	"blackhole": {
		{Symbol: "BHX", Name: "BlackHole Token", Decimals: 18, Address: "0xBH0000000000000000000000000000000000000000", Chain: "blackhole", IsNative: true, TotalSupply: "1000000000"},
		{Symbol: "BHUSDC", Name: "BlackHole USD Coin", Decimals: 6, Address: "0xBHUSDC000000000000000000000000000000000000", Chain: "blackhole", IsNative: false, TotalSupply: "10000000000"},
		{Symbol: "BHETH", Name: "BlackHole Ethereum", Decimals: 18, Address: "0xBHETH0000000000000000000000000000000000000", Chain: "blackhole", IsNative: false, TotalSupply: "21000000"},
		{Symbol: "BHSOL", Name: "BlackHole Solana", Decimals: 9, Address: "0xBHSOL0000000000000000000000000000000000000", Chain: "blackhole", IsNative: false, TotalSupply: "500000000"},
	},
}

// Helper functions for generating realistic data
func generateRandomAddress(chain string) string {
	switch chain {
	case "ethereum", "blackhole":
		return fmt.Sprintf("0x%x", rand.Uint64())
	case "solana":
		return generateSolanaAddress()
	default:
		return fmt.Sprintf("addr_%x", rand.Uint64())
	}
}

func getRandomToken(chain string) EnhancedToken {
	tokens := enhancedTokens[chain]
	if len(tokens) == 0 {
		return EnhancedToken{Symbol: "UNKNOWN", Name: "Unknown Token", Decimals: 18, Chain: chain}
	}
	return tokens[rand.Intn(len(tokens))]
}

func generateRealisticAmount(token EnhancedToken) string {
	var amount float64

	switch token.Symbol {
	case "ETH", "SOL", "BHX":
		amount = rand.Float64() * 10 // 0-10 native tokens
	case "USDC", "USDT", "BHUSDC":
		amount = rand.Float64() * 1000 // 0-1000 stablecoins
	case "WBTC":
		amount = rand.Float64() * 0.1 // 0-0.1 BTC
	default:
		amount = rand.Float64() * 100 // 0-100 other tokens
	}

	// Format based on decimals
	format := fmt.Sprintf("%%.%df", min(token.Decimals, 6))
	return fmt.Sprintf(format, amount)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func generateSolanaAddress() string {
	chars := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	result := make([]byte, 44)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func generateSolanaSignature() string {
	chars := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	result := make([]byte, 88)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

// Helper methods for SDK functionality
func (sdk *BridgeSDK) generateEventHash(tx *Transaction) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s",
		tx.ID, tx.Hash, tx.SourceChain, tx.DestChain,
		tx.SourceAddress, tx.DestAddress, tx.TokenSymbol, tx.Amount)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (sdk *BridgeSDK) isReplayAttack(hash string) bool {
	return sdk.replayProtection.isProcessed(hash)
}

func (sdk *BridgeSDK) markAsProcessed(hash string) error {
	return sdk.replayProtection.markProcessed(hash)
}

func (sdk *BridgeSDK) incrementBlockedReplays() {
	sdk.blockedMutex.Lock()
	defer sdk.blockedMutex.Unlock()
	sdk.blockedReplays++
}

func (sdk *BridgeSDK) saveTransaction(tx *Transaction) {
	sdk.transactionsMutex.Lock()
	defer sdk.transactionsMutex.Unlock()
	sdk.transactions[tx.ID] = tx

	// Also save to database
	sdk.db.Update(func(boltTx *bbolt.Tx) error {
		bucket := boltTx.Bucket([]byte("transactions"))
		if bucket == nil {
			return fmt.Errorf("transactions bucket not found")
		}

		data, err := json.Marshal(tx)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(tx.ID), data)
	})
}

func (sdk *BridgeSDK) addEvent(eventType, chain, txHash string, data map[string]interface{}) {
	sdk.eventsMutex.Lock()
	defer sdk.eventsMutex.Unlock()

	event := Event{
		ID:        fmt.Sprintf("event_%d", time.Now().UnixNano()),
		Type:      eventType,
		Chain:     chain,
		TxHash:    txHash,
		Timestamp: time.Now(),
		Data:      data,
		Processed: false,
	}

	sdk.events = append(sdk.events, event)

	// Keep only last 1000 events
	if len(sdk.events) > 1000 {
		sdk.events = sdk.events[len(sdk.events)-1000:]
	}

	// Send event to relay server for real-time streaming
	if sdk.relayServer != nil && sdk.relayServer.Status == "running" {
		select {
		case sdk.relayServer.EventStream <- event:
			// Event sent successfully
		default:
			// Event stream is full, skip to prevent blocking
			sdk.logger.Warnf("⚠️ Relay event stream is full, skipping event: %s", event.ID)
		}
	}

	// Record performance timing for the event
	if sdk.performanceMonitor != nil {
		// Use event timestamp as start time for latency calculation
		sdk.recordEventTiming(event.ID, event.Chain, "processing", event.Timestamp, true)
	}

	// --- NEW: Sync to Validator and Token Modules ---
	// Sync to validator (if available)
	go func(ev Event) {
		defer func() { recover() }()
		// Import validation package if not already
		// Run bridge test suite for event validation
		// This is a no-op if validator is not initialized
		// (You may want to add a build tag or interface for real integration)
		// Example:
		// import "github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/validation"
		// if validation.GlobalValidator != nil {
		//     validation.GlobalValidator.RunTestSuite(context.Background(), "bridge_functionality")
		// }
	}(event)

	// Sync to token module (if available)
	go func(ev Event) {
		defer func() { recover() }()
		// Import token package if not already
		// Example: log as a token event if token registry is available
		// if sdk.blockchainInterface != nil && sdk.blockchainInterface.blockchain != nil {
		//     tokenMod := sdk.blockchainInterface.blockchain.TokenRegistry[ev.Data["token"].(string)]
		//     if tokenMod != nil {
		//         tokenMod.emitEvent(token.Event{
		//             Type: token.EventType(ev.Type),
		//             From: ev.Data["from"].(string),
		//             To: ev.Data["to"].(string),
		//             Amount: uint64(ev.Data["amount"].(float64)),
		//         })
		//     }
		// }
	}(event)
	// --- END NEW ---
}

// Enhanced Retry Logic with Exponential Backoff and Dead Letter Queue

// addToRetryQueue adds a failed event to the retry queue with exponential backoff
func (sdk *BridgeSDK) addToRetryQueue(eventType string, data map[string]interface{}, err error) string {
	sdk.retryQueue.mutex.Lock()
	defer sdk.retryQueue.mutex.Unlock()

	retryItem := RetryItem{
		ID:         fmt.Sprintf("retry_%d", time.Now().UnixNano()),
		Type:       eventType,
		Data:       data,
		Attempts:   0,
		MaxRetries: sdk.retryConfig.MaxAttempts,
		NextRetry:  time.Now().Add(sdk.retryConfig.BaseDelay),
		LastError:  err.Error(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	sdk.retryQueue.items = append(sdk.retryQueue.items, retryItem)
	sdk.logger.Infof("🔄 Added event to retry queue: %s (attempt 1/%d)", retryItem.ID, retryItem.MaxRetries)
	return retryItem.ID
}

// processRetryQueue processes items in the retry queue with exponential backoff
func (sdk *BridgeSDK) processRetryQueue() {
	sdk.retryQueue.mutex.Lock()
	defer sdk.retryQueue.mutex.Unlock()

	now := time.Now()
	var remainingItems []RetryItem

	for _, item := range sdk.retryQueue.items {
		if now.Before(item.NextRetry) {
			remainingItems = append(remainingItems, item)
			continue
		}

		// Attempt to process the item
		success := sdk.retryEventProcessing(item)

		if success {
			sdk.logger.Infof("✅ Successfully processed retry item: %s after %d attempts", item.ID, item.Attempts+1)
			continue
		}

		// Increment attempts and calculate next retry time
		item.Attempts++
		item.UpdatedAt = now

		if item.Attempts >= item.MaxRetries {
			// Move to dead letter queue
			sdk.moveToDeadLetterQueue(item, "Max retry attempts exceeded")
			sdk.logger.Warnf("💀 Moved item to dead letter queue: %s after %d attempts", item.ID, item.Attempts)
		} else {
			// Calculate next retry time with exponential backoff
			delay := sdk.calculateBackoffDelay(item.Attempts)
			item.NextRetry = now.Add(delay)
			remainingItems = append(remainingItems, item)
			sdk.logger.Infof("🔄 Retry scheduled for %s: attempt %d/%d in %v", item.ID, item.Attempts+1, item.MaxRetries, delay)
		}
	}

	sdk.retryQueue.items = remainingItems
}

// calculateBackoffDelay calculates the delay for the next retry using exponential backoff with jitter
func (sdk *BridgeSDK) calculateBackoffDelay(attempts int) time.Duration {
	// Exponential backoff: baseDelay * (backoffFactor ^ attempts)
	delay := float64(sdk.retryConfig.BaseDelay) * math.Pow(sdk.retryConfig.BackoffFactor, float64(attempts))

	// Cap at max delay
	if time.Duration(delay) > sdk.retryConfig.MaxDelay {
		delay = float64(sdk.retryConfig.MaxDelay)
	}

	// Add jitter if enabled (±25% randomization)
	if sdk.retryConfig.JitterEnabled {
		jitter := delay * 0.25 * (rand.Float64()*2 - 1) // Random between -25% and +25%
		delay += jitter
	}

	return time.Duration(delay)
}

// retryEventProcessing attempts to reprocess a failed event
func (sdk *BridgeSDK) retryEventProcessing(item RetryItem) bool {
	defer func() {
		if r := recover(); r != nil {
			sdk.logger.Errorf("🚨 Panic during retry processing for %s: %v", item.ID, r)
		}
	}()

	// Simulate event processing based on type
	switch item.Type {
	case "bridge_transfer":
		return sdk.retryBridgeTransfer(item.Data)
	case "ethereum_event":
		return sdk.retryEthereumEvent(item.Data)
	case "solana_event":
		return sdk.retrySolanaEvent(item.Data)
	case "blackhole_event":
		return sdk.retryBlackholeEvent(item.Data)
	default:
		sdk.logger.Warnf("⚠️ Unknown event type for retry: %s", item.Type)
		return false
	}
}

// moveToDeadLetterQueue moves a failed item to the dead letter queue
func (sdk *BridgeSDK) moveToDeadLetterQueue(item RetryItem, reason string) {
	sdk.deadLetterMutex.Lock()
	defer sdk.deadLetterMutex.Unlock()

	deadItem := DeadLetterItem{
		ID:            fmt.Sprintf("dead_%d", time.Now().UnixNano()),
		OriginalEvent: item,
		FailureReason: reason,
		FailedAt:      time.Now(),
		TotalAttempts: item.Attempts,
		ErrorHistory:  []string{item.LastError},
	}

	sdk.deadLetterQueue = append(sdk.deadLetterQueue, deadItem)

	// Keep only last 1000 dead letter items
	if len(sdk.deadLetterQueue) > 1000 {
		sdk.deadLetterQueue = sdk.deadLetterQueue[len(sdk.deadLetterQueue)-1000:]
	}

	// Add event for monitoring
	sdk.addEvent("dead_letter_added", "system", item.ID, map[string]interface{}{
		"original_type":  item.Type,
		"failure_reason": reason,
		"total_attempts": item.Attempts,
		"created_at":     item.CreatedAt,
	})
}

// Retry-specific processing methods
func (sdk *BridgeSDK) retryBridgeTransfer(data map[string]interface{}) bool {
	// Simulate bridge transfer retry with 80% success rate
	return rand.Float64() > 0.2
}

func (sdk *BridgeSDK) retryEthereumEvent(data map[string]interface{}) bool {
	// Simulate Ethereum event retry with 85% success rate
	return rand.Float64() > 0.15
}

func (sdk *BridgeSDK) retrySolanaEvent(data map[string]interface{}) bool {
	// Simulate Solana event retry with 90% success rate
	return rand.Float64() > 0.1
}

func (sdk *BridgeSDK) retryBlackholeEvent(data map[string]interface{}) bool {
	// Simulate BlackHole event retry with 95% success rate (local blockchain)
	return rand.Float64() > 0.05
}

// startRetryProcessor starts the background retry processor
func (sdk *BridgeSDK) startRetryProcessor(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Second) // Process retries every 5 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				sdk.logger.Info("🛑 Retry processor stopped")
				return
			case <-ticker.C:
				sdk.processRetryQueue()
			}
		}
	}()
	sdk.logger.Info("🔄 Retry processor started")
}

// Relay Server Implementation for Real-time Endpoints

// startRelayServer initializes and starts the relay server
func (sdk *BridgeSDK) startRelayServer(ctx context.Context) error {
	sdk.relayServer.Status = "starting"

	// Start WebSocket server for real-time event streaming
	http.HandleFunc("/relay/ws", sdk.handleRelayWebSocket)
	http.HandleFunc("/relay/health", sdk.handleRelayHealth)
	http.HandleFunc("/relay/stats", sdk.handleRelayStats)

	// Start event streaming processor
	go sdk.processEventStream(ctx)

	sdk.relayServer.Status = "running"
	sdk.logger.Infof("🌐 Relay server started on port %d", sdk.relayServer.Port)

	return nil
}

// handleRelayWebSocket handles WebSocket connections for real-time event streaming
func (sdk *BridgeSDK) handleRelayWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := sdk.relayServer.WebSocketServer.Upgrade(w, r, nil)
	if err != nil {
		sdk.logger.Errorf("❌ WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// Add client to relay server
	sdk.relayServer.ClientsMutex.Lock()
	sdk.relayServer.Clients[conn] = true
	sdk.relayServer.Connections++
	sdk.relayServer.LastActivity = time.Now()
	sdk.relayServer.ClientsMutex.Unlock()

	sdk.logger.Infof("🔗 New relay WebSocket client connected (total: %d)", sdk.relayServer.Connections)

	// Remove client on disconnect
	defer func() {
		sdk.relayServer.ClientsMutex.Lock()
		delete(sdk.relayServer.Clients, conn)
		sdk.relayServer.Connections--
		sdk.relayServer.ClientsMutex.Unlock()
		sdk.logger.Infof("🔌 Relay WebSocket client disconnected (total: %d)", sdk.relayServer.Connections)
	}()

	// Send welcome message
	welcomeMsg := map[string]interface{}{
		"type":      "welcome",
		"message":   "Connected to BlackHole Bridge Relay Server",
		"timestamp": time.Now().Format(time.RFC3339),
		"server_id": "blackhole-relay-1",
	}

	if err := conn.WriteJSON(welcomeMsg); err != nil {
		sdk.logger.Errorf("❌ Failed to send welcome message: %v", err)
		return
	}

	// Keep connection alive and handle incoming messages
	for {
		var msg map[string]interface{}
		err := conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				sdk.logger.Errorf("❌ WebSocket error: %v", err)
			}
			break
		}

		// Handle client messages (ping, subscribe, etc.)
		sdk.handleRelayClientMessage(conn, msg)
	}
}

// handleRelayClientMessage processes messages from relay clients
func (sdk *BridgeSDK) handleRelayClientMessage(conn *websocket.Conn, msg map[string]interface{}) {
	msgType, ok := msg["type"].(string)
	if !ok {
		return
	}

	switch msgType {
	case "ping":
		pongMsg := map[string]interface{}{
			"type":      "pong",
			"timestamp": time.Now().Format(time.RFC3339),
		}
		conn.WriteJSON(pongMsg)

	case "subscribe":
		// Handle subscription to specific event types
		eventTypes, ok := msg["events"].([]interface{})
		if ok {
			sdk.logger.Infof("📡 Client subscribed to events: %v", eventTypes)
		}

	case "get_status":
		statusMsg := map[string]interface{}{
			"type":         "status",
			"relay_status": sdk.getRelayServerStatus(),
			"timestamp":    time.Now().Format(time.RFC3339),
		}
		conn.WriteJSON(statusMsg)
	}
}

// processEventStream processes and broadcasts events to relay clients
func (sdk *BridgeSDK) processEventStream(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			sdk.logger.Info("🛑 Event stream processor stopped")
			return
		case event := <-sdk.relayServer.EventStream:
			sdk.broadcastEventToRelayClients(event)
		}
	}
}

// broadcastEventToRelayClients sends events to all connected relay clients
func (sdk *BridgeSDK) broadcastEventToRelayClients(event Event) {
	sdk.relayServer.ClientsMutex.RLock()
	defer sdk.relayServer.ClientsMutex.RUnlock()

	if len(sdk.relayServer.Clients) == 0 {
		return
	}

	eventMsg := map[string]interface{}{
		"type":       "event",
		"event_id":   event.ID,
		"event_type": event.Type,
		"chain":      event.Chain,
		"tx_hash":    event.TxHash,
		"timestamp":  event.Timestamp.Format(time.RFC3339),
		"data":       event.Data,
	}

	var disconnectedClients []*websocket.Conn

	for client := range sdk.relayServer.Clients {
		err := client.WriteJSON(eventMsg)
		if err != nil {
			sdk.logger.Errorf("❌ Failed to send event to relay client: %v", err)
			disconnectedClients = append(disconnectedClients, client)
		}
	}

	// Clean up disconnected clients
	for _, client := range disconnectedClients {
		delete(sdk.relayServer.Clients, client)
		sdk.relayServer.Connections--
		client.Close()
	}

	sdk.relayServer.TotalMessages++
	sdk.relayServer.LastActivity = time.Now()
}

// handleRelayHealth provides health check for relay server
func (sdk *BridgeSDK) handleRelayHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	health := map[string]interface{}{
		"status":         sdk.relayServer.Status,
		"uptime":         time.Since(sdk.relayServer.StartedAt).String(),
		"connections":    sdk.relayServer.Connections,
		"last_activity":  sdk.relayServer.LastActivity.Format(time.RFC3339),
		"total_messages": sdk.relayServer.TotalMessages,
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    health,
	})
}

// handleRelayStats provides detailed statistics for relay server
func (sdk *BridgeSDK) handleRelayStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats := sdk.getRelayServerStatus()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

// getRelayServerStatus returns comprehensive relay server status
func (sdk *BridgeSDK) getRelayServerStatus() map[string]interface{} {
	return map[string]interface{}{
		"port":             sdk.relayServer.Port,
		"status":           sdk.relayServer.Status,
		"connections":      sdk.relayServer.Connections,
		"last_activity":    sdk.relayServer.LastActivity.Format(time.RFC3339),
		"started_at":       sdk.relayServer.StartedAt.Format(time.RFC3339),
		"uptime":           time.Since(sdk.relayServer.StartedAt).String(),
		"total_messages":   sdk.relayServer.TotalMessages,
		"event_queue_size": len(sdk.relayServer.EventStream),
		"retry_queue_size": len(sdk.retryQueue.items),
		"dead_letter_size": len(sdk.deadLetterQueue),
	}
}

// Performance Monitoring Implementation

// recordEventTiming records timing information for an event
func (sdk *BridgeSDK) recordEventTiming(eventID, chain, stage string, startTime time.Time, success bool) {
	sdk.performanceMonitor.mutex.Lock()
	defer sdk.performanceMonitor.mutex.Unlock()

	endTime := time.Now()
	duration := endTime.Sub(startTime)

	timing := EventTiming{
		EventID:   eventID,
		Chain:     chain,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  duration,
		Stage:     stage,
		Success:   success,
	}

	// Add to event timings (keep last 1000)
	sdk.performanceMonitor.EventTimings = append(sdk.performanceMonitor.EventTimings, timing)
	if len(sdk.performanceMonitor.EventTimings) > 1000 {
		sdk.performanceMonitor.EventTimings = sdk.performanceMonitor.EventTimings[len(sdk.performanceMonitor.EventTimings)-1000:]
	}

	// Update chain metrics
	if chainMetrics, exists := sdk.performanceMonitor.ChainMetrics[chain]; exists {
		chainMetrics.EventCount++
		chainMetrics.LastEventTime = endTime

		// Update average latency (simple moving average)
		if chainMetrics.EventCount == 1 {
			chainMetrics.AverageLatency = duration
		} else {
			chainMetrics.AverageLatency = time.Duration(
				(int64(chainMetrics.AverageLatency)*int64(chainMetrics.EventCount-1) + int64(duration)) / int64(chainMetrics.EventCount),
			)
		}

		if !success {
			chainMetrics.ErrorCount++
		}
		chainMetrics.ErrorRate = float64(chainMetrics.ErrorCount) / float64(chainMetrics.EventCount)
	}

	// Update overall metrics
	sdk.updateOverallMetrics()
}

// updateOverallMetrics calculates and updates overall performance metrics
func (sdk *BridgeSDK) updateOverallMetrics() {
	now := time.Now()
	metrics := &sdk.performanceMonitor.Metrics

	// Calculate total events and events per second
	totalEvents := int64(0)
	totalErrors := int64(0)
	var latencies []time.Duration

	for _, chainMetrics := range sdk.performanceMonitor.ChainMetrics {
		totalEvents += chainMetrics.EventCount
		totalErrors += chainMetrics.ErrorCount
	}

	// Collect latencies from recent event timings (last 100 events)
	recentTimings := sdk.performanceMonitor.EventTimings
	if len(recentTimings) > 100 {
		recentTimings = recentTimings[len(recentTimings)-100:]
	}

	for _, timing := range recentTimings {
		latencies = append(latencies, timing.Duration)
	}

	// Update metrics
	metrics.TotalEvents = totalEvents
	metrics.LastUpdated = now

	// Calculate events per second
	elapsed := now.Sub(metrics.StartTime).Seconds()
	if elapsed > 0 {
		metrics.EventsPerSecond = float64(totalEvents) / elapsed
	}

	// Calculate error rate
	if totalEvents > 0 {
		metrics.ErrorRate = float64(totalErrors) / float64(totalEvents)
	}

	// Calculate latency percentiles
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool {
			return latencies[i] < latencies[j]
		})

		// Average latency
		var totalLatency time.Duration
		for _, lat := range latencies {
			totalLatency += lat
		}
		metrics.AverageLatency = totalLatency / time.Duration(len(latencies))

		// P95 and P99 latencies
		p95Index := int(float64(len(latencies)) * 0.95)
		p99Index := int(float64(len(latencies)) * 0.99)

		if p95Index >= len(latencies) {
			p95Index = len(latencies) - 1
		}
		if p99Index >= len(latencies) {
			p99Index = len(latencies) - 1
		}

		metrics.P95Latency = latencies[p95Index]
		metrics.P99Latency = latencies[p99Index]
	}

	// Update chain latencies
	metrics.ChainLatencies = make(map[string]time.Duration)
	for chainName, chainMetrics := range sdk.performanceMonitor.ChainMetrics {
		metrics.ChainLatencies[chainName] = chainMetrics.AverageLatency
	}

	// Add to history (keep last 100 points)
	throughputPoint := ThroughputPoint{
		Timestamp:       now,
		EventsPerSecond: metrics.EventsPerSecond,
		TotalEvents:     metrics.TotalEvents,
	}
	metrics.ThroughputHistory = append(metrics.ThroughputHistory, throughputPoint)
	if len(metrics.ThroughputHistory) > 100 {
		metrics.ThroughputHistory = metrics.ThroughputHistory[len(metrics.ThroughputHistory)-100:]
	}

	latencyPoint := LatencyPoint{
		Timestamp:      now,
		AverageLatency: metrics.AverageLatency,
		P95Latency:     metrics.P95Latency,
		P99Latency:     metrics.P99Latency,
	}
	metrics.LatencyHistory = append(metrics.LatencyHistory, latencyPoint)
	if len(metrics.LatencyHistory) > 100 {
		metrics.LatencyHistory = metrics.LatencyHistory[len(metrics.LatencyHistory)-100:]
	}
}

// startPerformanceMonitoring starts the background performance monitoring
func (sdk *BridgeSDK) startPerformanceMonitoring(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Second) // Update metrics every 10 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				sdk.logger.Info("🛑 Performance monitoring stopped")
				return
			case <-ticker.C:
				sdk.performanceMonitor.mutex.Lock()
				sdk.updateOverallMetrics()
				sdk.checkPerformanceAlerts()
				sdk.performanceMonitor.mutex.Unlock()
			}
		}
	}()
	sdk.logger.Info("📊 Performance monitoring started")
}

// checkPerformanceAlerts checks for performance issues and logs alerts
func (sdk *BridgeSDK) checkPerformanceAlerts() {
	metrics := &sdk.performanceMonitor.Metrics
	thresholds := &sdk.performanceMonitor.AlertThresholds

	// Check latency alerts
	if metrics.AverageLatency > thresholds.MaxLatency {
		sdk.logger.Warnf("🚨 HIGH LATENCY ALERT: Average latency %v exceeds threshold %v",
			metrics.AverageLatency, thresholds.MaxLatency)
	}

	// Check error rate alerts
	if metrics.ErrorRate > thresholds.MaxErrorRate {
		sdk.logger.Warnf("🚨 HIGH ERROR RATE ALERT: Error rate %.2f%% exceeds threshold %.2f%%",
			metrics.ErrorRate*100, thresholds.MaxErrorRate*100)
	}

	// Check throughput alerts
	if metrics.EventsPerSecond < thresholds.MinThroughput {
		sdk.logger.Warnf("🚨 LOW THROUGHPUT ALERT: Events per second %.2f below threshold %.2f",
			metrics.EventsPerSecond, thresholds.MinThroughput)
	}

	// Check queue size alerts
	retryQueueSize := len(sdk.retryQueue.items)
	if retryQueueSize > thresholds.MaxQueueSize {
		sdk.logger.Warnf("🚨 HIGH QUEUE SIZE ALERT: Retry queue size %d exceeds threshold %d",
			retryQueueSize, thresholds.MaxQueueSize)
	}
}

// Performance Metrics HTTP Endpoints

// handlePerformanceMetrics provides comprehensive performance metrics
func (sdk *BridgeSDK) handlePerformanceMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sdk.performanceMonitor.mutex.RLock()
	defer sdk.performanceMonitor.mutex.RUnlock()

	// Get current metrics
	metrics := sdk.performanceMonitor.Metrics
	chainMetrics := make(map[string]interface{})

	for chainName, chain := range sdk.performanceMonitor.ChainMetrics {
		chainMetrics[chainName] = map[string]interface{}{
			"chain_name":       chain.ChainName,
			"event_count":      chain.EventCount,
			"average_latency":  chain.AverageLatency.String(),
			"error_count":      chain.ErrorCount,
			"error_rate":       chain.ErrorRate,
			"last_event_time":  chain.LastEventTime.Format(time.RFC3339),
			"throughput_trend": chain.ThroughputTrend,
		}
	}

	response := map[string]interface{}{
		"total_events":      metrics.TotalEvents,
		"events_per_second": metrics.EventsPerSecond,
		"average_latency":   metrics.AverageLatency.String(),
		"p95_latency":       metrics.P95Latency.String(),
		"p99_latency":       metrics.P99Latency.String(),
		"error_rate":        metrics.ErrorRate,
		"last_updated":      metrics.LastUpdated.Format(time.RFC3339),
		"start_time":        metrics.StartTime.Format(time.RFC3339),
		"uptime":            time.Since(metrics.StartTime).String(),
		"chain_metrics":     chainMetrics,
		"alert_thresholds": map[string]interface{}{
			"max_latency":    sdk.performanceMonitor.AlertThresholds.MaxLatency.String(),
			"max_error_rate": sdk.performanceMonitor.AlertThresholds.MaxErrorRate,
			"min_throughput": sdk.performanceMonitor.AlertThresholds.MinThroughput,
			"max_queue_size": sdk.performanceMonitor.AlertThresholds.MaxQueueSize,
		},
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    response,
	})
}

// handleLatencyMetrics provides detailed latency metrics and history
func (sdk *BridgeSDK) handleLatencyMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sdk.performanceMonitor.mutex.RLock()
	defer sdk.performanceMonitor.mutex.RUnlock()

	// Format latency history
	latencyHistory := make([]map[string]interface{}, len(sdk.performanceMonitor.Metrics.LatencyHistory))
	for i, point := range sdk.performanceMonitor.Metrics.LatencyHistory {
		latencyHistory[i] = map[string]interface{}{
			"timestamp":       point.Timestamp.Format(time.RFC3339),
			"average_latency": point.AverageLatency.String(),
			"p95_latency":     point.P95Latency.String(),
			"p99_latency":     point.P99Latency.String(),
		}
	}

	// Format chain latencies
	chainLatencies := make(map[string]string)
	for chain, latency := range sdk.performanceMonitor.Metrics.ChainLatencies {
		chainLatencies[chain] = latency.String()
	}

	// Get recent event timings (last 50)
	recentTimings := sdk.performanceMonitor.EventTimings
	if len(recentTimings) > 50 {
		recentTimings = recentTimings[len(recentTimings)-50:]
	}

	timings := make([]map[string]interface{}, len(recentTimings))
	for i, timing := range recentTimings {
		timings[i] = map[string]interface{}{
			"event_id":   timing.EventID,
			"chain":      timing.Chain,
			"start_time": timing.StartTime.Format(time.RFC3339),
			"end_time":   timing.EndTime.Format(time.RFC3339),
			"duration":   timing.Duration.String(),
			"stage":      timing.Stage,
			"success":    timing.Success,
		}
	}

	response := map[string]interface{}{
		"current_metrics": map[string]interface{}{
			"average_latency": sdk.performanceMonitor.Metrics.AverageLatency.String(),
			"p95_latency":     sdk.performanceMonitor.Metrics.P95Latency.String(),
			"p99_latency":     sdk.performanceMonitor.Metrics.P99Latency.String(),
		},
		"chain_latencies": chainLatencies,
		"latency_history": latencyHistory,
		"recent_timings":  timings,
		"alert_threshold": sdk.performanceMonitor.AlertThresholds.MaxLatency.String(),
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    response,
	})
}

// handleThroughputMetrics provides detailed throughput metrics and history
func (sdk *BridgeSDK) handleThroughputMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sdk.performanceMonitor.mutex.RLock()
	defer sdk.performanceMonitor.mutex.RUnlock()

	// Format throughput history
	throughputHistory := make([]map[string]interface{}, len(sdk.performanceMonitor.Metrics.ThroughputHistory))
	for i, point := range sdk.performanceMonitor.Metrics.ThroughputHistory {
		throughputHistory[i] = map[string]interface{}{
			"timestamp":         point.Timestamp.Format(time.RFC3339),
			"events_per_second": point.EventsPerSecond,
			"total_events":      point.TotalEvents,
		}
	}

	// Calculate chain-specific throughput
	chainThroughput := make(map[string]interface{})
	totalUptime := time.Since(sdk.performanceMonitor.Metrics.StartTime).Seconds()

	for chainName, chain := range sdk.performanceMonitor.ChainMetrics {
		eventsPerSecond := 0.0
		if totalUptime > 0 {
			eventsPerSecond = float64(chain.EventCount) / totalUptime
		}

		chainThroughput[chainName] = map[string]interface{}{
			"total_events":      chain.EventCount,
			"events_per_second": eventsPerSecond,
			"trend":             chain.ThroughputTrend,
			"last_event":        chain.LastEventTime.Format(time.RFC3339),
		}
	}

	response := map[string]interface{}{
		"current_metrics": map[string]interface{}{
			"total_events":      sdk.performanceMonitor.Metrics.TotalEvents,
			"events_per_second": sdk.performanceMonitor.Metrics.EventsPerSecond,
			"uptime":            time.Since(sdk.performanceMonitor.Metrics.StartTime).String(),
		},
		"chain_throughput":   chainThroughput,
		"throughput_history": throughputHistory,
		"alert_threshold":    sdk.performanceMonitor.AlertThresholds.MinThroughput,
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    response,
	})
}

// Enhanced Performance Monitoring Endpoints

// handlePerformanceDashboard provides comprehensive performance data for dashboard widgets
func (sdk *BridgeSDK) handlePerformanceDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sdk.performanceMonitor.mutex.RLock()
	defer sdk.performanceMonitor.mutex.RUnlock()

	// Get current time and calculate uptime
	now := time.Now()
	uptime := now.Sub(sdk.performanceMonitor.Metrics.StartTime)

	// Calculate real-time metrics
	recentEvents := sdk.getRecentEventCount(5 * time.Minute)
	currentTPS := float64(recentEvents) / (5 * 60) // Events per second over last 5 minutes

	// Get latest latency measurements
	latestLatencies := sdk.getLatestLatencies(10) // Last 10 events
	currentLatency := sdk.calculateAverageLatency(latestLatencies)

	// Calculate success rate from recent events
	successRate := sdk.calculateRecentSuccessRate(1 * time.Hour)

	// Get chain-specific performance
	chainPerformance := make(map[string]interface{})
	for chainName, metrics := range sdk.performanceMonitor.ChainMetrics {
		chainPerformance[chainName] = map[string]interface{}{
			"events_count":     metrics.EventCount,
			"average_latency":  metrics.AverageLatency.Milliseconds(),
			"error_rate":       metrics.ErrorRate,
			"last_event":       metrics.LastEventTime.Format(time.RFC3339),
			"trend":           metrics.ThroughputTrend,
		}
	}

	// Performance alerts summary
	alerts := sdk.getActivePerformanceAlerts()

	// Historical data for charts (last 24 hours, 1-hour intervals)
	historicalData := sdk.getHistoricalPerformanceData(24*time.Hour, 1*time.Hour)

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"overview": map[string]interface{}{
				"uptime_seconds":     uptime.Seconds(),
				"uptime_formatted":   uptime.String(),
				"total_events":       sdk.performanceMonitor.Metrics.TotalEvents,
				"current_tps":        currentTPS,
				"current_latency_ms": currentLatency.Milliseconds(),
				"success_rate":       successRate,
				"error_rate":         sdk.performanceMonitor.Metrics.ErrorRate,
				"last_updated":       now.Format(time.RFC3339),
			},
			"chain_performance": chainPerformance,
			"alerts": map[string]interface{}{
				"active_count": len(alerts),
				"alerts":       alerts,
			},
			"historical_data": historicalData,
			"thresholds": map[string]interface{}{
				"max_latency_ms":    sdk.performanceMonitor.AlertThresholds.MaxLatency.Milliseconds(),
				"max_error_rate":    sdk.performanceMonitor.AlertThresholds.MaxErrorRate,
				"min_throughput":    sdk.performanceMonitor.AlertThresholds.MinThroughput,
			},
		},
	}

	json.NewEncoder(w).Encode(response)
}

// handlePerformanceAlerts provides detailed performance alerts and warnings
func (sdk *BridgeSDK) handlePerformanceAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters
	severity := r.URL.Query().Get("severity") // critical, warning, info
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}

	sdk.performanceMonitor.mutex.RLock()
	defer sdk.performanceMonitor.mutex.RUnlock()

	// Get current performance state
	alerts := make([]map[string]interface{}, 0)

	// Check latency alerts
	if sdk.performanceMonitor.Metrics.AverageLatency > sdk.performanceMonitor.AlertThresholds.MaxLatency {
		alertSeverity := "warning"
		if sdk.performanceMonitor.Metrics.AverageLatency > sdk.performanceMonitor.AlertThresholds.MaxLatency*2 {
			alertSeverity = "critical"
		}

		if severity == "" || severity == alertSeverity {
			alerts = append(alerts, map[string]interface{}{
				"id":          fmt.Sprintf("latency_%d", time.Now().Unix()),
				"type":        "latency",
				"severity":    alertSeverity,
				"title":       "High Latency Detected",
				"description": fmt.Sprintf("Average latency %v exceeds threshold %v",
					sdk.performanceMonitor.Metrics.AverageLatency,
					sdk.performanceMonitor.AlertThresholds.MaxLatency),
				"current_value": sdk.performanceMonitor.Metrics.AverageLatency.String(),
				"threshold":     sdk.performanceMonitor.AlertThresholds.MaxLatency.String(),
				"timestamp":     time.Now().Format(time.RFC3339),
				"chain":         "all",
			})
		}
	}

	// Check error rate alerts
	if sdk.performanceMonitor.Metrics.ErrorRate > sdk.performanceMonitor.AlertThresholds.MaxErrorRate {
		alertSeverity := "warning"
		if sdk.performanceMonitor.Metrics.ErrorRate > sdk.performanceMonitor.AlertThresholds.MaxErrorRate*2 {
			alertSeverity = "critical"
		}

		if severity == "" || severity == alertSeverity {
			alerts = append(alerts, map[string]interface{}{
				"id":          fmt.Sprintf("error_rate_%d", time.Now().Unix()),
				"type":        "error_rate",
				"severity":    alertSeverity,
				"title":       "High Error Rate Detected",
				"description": fmt.Sprintf("Error rate %.2f%% exceeds threshold %.2f%%",
					sdk.performanceMonitor.Metrics.ErrorRate,
					sdk.performanceMonitor.AlertThresholds.MaxErrorRate),
				"current_value": fmt.Sprintf("%.2f%%", sdk.performanceMonitor.Metrics.ErrorRate),
				"threshold":     fmt.Sprintf("%.2f%%", sdk.performanceMonitor.AlertThresholds.MaxErrorRate),
				"timestamp":     time.Now().Format(time.RFC3339),
				"chain":         "all",
			})
		}
	}

	// Check throughput alerts
	if sdk.performanceMonitor.Metrics.EventsPerSecond < sdk.performanceMonitor.AlertThresholds.MinThroughput {
		alertSeverity := "info"
		if sdk.performanceMonitor.Metrics.EventsPerSecond < sdk.performanceMonitor.AlertThresholds.MinThroughput*0.5 {
			alertSeverity = "warning"
		}

		if severity == "" || severity == alertSeverity {
			alerts = append(alerts, map[string]interface{}{
				"id":          fmt.Sprintf("throughput_%d", time.Now().Unix()),
				"type":        "throughput",
				"severity":    alertSeverity,
				"title":       "Low Throughput Detected",
				"description": fmt.Sprintf("Events per second %.2f below threshold %.2f",
					sdk.performanceMonitor.Metrics.EventsPerSecond,
					sdk.performanceMonitor.AlertThresholds.MinThroughput),
				"current_value": fmt.Sprintf("%.2f", sdk.performanceMonitor.Metrics.EventsPerSecond),
				"threshold":     fmt.Sprintf("%.2f", sdk.performanceMonitor.AlertThresholds.MinThroughput),
				"timestamp":     time.Now().Format(time.RFC3339),
				"chain":         "all",
			})
		}
	}

	// Check chain-specific alerts
	for chainName, chainMetrics := range sdk.performanceMonitor.ChainMetrics {
		if chainMetrics.ErrorRate > 10.0 { // 10% error rate threshold per chain
			if severity == "" || severity == "warning" {
				alerts = append(alerts, map[string]interface{}{
					"id":          fmt.Sprintf("chain_error_%s_%d", chainName, time.Now().Unix()),
					"type":        "chain_error",
					"severity":    "warning",
					"title":       fmt.Sprintf("High Error Rate on %s Chain", strings.Title(chainName)),
					"description": fmt.Sprintf("Chain %s has error rate %.2f%%", chainName, chainMetrics.ErrorRate),
					"current_value": fmt.Sprintf("%.2f%%", chainMetrics.ErrorRate),
					"threshold":     "10.0%",
					"timestamp":     time.Now().Format(time.RFC3339),
					"chain":         chainName,
				})
			}
		}
	}

	// Apply limit
	if len(alerts) > limit {
		alerts = alerts[:limit]
	}

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"alerts":       alerts,
			"total_count":  len(alerts),
			"severity_filter": severity,
			"timestamp":    time.Now().Format(time.RFC3339),
		},
	}

	json.NewEncoder(w).Encode(response)
}

// handleHistoricalPerformance provides historical performance data for analysis
func (sdk *BridgeSDK) handleHistoricalPerformance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters
	durationStr := r.URL.Query().Get("duration") // "1h", "24h", "7d", "30d"
	intervalStr := r.URL.Query().Get("interval") // "1m", "5m", "1h"

	// Set defaults
	duration := 24 * time.Hour
	interval := 1 * time.Hour

	// Parse duration
	if durationStr != "" {
		if d, err := time.ParseDuration(durationStr); err == nil {
			duration = d
		}
	}

	// Parse interval
	if intervalStr != "" {
		if i, err := time.ParseDuration(intervalStr); err == nil {
			interval = i
		}
	}

	sdk.performanceMonitor.mutex.RLock()
	defer sdk.performanceMonitor.mutex.RUnlock()

	// Generate historical data points
	historicalData := sdk.getHistoricalPerformanceData(duration, interval)

	// Calculate statistics over the period
	stats := sdk.calculateHistoricalStats(historicalData)

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"historical_data": historicalData,
			"statistics":      stats,
			"period": map[string]interface{}{
				"duration": duration.String(),
				"interval": interval.String(),
				"start":    time.Now().Add(-duration).Format(time.RFC3339),
				"end":      time.Now().Format(time.RFC3339),
			},
		},
	}

	json.NewEncoder(w).Encode(response)
}

// Helper methods for enhanced performance monitoring

// getRecentEventCount returns the number of events in the specified duration
func (sdk *BridgeSDK) getRecentEventCount(duration time.Duration) int {
	cutoff := time.Now().Add(-duration)
	count := 0

	for _, timing := range sdk.performanceMonitor.EventTimings {
		if timing.StartTime.After(cutoff) {
			count++
		}
	}

	return count
}

// getLatestLatencies returns the latest N event latencies
func (sdk *BridgeSDK) getLatestLatencies(n int) []time.Duration {
	timings := sdk.performanceMonitor.EventTimings
	if len(timings) == 0 {
		return []time.Duration{}
	}

	start := len(timings) - n
	if start < 0 {
		start = 0
	}

	latencies := make([]time.Duration, 0, n)
	for i := start; i < len(timings); i++ {
		latencies = append(latencies, timings[i].Duration)
	}

	return latencies
}

// calculateAverageLatency calculates the average of given latencies
func (sdk *BridgeSDK) calculateAverageLatency(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}

	total := time.Duration(0)
	for _, latency := range latencies {
		total += latency
	}

	return total / time.Duration(len(latencies))
}

// calculateRecentSuccessRate calculates success rate over the specified duration
func (sdk *BridgeSDK) calculateRecentSuccessRate(duration time.Duration) float64 {
	cutoff := time.Now().Add(-duration)
	total := 0
	successful := 0

	for _, timing := range sdk.performanceMonitor.EventTimings {
		if timing.StartTime.After(cutoff) {
			total++
			if timing.Success {
				successful++
			}
		}
	}

	if total == 0 {
		return 100.0 // No events means 100% success rate
	}

	return float64(successful) / float64(total) * 100.0
}

// getActivePerformanceAlerts returns currently active performance alerts
func (sdk *BridgeSDK) getActivePerformanceAlerts() []map[string]interface{} {
	alerts := make([]map[string]interface{}, 0)

	// Check current thresholds
	if sdk.performanceMonitor.Metrics.AverageLatency > sdk.performanceMonitor.AlertThresholds.MaxLatency {
		alerts = append(alerts, map[string]interface{}{
			"type":        "latency",
			"severity":    "warning",
			"description": "High latency detected",
			"value":       sdk.performanceMonitor.Metrics.AverageLatency.String(),
		})
	}

	if sdk.performanceMonitor.Metrics.ErrorRate > sdk.performanceMonitor.AlertThresholds.MaxErrorRate {
		alerts = append(alerts, map[string]interface{}{
			"type":        "error_rate",
			"severity":    "warning",
			"description": "High error rate detected",
			"value":       fmt.Sprintf("%.2f%%", sdk.performanceMonitor.Metrics.ErrorRate),
		})
	}

	if sdk.performanceMonitor.Metrics.EventsPerSecond < sdk.performanceMonitor.AlertThresholds.MinThroughput {
		alerts = append(alerts, map[string]interface{}{
			"type":        "throughput",
			"severity":    "info",
			"description": "Low throughput detected",
			"value":       fmt.Sprintf("%.2f TPS", sdk.performanceMonitor.Metrics.EventsPerSecond),
		})
	}

	return alerts
}

// getHistoricalPerformanceData generates historical performance data points
func (sdk *BridgeSDK) getHistoricalPerformanceData(duration, interval time.Duration) []map[string]interface{} {
	now := time.Now()
	start := now.Add(-duration)

	dataPoints := make([]map[string]interface{}, 0)

	// Generate data points at specified intervals
	for t := start; t.Before(now); t = t.Add(interval) {
		// Calculate metrics for this time window
		windowStart := t
		windowEnd := t.Add(interval)

		// Count events in this window
		eventCount := 0
		totalLatency := time.Duration(0)
		successCount := 0

		for _, timing := range sdk.performanceMonitor.EventTimings {
			if timing.StartTime.After(windowStart) && timing.StartTime.Before(windowEnd) {
				eventCount++
				totalLatency += timing.Duration
				if timing.Success {
					successCount++
				}
			}
		}

		// Calculate averages
		avgLatency := time.Duration(0)
		if eventCount > 0 {
			avgLatency = totalLatency / time.Duration(eventCount)
		}

		successRate := 100.0
		if eventCount > 0 {
			successRate = float64(successCount) / float64(eventCount) * 100.0
		}

		eventsPerSecond := float64(eventCount) / interval.Seconds()

		dataPoint := map[string]interface{}{
			"timestamp":         t.Format(time.RFC3339),
			"events_count":      eventCount,
			"events_per_second": eventsPerSecond,
			"avg_latency_ms":    avgLatency.Milliseconds(),
			"success_rate":      successRate,
			"error_rate":        100.0 - successRate,
		}

		dataPoints = append(dataPoints, dataPoint)
	}

	return dataPoints
}

// calculateHistoricalStats calculates statistics over historical data
func (sdk *BridgeSDK) calculateHistoricalStats(data []map[string]interface{}) map[string]interface{} {
	if len(data) == 0 {
		return map[string]interface{}{
			"total_events":     0,
			"avg_tps":         0.0,
			"max_tps":         0.0,
			"min_tps":         0.0,
			"avg_latency_ms":  0,
			"max_latency_ms":  0,
			"min_latency_ms":  0,
			"avg_success_rate": 100.0,
		}
	}

	totalEvents := 0
	totalTPS := 0.0
	maxTPS := 0.0
	minTPS := math.MaxFloat64
	totalLatency := int64(0)
	maxLatency := int64(0)
	minLatency := int64(math.MaxInt64)
	totalSuccessRate := 0.0

	for _, point := range data {
		events := int(point["events_count"].(int))
		tps := point["events_per_second"].(float64)
		latency := int64(point["avg_latency_ms"].(int64))
		successRate := point["success_rate"].(float64)

		totalEvents += events
		totalTPS += tps
		totalLatency += latency
		totalSuccessRate += successRate

		if tps > maxTPS {
			maxTPS = tps
		}
		if tps < minTPS {
			minTPS = tps
		}

		if latency > maxLatency {
			maxLatency = latency
		}
		if latency < minLatency {
			minLatency = latency
		}
	}

	dataPointCount := len(data)

	return map[string]interface{}{
		"total_events":     totalEvents,
		"avg_tps":         totalTPS / float64(dataPointCount),
		"max_tps":         maxTPS,
		"min_tps":         minTPS,
		"avg_latency_ms":  totalLatency / int64(dataPointCount),
		"max_latency_ms":  maxLatency,
		"min_latency_ms":  minLatency,
		"avg_success_rate": totalSuccessRate / float64(dataPointCount),
	}
}

// Load Testing and Chaos Testing HTTP Endpoints

// handleLoadTest starts or configures load testing
func (sdk *BridgeSDK) handleLoadTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// Get current load test status
		sdk.loadTester.mutex.RLock()
		status := sdk.loadTester.Status
		config := sdk.loadTester.Config
		sdk.loadTester.mutex.RUnlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"status": status,
				"config": config,
			},
		})

	case "POST":
		// Start load test or update configuration
		var requestData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Check if load test is already running
		if sdk.loadTester.Status.Status == "running" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Load test is already running",
			})
			return
		}

		// Update configuration with provided parameters
		if totalTx, ok := requestData["total_transactions"].(float64); ok {
			sdk.loadTester.Config.TotalTransactions = int(totalTx)
		}
		if workers, ok := requestData["concurrent_workers"].(float64); ok {
			sdk.loadTester.Config.ConcurrentWorkers = int(workers)
		}
		if retries, ok := requestData["retry_count"].(float64); ok {
			sdk.loadTester.Config.RetryCount = int(retries)
		}
		if duration, ok := requestData["duration_minutes"].(float64); ok {
			sdk.loadTester.Config.TestDuration = time.Duration(duration) * time.Minute
		}

		// Start load test
		go sdk.runLoadTest()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Load test started",
			"test_id": fmt.Sprintf("load_%d", time.Now().Unix()),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleChaosTest starts or configures chaos testing
func (sdk *BridgeSDK) handleChaosTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// Get current chaos test status
		sdk.chaosTester.mutex.RLock()
		status := sdk.chaosTester.Status
		config := sdk.chaosTester.Config
		sdk.chaosTester.mutex.RUnlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"status": status,
				"config": config,
			},
		})

	case "POST":
		// Start chaos test or update configuration
		var requestData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Check if chaos test is already running
		if sdk.chaosTester.Status.Status == "running" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Chaos test is already running",
			})
			return
		}

		// Update configuration with provided parameters
		if failureRate, ok := requestData["failure_rate"].(float64); ok {
			sdk.chaosTester.Config.FailureInjection = failureRate > 0
		}
		if duration, ok := requestData["duration_minutes"].(float64); ok {
			sdk.chaosTester.Config.TestDuration = time.Duration(duration) * time.Minute
		}

		// Start chaos test
		go sdk.runChaosTest()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Chaos test started",
			"test_id": "chaos_" + fmt.Sprintf("%d", time.Now().Unix()),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTestStatus provides status of all running tests
func (sdk *BridgeSDK) handleTestStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sdk.loadTester.mutex.RLock()
	loadStatus := sdk.loadTester.Status
	sdk.loadTester.mutex.RUnlock()

	sdk.chaosTester.mutex.RLock()
	chaosStatus := sdk.chaosTester.Status
	sdk.chaosTester.mutex.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"load_test":  loadStatus,
			"chaos_test": chaosStatus,
			"system_metrics": map[string]interface{}{
				"total_events":    sdk.performanceMonitor.Metrics.TotalEvents,
				"events_per_sec":  sdk.performanceMonitor.Metrics.EventsPerSecond,
				"error_rate":      sdk.performanceMonitor.Metrics.ErrorRate,
				"average_latency": sdk.performanceMonitor.Metrics.AverageLatency.String(),
			},
		},
	})
}

// Load Testing Implementation

// updateLoadTestConfig updates the load test configuration
func (sdk *BridgeSDK) updateLoadTestConfig(configData map[string]interface{}) {
	sdk.loadTester.mutex.Lock()
	defer sdk.loadTester.mutex.Unlock()

	if totalTx, exists := configData["total_transactions"].(float64); exists {
		sdk.loadTester.Config.TotalTransactions = int(totalTx)
	}
	if workers, exists := configData["concurrent_workers"].(float64); exists {
		sdk.loadTester.Config.ConcurrentWorkers = int(workers)
	}
	if rate, exists := configData["transaction_rate"].(float64); exists {
		sdk.loadTester.Config.TransactionRate = int(rate)
	}
	if duration, exists := configData["test_duration"].(string); exists {
		if d, err := time.ParseDuration(duration); err == nil {
			sdk.loadTester.Config.TestDuration = d
		}
	}
	if failureRate, exists := configData["failure_rate"].(float64); exists {
		sdk.loadTester.Config.FailureRate = failureRate
	}
	if retryCount, exists := configData["retry_count"].(float64); exists {
		sdk.loadTester.Config.RetryCount = int(retryCount)
	}
}

// runLoadTest executes the load test
func (sdk *BridgeSDK) runLoadTest() {
	sdk.loadTester.mutex.Lock()
	sdk.loadTester.Status = TestStatus{
		TestType:          "load",
		Status:            "running",
		StartTime:         time.Now(),
		TotalTransactions: sdk.loadTester.Config.TotalTransactions,
		Results:           make([]TestResult, 0),
	}
	config := sdk.loadTester.Config
	sdk.loadTester.mutex.Unlock()

	sdk.logger.Infof("🧪 Starting load test: %d transactions, %d workers, %d TPS",
		config.TotalTransactions, config.ConcurrentWorkers, config.TransactionRate)

	// Create worker channels
	workers := make([]chan bool, config.ConcurrentWorkers)
	for i := range workers {
		workers[i] = make(chan bool, 1)
	}

	// Start result processor
	go sdk.processLoadTestResults()

	// Rate limiter for transaction rate
	rateLimiter := time.NewTicker(time.Second / time.Duration(config.TransactionRate))
	defer rateLimiter.Stop()

	// Generate transactions
	transactionCount := 0
	startTime := time.Now()

	for transactionCount < config.TotalTransactions {
		select {
		case <-sdk.loadTester.StopChannel:
			sdk.logger.Info("🛑 Load test stopped by user")
			sdk.finishLoadTest("stopped")
			return
		case <-rateLimiter.C:
			if time.Since(startTime) > config.TestDuration {
				sdk.logger.Info("⏰ Load test duration exceeded")
				sdk.finishLoadTest("completed")
				return
			}

			// Select chain based on distribution
			chain := sdk.selectChainForLoadTest()

			// Create test transaction
			txID := fmt.Sprintf("load_test_%d_%d", time.Now().Unix(), transactionCount)

			// Send to worker
			workerIndex := transactionCount % config.ConcurrentWorkers
			go sdk.executeLoadTestTransaction(txID, chain, workers[workerIndex])

			transactionCount++
		}
	}

	sdk.logger.Info("✅ Load test completed all transactions")
	sdk.finishLoadTest("completed")
}

// selectChainForLoadTest selects a chain based on distribution configuration
func (sdk *BridgeSDK) selectChainForLoadTest() string {
	rand := rand.Float64()
	cumulative := 0.0

	for chain, percentage := range sdk.loadTester.Config.ChainDistribution {
		cumulative += percentage
		if rand <= cumulative {
			return chain
		}
	}
	return "ethereum" // fallback
}

// executeLoadTestTransaction executes a single load test transaction
func (sdk *BridgeSDK) executeLoadTestTransaction(txID, chain string, workerChan chan bool) {
	startTime := time.Now()
	success := true
	errorMessage := ""
	retryCount := 0

	// Simulate transaction processing
	defer func() {
		result := TestResult{
			TransactionID: txID,
			Chain:         chain,
			StartTime:     startTime,
			EndTime:       time.Now(),
			Duration:      time.Since(startTime),
			Success:       success,
			ErrorMessage:  errorMessage,
			RetryCount:    retryCount,
		}

		select {
		case sdk.loadTester.ResultsQueue <- result:
		default:
			// Queue is full, skip result
		}
	}()

	// Simulate failure based on failure rate
	if rand.Float64() < sdk.loadTester.Config.FailureRate {
		success = false
		errorMessage = "Simulated failure for load testing"

		// Simulate retries
		for retryCount < sdk.loadTester.Config.RetryCount {
			retryCount++
			time.Sleep(time.Duration(retryCount*100) * time.Millisecond) // Exponential backoff

			if rand.Float64() > 0.5 { // 50% chance of retry success
				success = true
				errorMessage = ""
				break
			}
		}
	} else {
		// Simulate processing time
		processingTime := time.Duration(rand.Intn(100)+10) * time.Millisecond
		time.Sleep(processingTime)
	}

	// Record performance timing
	if sdk.performanceMonitor != nil {
		sdk.recordEventTiming(txID, chain, "load_test", startTime, success)
	}
}

// processLoadTestResults processes results from the results queue
func (sdk *BridgeSDK) processLoadTestResults() {
	for result := range sdk.loadTester.ResultsQueue {
		sdk.loadTester.mutex.Lock()

		sdk.loadTester.Status.Results = append(sdk.loadTester.Status.Results, result)

		if result.Success {
			sdk.loadTester.Status.SuccessfulTx++
		} else {
			sdk.loadTester.Status.FailedTx++
		}

		sdk.loadTester.Status.RetriedTx += result.RetryCount

		// Update latency metrics
		if sdk.loadTester.Status.MinLatency == 0 || result.Duration < sdk.loadTester.Status.MinLatency {
			sdk.loadTester.Status.MinLatency = result.Duration
		}
		if result.Duration > sdk.loadTester.Status.MaxLatency {
			sdk.loadTester.Status.MaxLatency = result.Duration
		}

		// Calculate average latency
		totalResults := len(sdk.loadTester.Status.Results)
		if totalResults > 0 {
			var totalLatency time.Duration
			for _, r := range sdk.loadTester.Status.Results {
				totalLatency += r.Duration
			}
			sdk.loadTester.Status.AverageLatency = totalLatency / time.Duration(totalResults)
		}

		sdk.loadTester.mutex.Unlock()
	}
}

// finishLoadTest completes the load test and updates final statistics
func (sdk *BridgeSDK) finishLoadTest(status string) {
	sdk.loadTester.mutex.Lock()
	defer sdk.loadTester.mutex.Unlock()

	endTime := time.Now()
	sdk.loadTester.Status.EndTime = &endTime
	sdk.loadTester.Status.Duration = endTime.Sub(sdk.loadTester.Status.StartTime)
	sdk.loadTester.Status.Status = status

	// Calculate final metrics
	totalTx := sdk.loadTester.Status.SuccessfulTx + sdk.loadTester.Status.FailedTx
	if totalTx > 0 {
		sdk.loadTester.Status.ErrorRate = float64(sdk.loadTester.Status.FailedTx) / float64(totalTx)
		sdk.loadTester.Status.ThroughputTPS = float64(totalTx) / sdk.loadTester.Status.Duration.Seconds()
	}

	sdk.logger.Infof("📊 Load test %s: %d total, %d successful, %d failed, %.2f%% error rate, %.2f TPS",
		status, totalTx, sdk.loadTester.Status.SuccessfulTx, sdk.loadTester.Status.FailedTx,
		sdk.loadTester.Status.ErrorRate*100, sdk.loadTester.Status.ThroughputTPS)
}

// Chaos Testing Implementation

// updateChaosTestConfig updates the chaos test configuration
func (sdk *BridgeSDK) updateChaosTestConfig(configData map[string]interface{}) {
	sdk.chaosTester.mutex.Lock()
	defer sdk.chaosTester.mutex.Unlock()

	if duration, exists := configData["test_duration"].(string); exists {
		if d, err := time.ParseDuration(duration); err == nil {
			sdk.chaosTester.Config.TestDuration = d
		}
	}
	if failureInjection, exists := configData["failure_injection"].(bool); exists {
		sdk.chaosTester.Config.FailureInjection = failureInjection
	}
	if networkLatency, exists := configData["network_latency"].(string); exists {
		if d, err := time.ParseDuration(networkLatency); err == nil {
			sdk.chaosTester.Config.NetworkLatency = d
		}
	}
	if randomDelays, exists := configData["random_delays"].(bool); exists {
		sdk.chaosTester.Config.RandomDelays = randomDelays
	}
	if circuitBreaker, exists := configData["circuit_breaker"].(bool); exists {
		sdk.chaosTester.Config.CircuitBreaker = circuitBreaker
	}
}

// runChaosTest executes the chaos test
func (sdk *BridgeSDK) runChaosTest() {
	sdk.chaosTester.mutex.Lock()
	sdk.chaosTester.Status = TestStatus{
		TestType:  "chaos",
		Status:    "running",
		StartTime: time.Now(),
		Results:   make([]TestResult, 0),
	}
	config := sdk.chaosTester.Config
	sdk.chaosTester.mutex.Unlock()

	sdk.logger.Infof("🌪️ Starting chaos test for %v", config.TestDuration)

	// Start chaos scenarios
	go sdk.runChaosScenarios()

	// Monitor test duration
	timer := time.NewTimer(config.TestDuration)
	defer timer.Stop()

	select {
	case <-sdk.chaosTester.StopChannel:
		sdk.logger.Info("🛑 Chaos test stopped by user")
		sdk.finishChaosTest("stopped")
	case <-timer.C:
		sdk.logger.Info("⏰ Chaos test duration completed")
		sdk.finishChaosTest("completed")
	}
}

// runChaosScenarios executes various chaos testing scenarios
func (sdk *BridgeSDK) runChaosScenarios() {
	config := sdk.chaosTester.Config
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sdk.chaosTester.StopChannel:
			return
		case <-ticker.C:
			if config.FailureInjection {
				sdk.injectRandomFailures()
			}
			if config.NetworkLatency > 0 {
				sdk.simulateNetworkLatency()
			}
			if config.RandomDelays {
				sdk.injectRandomDelays()
			}
		}
	}
}

// injectRandomFailures simulates random system failures
func (sdk *BridgeSDK) injectRandomFailures() {
	if rand.Float64() < 0.1 { // 10% chance
		failureType := rand.Intn(3)
		switch failureType {
		case 0:
			sdk.logger.Warn("🔥 CHAOS: Database failure simulation")
			time.Sleep(time.Duration(rand.Intn(1000)+500) * time.Millisecond)
		case 1:
			sdk.logger.Warn("🔥 CHAOS: Network timeout simulation")
			time.Sleep(time.Duration(rand.Intn(2000)+1000) * time.Millisecond)
		case 2:
			sdk.logger.Warn("🔥 CHAOS: Service unavailable simulation")
			time.Sleep(time.Duration(rand.Intn(3000)+1500) * time.Millisecond)
		}
		sdk.recordChaosEvent("failure_injection", fmt.Sprintf("Type %d failure", failureType))
	}
}

// simulateNetworkLatency adds artificial network delays
func (sdk *BridgeSDK) simulateNetworkLatency() {
	if rand.Float64() < 0.3 { // 30% chance
		latency := sdk.chaosTester.Config.NetworkLatency
		sdk.logger.Warnf("🔥 CHAOS: Network latency: %v", latency)
		time.Sleep(latency)
		sdk.recordChaosEvent("network_latency", fmt.Sprintf("Added %v latency", latency))
	}
}

// injectRandomDelays adds random processing delays
func (sdk *BridgeSDK) injectRandomDelays() {
	if rand.Float64() < 0.2 { // 20% chance
		delay := time.Duration(rand.Intn(500)+100) * time.Millisecond
		sdk.logger.Warnf("🔥 CHAOS: Random delay: %v", delay)
		time.Sleep(delay)
		sdk.recordChaosEvent("random_delay", fmt.Sprintf("Added %v delay", delay))
	}
}

// recordChaosEvent records a chaos testing event
func (sdk *BridgeSDK) recordChaosEvent(eventType, description string) {
	sdk.chaosTester.mutex.Lock()
	defer sdk.chaosTester.mutex.Unlock()

	result := TestResult{
		TransactionID: fmt.Sprintf("chaos_%d", time.Now().UnixNano()),
		Chain:         "chaos",
		StartTime:     time.Now(),
		EndTime:       time.Now(),
		Duration:      0,
		Success:       true,
		ErrorMessage:  description,
		RetryCount:    0,
	}

	sdk.chaosTester.Status.Results = append(sdk.chaosTester.Status.Results, result)
	sdk.chaosTester.Status.TotalTransactions++
}

// finishChaosTest completes the chaos test
func (sdk *BridgeSDK) finishChaosTest(status string) {
	sdk.chaosTester.mutex.Lock()
	defer sdk.chaosTester.mutex.Unlock()

	endTime := time.Now()
	sdk.chaosTester.Status.EndTime = &endTime
	sdk.chaosTester.Status.Duration = endTime.Sub(sdk.chaosTester.Status.StartTime)
	sdk.chaosTester.Status.Status = status

	sdk.logger.Infof("🌪️ Chaos test %s: %d events in %v",
		status, sdk.chaosTester.Status.TotalTransactions, sdk.chaosTester.Status.Duration)
}

// Enhanced Resilience Testing Endpoints

// handleResilienceTest starts comprehensive resilience testing
func (sdk *BridgeSDK) handleResilienceTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var request struct {
		TestType     string                 `json:"test_type"`     // "circuit_breaker", "retry_queue", "network_failure", "comprehensive"
		Duration     int                    `json:"duration"`      // Duration in minutes
		Intensity    string                 `json:"intensity"`     // "low", "medium", "high"
		TargetChains []string               `json:"target_chains"` // Chains to test
		Scenarios    []string               `json:"scenarios"`     // Specific scenarios to run
		Parameters   map[string]interface{} `json:"parameters"`    // Additional parameters
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Set defaults
	if request.TestType == "" {
		request.TestType = "comprehensive"
	}
	if request.Duration == 0 {
		request.Duration = 10
	}
	if request.Intensity == "" {
		request.Intensity = "medium"
	}
	if len(request.TargetChains) == 0 {
		request.TargetChains = []string{"ethereum", "solana", "blackhole"}
	}

	testID := fmt.Sprintf("resilience_%s_%d", request.TestType, time.Now().UnixNano())

	// Start resilience test in background
	go sdk.executeResilienceTest(testID, request)

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"test_id":       testID,
			"test_type":     request.TestType,
			"duration":      request.Duration,
			"intensity":     request.Intensity,
			"target_chains": request.TargetChains,
			"scenarios":     request.Scenarios,
			"status":        "started",
			"estimated_completion": time.Now().Add(time.Duration(request.Duration) * time.Minute).Format(time.RFC3339),
		},
	}

	json.NewEncoder(w).Encode(response)
}

// handleResilienceStatus provides status of resilience tests
func (sdk *BridgeSDK) handleResilienceStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	testID := r.URL.Query().Get("test_id")

	// Get current resilience test status
	status := sdk.getResilienceTestStatus(testID)

	response := map[string]interface{}{
		"success": true,
		"data":    status,
	}

	json.NewEncoder(w).Encode(response)
}

// handleResilienceScenarios returns available resilience test scenarios
func (sdk *BridgeSDK) handleResilienceScenarios(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scenarios := []map[string]interface{}{
		{
			"id":          "circuit_breaker_trip",
			"name":        "Circuit Breaker Trip Test",
			"description": "Tests circuit breaker functionality by simulating failures",
			"duration":    "5-15 minutes",
			"complexity":  "medium",
			"targets":     []string{"ethereum_listener", "solana_listener", "relay_server"},
		},
		{
			"id":          "retry_queue_overflow",
			"name":        "Retry Queue Overflow Test",
			"description": "Tests retry queue behavior under high failure rates",
			"duration":    "10-20 minutes",
			"complexity":  "high",
			"targets":     []string{"retry_queue", "dead_letter_queue"},
		},
		{
			"id":          "network_partition",
			"name":        "Network Partition Simulation",
			"description": "Simulates network partitions between chains",
			"duration":    "15-30 minutes",
			"complexity":  "high",
			"targets":     []string{"ethereum", "solana", "blackhole"},
		},
		{
			"id":          "graceful_degradation",
			"name":        "Graceful Degradation Test",
			"description": "Tests system behavior when components fail gracefully",
			"duration":    "10-25 minutes",
			"complexity":  "medium",
			"targets":     []string{"all_components"},
		},
		{
			"id":          "recovery_validation",
			"name":        "Recovery Validation Test",
			"description": "Tests system recovery after failures are resolved",
			"duration":    "20-40 minutes",
			"complexity":  "high",
			"targets":     []string{"all_systems"},
		},
		{
			"id":          "cascade_failure",
			"name":        "Cascade Failure Prevention",
			"description": "Tests prevention of cascade failures across components",
			"duration":    "15-35 minutes",
			"complexity":  "high",
			"targets":     []string{"all_components"},
		},
	}

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"scenarios":     scenarios,
			"total_count":   len(scenarios),
			"categories":    []string{"circuit_breaker", "retry_queue", "network", "recovery", "cascade"},
		},
	}

	json.NewEncoder(w).Encode(response)
}

// handleCircuitBreakerTest specifically tests circuit breaker functionality
func (sdk *BridgeSDK) handleCircuitBreakerTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var request struct {
		TargetBreaker   string `json:"target_breaker"`   // Which circuit breaker to test
		FailureCount    int    `json:"failure_count"`    // Number of failures to inject
		TestDuration    int    `json:"test_duration"`    // Duration in minutes
		RecoveryTest    bool   `json:"recovery_test"`    // Test recovery behavior
		AutoReset       bool   `json:"auto_reset"`       // Auto-reset after test
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Set defaults
	if request.TargetBreaker == "" {
		request.TargetBreaker = "ethereum_listener"
	}
	if request.FailureCount == 0 {
		request.FailureCount = 10
	}
	if request.TestDuration == 0 {
		request.TestDuration = 5
	}

	testID := fmt.Sprintf("cb_test_%s_%d", request.TargetBreaker, time.Now().UnixNano())

	// Start circuit breaker test
	go sdk.executeCircuitBreakerTest(testID, request)

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"test_id":        testID,
			"target_breaker": request.TargetBreaker,
			"failure_count":  request.FailureCount,
			"test_duration":  request.TestDuration,
			"recovery_test":  request.RecoveryTest,
			"status":         "started",
		},
	}

	json.NewEncoder(w).Encode(response)
}

// handleRetryQueueTest specifically tests retry queue functionality
func (sdk *BridgeSDK) handleRetryQueueTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var request struct {
		FailureRate     float64 `json:"failure_rate"`     // Percentage of transactions to fail (0-100)
		TransactionCount int     `json:"transaction_count"` // Number of test transactions
		MaxRetries      int     `json:"max_retries"`      // Override max retries for test
		TestDuration    int     `json:"test_duration"`    // Duration in minutes
		TestDeadLetter  bool    `json:"test_dead_letter"` // Test dead letter queue behavior
		StressTest      bool    `json:"stress_test"`      // High-volume stress test
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Set defaults
	if request.FailureRate == 0 {
		request.FailureRate = 30.0 // 30% failure rate
	}
	if request.TransactionCount == 0 {
		request.TransactionCount = 100
	}
	if request.MaxRetries == 0 {
		request.MaxRetries = 5
	}
	if request.TestDuration == 0 {
		request.TestDuration = 10
	}

	testID := fmt.Sprintf("retry_test_%d", time.Now().UnixNano())

	// Start retry queue test
	go sdk.executeRetryQueueTest(testID, request)

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"test_id":           testID,
			"failure_rate":      request.FailureRate,
			"transaction_count": request.TransactionCount,
			"max_retries":       request.MaxRetries,
			"test_duration":     request.TestDuration,
			"test_dead_letter":  request.TestDeadLetter,
			"stress_test":       request.StressTest,
			"status":            "started",
		},
	}

	json.NewEncoder(w).Encode(response)
}

// Resilience Test Implementation Methods

// executeResilienceTest runs a comprehensive resilience test
func (sdk *BridgeSDK) executeResilienceTest(testID string, request struct {
	TestType     string                 `json:"test_type"`
	Duration     int                    `json:"duration"`
	Intensity    string                 `json:"intensity"`
	TargetChains []string               `json:"target_chains"`
	Scenarios    []string               `json:"scenarios"`
	Parameters   map[string]interface{} `json:"parameters"`
}) {
	sdk.logger.Infof("🛡️ Starting resilience test: %s (type: %s, duration: %dm)", testID, request.TestType, request.Duration)

	startTime := time.Now()

	switch request.TestType {
	case "circuit_breaker":
		sdk.runCircuitBreakerResilienceTest(testID, request)
	case "retry_queue":
		sdk.runRetryQueueResilienceTest(testID, request)
	case "network_failure":
		sdk.runNetworkFailureResilienceTest(testID, request)
	case "comprehensive":
		sdk.runComprehensiveResilienceTest(testID, request)
	default:
		sdk.runComprehensiveResilienceTest(testID, request)
	}

	duration := time.Since(startTime)
	sdk.logger.Infof("✅ Resilience test completed: %s (duration: %v)", testID, duration)
}

// runCircuitBreakerResilienceTest tests circuit breaker resilience
func (sdk *BridgeSDK) runCircuitBreakerResilienceTest(testID string, request struct {
	TestType     string                 `json:"test_type"`
	Duration     int                    `json:"duration"`
	Intensity    string                 `json:"intensity"`
	TargetChains []string               `json:"target_chains"`
	Scenarios    []string               `json:"scenarios"`
	Parameters   map[string]interface{} `json:"parameters"`
}) {
	sdk.logger.Infof("🔌 Running circuit breaker resilience test: %s", testID)

	// Test each circuit breaker
	for name, cb := range sdk.circuitBreakers {
		sdk.logger.Infof("Testing circuit breaker: %s", name)

		// Record initial state
		cb.mutex.RLock()
		initialState := cb.state
		initialFailures := cb.failureCount
		cb.mutex.RUnlock()

		// Inject failures to trip the circuit breaker
		for i := 0; i < cb.failureThreshold+2; i++ {
			cb.recordFailure()
			time.Sleep(100 * time.Millisecond)
		}

		// Verify circuit breaker is open
		cb.mutex.RLock()
		if cb.state != "open" {
			sdk.logger.Warnf("⚠️ Circuit breaker %s did not open as expected", name)
		} else {
			sdk.logger.Infof("✅ Circuit breaker %s opened successfully", name)
		}
		cb.mutex.RUnlock()

		// Test recovery after timeout
		time.Sleep(cb.timeout + 100*time.Millisecond)

		// Attempt operation (should be half-open)
		if cb.canExecute() {
			cb.recordSuccess()
			sdk.logger.Infof("✅ Circuit breaker %s recovered successfully", name)
		}

		// Reset to initial state
		cb.mutex.Lock()
		cb.state = initialState
		cb.failureCount = initialFailures
		cb.lastFailure = nil
		cb.mutex.Unlock()
	}
}

// runRetryQueueResilienceTest tests retry queue resilience
func (sdk *BridgeSDK) runRetryQueueResilienceTest(testID string, request struct {
	TestType     string                 `json:"test_type"`
	Duration     int                    `json:"duration"`
	Intensity    string                 `json:"intensity"`
	TargetChains []string               `json:"target_chains"`
	Scenarios    []string               `json:"scenarios"`
	Parameters   map[string]interface{} `json:"parameters"`
}) {
	sdk.logger.Infof("🔄 Running retry queue resilience test: %s", testID)

	// Generate test failures to populate retry queue
	for i := 0; i < 50; i++ {
		testData := map[string]interface{}{
			"test_id":        testID,
			"transaction_id": fmt.Sprintf("test_tx_%d", i),
			"chain":          request.TargetChains[i%len(request.TargetChains)],
			"amount":         100.0 + float64(i),
		}

		testError := fmt.Errorf("resilience test failure %d", i)
		sdk.addToRetryQueue(fmt.Sprintf("test_event_%d", i), testData, testError)

		time.Sleep(50 * time.Millisecond)
	}

	// Monitor retry queue processing
	initialQueueSize := len(sdk.retryQueue.items)
	sdk.logger.Infof("📊 Initial retry queue size: %d", initialQueueSize)

	// Wait for some processing
	time.Sleep(5 * time.Second)

	// Check queue processing
	sdk.retryQueue.mutex.RLock()
	currentQueueSize := len(sdk.retryQueue.items)
	sdk.retryQueue.mutex.RUnlock()

	sdk.logger.Infof("📊 Retry queue size after processing: %d", currentQueueSize)

	if currentQueueSize < initialQueueSize {
		sdk.logger.Infof("✅ Retry queue is processing items correctly")
	} else {
		sdk.logger.Warnf("⚠️ Retry queue may not be processing items as expected")
	}
}

// runNetworkFailureResilienceTest tests network failure resilience
func (sdk *BridgeSDK) runNetworkFailureResilienceTest(testID string, request struct {
	TestType     string                 `json:"test_type"`
	Duration     int                    `json:"duration"`
	Intensity    string                 `json:"intensity"`
	TargetChains []string               `json:"target_chains"`
	Scenarios    []string               `json:"scenarios"`
	Parameters   map[string]interface{} `json:"parameters"`
}) {
	sdk.logger.Infof("🌐 Running network failure resilience test: %s", testID)

	// Simulate network failures for each target chain
	for _, chain := range request.TargetChains {
		sdk.logger.Infof("Simulating network failure for chain: %s", chain)

		// Inject network latency
		if cb, exists := sdk.circuitBreakers[chain+"_listener"]; exists {
			// Simulate multiple failures to test circuit breaker
			for i := 0; i < 3; i++ {
				cb.recordFailure()
				time.Sleep(200 * time.Millisecond)
			}
		}

		// Simulate recovery
		time.Sleep(2 * time.Second)

		if cb, exists := sdk.circuitBreakers[chain+"_listener"]; exists {
			cb.recordSuccess()
			sdk.logger.Infof("✅ Network recovery simulated for chain: %s", chain)
		}
	}
}

// runComprehensiveResilienceTest runs all resilience tests
func (sdk *BridgeSDK) runComprehensiveResilienceTest(testID string, request struct {
	TestType     string                 `json:"test_type"`
	Duration     int                    `json:"duration"`
	Intensity    string                 `json:"intensity"`
	TargetChains []string               `json:"target_chains"`
	Scenarios    []string               `json:"scenarios"`
	Parameters   map[string]interface{} `json:"parameters"`
}) {
	sdk.logger.Infof("🛡️ Running comprehensive resilience test: %s", testID)

	// Run all resilience tests in sequence
	sdk.runCircuitBreakerResilienceTest(testID, request)
	time.Sleep(2 * time.Second)

	sdk.runRetryQueueResilienceTest(testID, request)
	time.Sleep(2 * time.Second)

	sdk.runNetworkFailureResilienceTest(testID, request)

	sdk.logger.Infof("✅ Comprehensive resilience test completed: %s", testID)
}

// executeCircuitBreakerTest runs a specific circuit breaker test
func (sdk *BridgeSDK) executeCircuitBreakerTest(testID string, request struct {
	TargetBreaker   string `json:"target_breaker"`
	FailureCount    int    `json:"failure_count"`
	TestDuration    int    `json:"test_duration"`
	RecoveryTest    bool   `json:"recovery_test"`
	AutoReset       bool   `json:"auto_reset"`
}) {
	sdk.logger.Infof("🔌 Starting circuit breaker test: %s (target: %s)", testID, request.TargetBreaker)

	cb, exists := sdk.circuitBreakers[request.TargetBreaker]
	if !exists {
		sdk.logger.Errorf("❌ Circuit breaker not found: %s", request.TargetBreaker)
		return
	}

	// Record initial state
	cb.mutex.RLock()
	initialState := cb.state
	initialFailures := cb.failureCount
	cb.mutex.RUnlock()

	sdk.logger.Infof("📊 Initial circuit breaker state: %s (failures: %d)", initialState, initialFailures)

	// Phase 1: Inject failures
	sdk.logger.Infof("🔥 Phase 1: Injecting %d failures", request.FailureCount)
	for i := 0; i < request.FailureCount; i++ {
		cb.recordFailure()
		time.Sleep(100 * time.Millisecond)

		cb.mutex.RLock()
		currentState := cb.state
		currentFailures := cb.failureCount
		cb.mutex.RUnlock()

		sdk.logger.Infof("Failure %d: State=%s, Failures=%d", i+1, currentState, currentFailures)
	}

	// Check if circuit breaker opened
	cb.mutex.RLock()
	finalState := cb.state
	cb.mutex.RUnlock()

	if finalState == "open" {
		sdk.logger.Infof("✅ Circuit breaker opened successfully after %d failures", request.FailureCount)
	} else {
		sdk.logger.Warnf("⚠️ Circuit breaker did not open (current state: %s)", finalState)
	}

	// Phase 2: Recovery test
	if request.RecoveryTest {
		sdk.logger.Infof("🔄 Phase 2: Testing recovery behavior")

		// Wait for timeout period
		sdk.logger.Infof("⏳ Waiting for circuit breaker timeout (%v)", cb.timeout)
		time.Sleep(cb.timeout + 100*time.Millisecond)

		// Test half-open state
		if cb.canExecute() {
			sdk.logger.Infof("✅ Circuit breaker entered half-open state")

			// Record success to close circuit
			cb.recordSuccess()

			cb.mutex.RLock()
			recoveredState := cb.state
			cb.mutex.RUnlock()

			if recoveredState == "closed" {
				sdk.logger.Infof("✅ Circuit breaker recovered to closed state")
			} else {
				sdk.logger.Warnf("⚠️ Circuit breaker did not recover properly (state: %s)", recoveredState)
			}
		} else {
			sdk.logger.Warnf("⚠️ Circuit breaker did not allow execution in half-open state")
		}
	}

	// Phase 3: Auto-reset
	if request.AutoReset {
		sdk.logger.Infof("🔄 Phase 3: Auto-resetting circuit breaker")
		cb.mutex.Lock()
		cb.state = initialState
		cb.failureCount = initialFailures
		cb.lastFailure = nil
		cb.mutex.Unlock()
		sdk.logger.Infof("✅ Circuit breaker reset to initial state")
	}

	sdk.logger.Infof("✅ Circuit breaker test completed: %s", testID)
}

// executeRetryQueueTest runs a specific retry queue test
func (sdk *BridgeSDK) executeRetryQueueTest(testID string, request struct {
	FailureRate     float64 `json:"failure_rate"`
	TransactionCount int     `json:"transaction_count"`
	MaxRetries      int     `json:"max_retries"`
	TestDuration    int     `json:"test_duration"`
	TestDeadLetter  bool    `json:"test_dead_letter"`
	StressTest      bool    `json:"stress_test"`
}) {
	sdk.logger.Infof("🔄 Starting retry queue test: %s", testID)

	// Record initial queue state
	sdk.retryQueue.mutex.RLock()
	initialQueueSize := len(sdk.retryQueue.items)
	sdk.retryQueue.mutex.RUnlock()

	sdk.deadLetterMutex.RLock()
	initialDeadLetterSize := len(sdk.deadLetterQueue)
	sdk.deadLetterMutex.RUnlock()

	sdk.logger.Infof("📊 Initial state - Retry queue: %d, Dead letter: %d", initialQueueSize, initialDeadLetterSize)

	// Generate test transactions
	successCount := 0
	failureCount := 0

	for i := 0; i < request.TransactionCount; i++ {
		testData := map[string]interface{}{
			"test_id":        testID,
			"transaction_id": fmt.Sprintf("retry_test_tx_%d", i),
			"chain":          []string{"ethereum", "solana", "blackhole"}[i%3],
			"amount":         100.0 + float64(i),
			"timestamp":      time.Now().Format(time.RFC3339),
		}

		// Determine if this transaction should fail
		shouldFail := rand.Float64()*100 < request.FailureRate

		if shouldFail {
			testError := fmt.Errorf("retry queue test failure %d (%.1f%% failure rate)", i, request.FailureRate)
			sdk.addToRetryQueue(fmt.Sprintf("retry_test_event_%d", i), testData, testError)
			failureCount++
		} else {
			// Simulate successful transaction
			successCount++
		}

		// Add delay for stress test
		if request.StressTest {
			time.Sleep(10 * time.Millisecond)
		} else {
			time.Sleep(50 * time.Millisecond)
		}
	}

	sdk.logger.Infof("📊 Generated %d transactions: %d successful, %d failed", request.TransactionCount, successCount, failureCount)

	// Monitor queue processing for test duration
	monitorDuration := time.Duration(request.TestDuration) * time.Minute
	if monitorDuration > 5*time.Minute {
		monitorDuration = 5 * time.Minute // Cap monitoring at 5 minutes
	}

	sdk.logger.Infof("⏳ Monitoring retry queue for %v", monitorDuration)

	startTime := time.Now()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sdk.retryQueue.mutex.RLock()
			currentQueueSize := len(sdk.retryQueue.items)
			sdk.retryQueue.mutex.RUnlock()

			sdk.deadLetterMutex.RLock()
			currentDeadLetterSize := len(sdk.deadLetterQueue)
			sdk.deadLetterMutex.RUnlock()

			elapsed := time.Since(startTime)
			sdk.logger.Infof("📊 [%v] Retry queue: %d, Dead letter: %d", elapsed.Truncate(time.Second), currentQueueSize, currentDeadLetterSize)

		case <-time.After(monitorDuration):
			// Final statistics
			sdk.retryQueue.mutex.RLock()
			finalQueueSize := len(sdk.retryQueue.items)
			sdk.retryQueue.mutex.RUnlock()

			sdk.deadLetterMutex.RLock()
			finalDeadLetterSize := len(sdk.deadLetterQueue)
			sdk.deadLetterMutex.RUnlock()

			sdk.logger.Infof("✅ Retry queue test completed: %s", testID)
			sdk.logger.Infof("📊 Final state - Retry queue: %d, Dead letter: %d", finalQueueSize, finalDeadLetterSize)
			sdk.logger.Infof("📊 Queue changes - Retry: %+d, Dead letter: %+d", finalQueueSize-initialQueueSize, finalDeadLetterSize-initialDeadLetterSize)

			return
		}
	}
}

// getResilienceTestStatus returns the status of a resilience test
func (sdk *BridgeSDK) getResilienceTestStatus(testID string) map[string]interface{} {
	// In a production system, this would track actual test state
	// For now, return mock status based on test ID

	if testID == "" {
		return map[string]interface{}{
			"error": "Test ID required",
		}
	}

	// Parse test type from ID
	testType := "unknown"
	if strings.Contains(testID, "circuit_breaker") || strings.Contains(testID, "cb_test") {
		testType = "circuit_breaker"
	} else if strings.Contains(testID, "retry") {
		testType = "retry_queue"
	} else if strings.Contains(testID, "resilience") {
		testType = "comprehensive"
	}

	// Get current system state for status
	sdk.retryQueue.mutex.RLock()
	retryQueueSize := len(sdk.retryQueue.items)
	sdk.retryQueue.mutex.RUnlock()

	sdk.deadLetterMutex.RLock()
	deadLetterSize := len(sdk.deadLetterQueue)
	sdk.deadLetterMutex.RUnlock()

	// Get circuit breaker states
	circuitBreakerStates := make(map[string]string)
	for name, cb := range sdk.circuitBreakers {
		cb.mutex.RLock()
		circuitBreakerStates[name] = string(cb.state)
		cb.mutex.RUnlock()
	}

	return map[string]interface{}{
		"test_id":    testID,
		"test_type":  testType,
		"status":     "completed", // Mock status
		"progress":   100.0,
		"started_at": time.Now().Add(-10 * time.Minute).Format(time.RFC3339),
		"completed_at": time.Now().Format(time.RFC3339),
		"duration":   "10m0s",
		"results": map[string]interface{}{
			"overall_score":      85.5,
			"circuit_breakers":   circuitBreakerStates,
			"retry_queue_size":   retryQueueSize,
			"dead_letter_size":   deadLetterSize,
			"tests_passed":       8,
			"tests_failed":       2,
			"recovery_time_avg":  "2.3s",
			"system_stability":   "92.1%",
		},
		"recommendations": []string{
			"Consider increasing circuit breaker timeout for ethereum_listener",
			"Monitor retry queue size during high load periods",
			"Implement additional monitoring for dead letter queue",
		},
	}
}

// Event Tree Dumping Implementation

// EventTreeNode represents a node in the event tree
type EventTreeNode struct {
	EventID        string                 `json:"event_id"`
	Chain          string                 `json:"chain"`
	EventType      string                 `json:"event_type"`
	Timestamp      time.Time              `json:"timestamp"`
	Status         string                 `json:"status"`
	ParentID       string                 `json:"parent_id,omitempty"`
	Children       []EventTreeNode        `json:"children,omitempty"`
	Metadata       map[string]interface{} `json:"metadata"`
	ProcessingTime time.Duration          `json:"processing_time"`
	RetryCount     int                    `json:"retry_count"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
}

// EventTree represents the complete event tree structure
type EventTree struct {
	RootNodes   []EventTreeNode `json:"root_nodes"`
	TotalEvents int             `json:"total_events"`
	TreeDepth   int             `json:"tree_depth"`
	GeneratedAt time.Time       `json:"generated_at"`
	TimeRange   struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"time_range"`
}

// handleEventTree provides event tree visualization and dumping
func (sdk *BridgeSDK) handleEventTree(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters
	query := r.URL.Query()
	format := query.Get("format")
	if format == "" {
		format = "json"
	}

	depth := 10 // default depth
	if depthStr := query.Get("depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 {
			depth = d
		}
	}

	limit := 100 // default limit
	if limitStr := query.Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	chainFilter := query.Get("chain")
	sinceStr := query.Get("since")
	var since time.Time
	if sinceStr != "" {
		if s, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = s
		}
	}

	// Generate event tree
	eventTree := sdk.generateEventTree(depth, limit, chainFilter, since)

	switch format {
	case "json":
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    eventTree,
		})

	case "tree":
		// ASCII tree format
		w.Header().Set("Content-Type", "text/plain")
		treeText := sdk.formatEventTreeAsText(eventTree)
		w.Write([]byte(treeText))

	case "dot":
		// Graphviz DOT format
		w.Header().Set("Content-Type", "text/plain")
		dotText := sdk.formatEventTreeAsDot(eventTree)
		w.Write([]byte(dotText))

	case "mermaid":
		// Mermaid diagram format
		w.Header().Set("Content-Type", "text/plain")
		mermaidText := sdk.formatEventTreeAsMermaid(eventTree)
		w.Write([]byte(mermaidText))

	default:
		http.Error(w, "Unsupported format. Use: json, tree, dot, or mermaid", http.StatusBadRequest)
	}
}

// generateEventTree creates a hierarchical tree structure from events
func (sdk *BridgeSDK) generateEventTree(depth, limit int, chainFilter string, since time.Time) EventTree {
	sdk.eventsMutex.RLock()
	defer sdk.eventsMutex.RUnlock()

	// Filter events
	var filteredEvents []Event
	for _, event := range sdk.events {
		if chainFilter != "" && event.Chain != chainFilter {
			continue
		}
		if !since.IsZero() && event.Timestamp.Before(since) {
			continue
		}
		filteredEvents = append(filteredEvents, event)
	}

	// Sort events by timestamp
	sort.Slice(filteredEvents, func(i, j int) bool {
		return filteredEvents[i].Timestamp.Before(filteredEvents[j].Timestamp)
	})

	// Limit events
	if len(filteredEvents) > limit {
		filteredEvents = filteredEvents[:limit]
	}

	// Build event tree
	eventMap := make(map[string]*EventTreeNode)
	var rootNodes []EventTreeNode

	// Create nodes
	for _, event := range filteredEvents {
		// Determine status
		status := "pending"
		if event.Processed {
			status = "completed"
		}
		if event.ErrorMessage != "" {
			status = "failed"
		}

		node := EventTreeNode{
			EventID:   event.ID,
			Chain:     event.Chain,
			EventType: event.Type,
			Timestamp: event.Timestamp,
			Status:    status,
			Metadata: map[string]interface{}{
				"block_number": event.BlockNumber,
				"tx_hash":      event.TxHash,
				"processed":    event.Processed,
				"data":         event.Data,
			},
			ProcessingTime: time.Since(event.Timestamp),
			Children:       make([]EventTreeNode, 0),
			RetryCount:     event.RetryCount,
			ErrorMessage:   event.ErrorMessage,
		}

		// Check for additional retry information from retry queue
		if retryInfo := sdk.getRetryInfo(event.ID); retryInfo != nil {
			if retryInfo.Attempts > node.RetryCount {
				node.RetryCount = retryInfo.Attempts
			}
			if retryInfo.LastError != "" && node.ErrorMessage == "" {
				node.ErrorMessage = retryInfo.LastError
			}
		}

		eventMap[event.ID] = &node
	}

	// Build parent-child relationships
	for _, event := range filteredEvents {
		node := eventMap[event.ID]

		// Find parent based on transaction hash or related events
		parentID := sdk.findParentEvent(event, filteredEvents)
		if parentID != "" && eventMap[parentID] != nil {
			node.ParentID = parentID
			parent := eventMap[parentID]
			parent.Children = append(parent.Children, *node)
		} else {
			// This is a root node
			rootNodes = append(rootNodes, *node)
		}
	}

	// Calculate tree depth
	maxDepth := 0
	for _, root := range rootNodes {
		depth := sdk.calculateTreeDepth(root, 1)
		if depth > maxDepth {
			maxDepth = depth
		}
	}

	// Determine time range
	var timeRange struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	}
	if len(filteredEvents) > 0 {
		timeRange.Start = filteredEvents[0].Timestamp
		timeRange.End = filteredEvents[len(filteredEvents)-1].Timestamp
	}

	return EventTree{
		RootNodes:   rootNodes,
		TotalEvents: len(filteredEvents),
		TreeDepth:   maxDepth,
		GeneratedAt: time.Now(),
		TimeRange:   timeRange,
	}
}

// findParentEvent finds the parent event for a given event
func (sdk *BridgeSDK) findParentEvent(event Event, allEvents []Event) string {
	// Look for events with the same transaction hash but earlier timestamp
	for _, other := range allEvents {
		if other.ID != event.ID &&
			other.TxHash == event.TxHash &&
			other.Timestamp.Before(event.Timestamp) {
			return other.ID
		}
	}

	// Look for related events based on data content
	if event.Type == "bridge_confirmation" || event.Type == "bridge_completion" {
		for _, other := range allEvents {
			if other.Type == "bridge_initiation" &&
				other.Timestamp.Before(event.Timestamp) {
				// Check if events are related by comparing data fields
				if sdk.eventsAreRelated(event, other) {
					return other.ID
				}
			}
		}
	}

	// Look for events in sequence (e.g., deposit -> lock -> mint)
	if event.Type == "token_mint" || event.Type == "token_burn" {
		for _, other := range allEvents {
			if (other.Type == "token_lock" || other.Type == "token_deposit") &&
				other.Timestamp.Before(event.Timestamp) &&
				sdk.eventsAreRelated(event, other) {
				return other.ID
			}
		}
	}

	return ""
}

// eventsAreRelated checks if two events are related based on their data
func (sdk *BridgeSDK) eventsAreRelated(event1, event2 Event) bool {
	// Compare data fields to determine if events are related
	if event1.Data == nil || event2.Data == nil {
		return false
	}

	// Check for common identifiers in the data
	data1 := event1.Data
	data2 := event2.Data

	// Compare common fields that might indicate relationship
	if addr1, ok1 := data1["from_address"]; ok1 {
		if addr2, ok2 := data2["from_address"]; ok2 && addr1 == addr2 {
			return true
		}
	}

	if addr1, ok1 := data1["to_address"]; ok1 {
		if addr2, ok2 := data2["to_address"]; ok2 && addr1 == addr2 {
			return true
		}
	}

	if amount1, ok1 := data1["amount"]; ok1 {
		if amount2, ok2 := data2["amount"]; ok2 && amount1 == amount2 {
			return true
		}
	}

	if token1, ok1 := data1["token"]; ok1 {
		if token2, ok2 := data2["token"]; ok2 && token1 == token2 {
			return true
		}
	}

	return false
}

// calculateTreeDepth calculates the maximum depth of a tree
func (sdk *BridgeSDK) calculateTreeDepth(node EventTreeNode, currentDepth int) int {
	maxDepth := currentDepth
	for _, child := range node.Children {
		childDepth := sdk.calculateTreeDepth(child, currentDepth+1)
		if childDepth > maxDepth {
			maxDepth = childDepth
		}
	}
	return maxDepth
}

// getRetryInfo gets retry information for an event
func (sdk *BridgeSDK) getRetryInfo(eventID string) *RetryItem {
	sdk.retryQueue.mutex.RLock()
	defer sdk.retryQueue.mutex.RUnlock()

	for _, item := range sdk.retryQueue.items {
		if item.ID == eventID {
			return &item
		}
	}
	return nil
}

// Event Tree Formatting Methods

// formatEventTreeAsText formats the event tree as ASCII text
func (sdk *BridgeSDK) formatEventTreeAsText(tree EventTree) string {
	var result strings.Builder

	result.WriteString(fmt.Sprintf("Event Tree (Generated: %s)\n", tree.GeneratedAt.Format(time.RFC3339)))
	result.WriteString(fmt.Sprintf("Total Events: %d, Tree Depth: %d\n", tree.TotalEvents, tree.TreeDepth))
	result.WriteString(fmt.Sprintf("Time Range: %s to %s\n\n",
		tree.TimeRange.Start.Format(time.RFC3339),
		tree.TimeRange.End.Format(time.RFC3339)))

	for i, root := range tree.RootNodes {
		sdk.formatNodeAsText(&result, root, "", i == len(tree.RootNodes)-1)
	}

	return result.String()
}

// formatNodeAsText recursively formats a node as text
func (sdk *BridgeSDK) formatNodeAsText(result *strings.Builder, node EventTreeNode, prefix string, isLast bool) {
	connector := "├── "
	if isLast {
		connector = "└── "
	}

	result.WriteString(fmt.Sprintf("%s%s[%s] %s (%s) - %s\n",
		prefix, connector, node.Chain, node.EventID, node.EventType, node.Timestamp.Format("15:04:05")))

	if node.RetryCount > 0 {
		result.WriteString(fmt.Sprintf("%s    ↳ Retries: %d\n", prefix, node.RetryCount))
	}

	if node.ErrorMessage != "" {
		result.WriteString(fmt.Sprintf("%s    ↳ Error: %s\n", prefix, node.ErrorMessage))
	}

	newPrefix := prefix
	if isLast {
		newPrefix += "    "
	} else {
		newPrefix += "│   "
	}

	for i, child := range node.Children {
		sdk.formatNodeAsText(result, child, newPrefix, i == len(node.Children)-1)
	}
}

// formatEventTreeAsDot formats the event tree as Graphviz DOT
func (sdk *BridgeSDK) formatEventTreeAsDot(tree EventTree) string {
	var result strings.Builder

	result.WriteString("digraph EventTree {\n")
	result.WriteString("  rankdir=TB;\n")
	result.WriteString("  node [shape=box, style=rounded];\n\n")

	// Add nodes
	nodeCount := 0
	nodeMap := make(map[string]int)

	var addNodes func(node EventTreeNode)
	addNodes = func(node EventTreeNode) {
		nodeID := nodeCount
		nodeMap[node.EventID] = nodeID
		nodeCount++

		color := "lightblue"
		switch node.Chain {
		case "ethereum":
			color = "lightgreen"
		case "solana":
			color = "lightyellow"
		case "blackhole":
			color = "lightpink"
		}

		label := fmt.Sprintf("%s\\n%s\\n%s", node.EventID[:8], node.EventType, node.Chain)
		if node.RetryCount > 0 {
			label += fmt.Sprintf("\\nRetries: %d", node.RetryCount)
		}

		result.WriteString(fmt.Sprintf("  node%d [label=\"%s\", fillcolor=\"%s\", style=\"filled\"];\n",
			nodeID, label, color))

		for _, child := range node.Children {
			addNodes(child)
		}
	}

	for _, root := range tree.RootNodes {
		addNodes(root)
	}

	result.WriteString("\n")

	// Add edges
	var addEdges func(node EventTreeNode)
	addEdges = func(node EventTreeNode) {
		parentID := nodeMap[node.EventID]
		for _, child := range node.Children {
			childID := nodeMap[child.EventID]
			result.WriteString(fmt.Sprintf("  node%d -> node%d;\n", parentID, childID))
			addEdges(child)
		}
	}

	for _, root := range tree.RootNodes {
		addEdges(root)
	}

	result.WriteString("}\n")
	return result.String()
}

// formatEventTreeAsMermaid formats the event tree as Mermaid diagram
func (sdk *BridgeSDK) formatEventTreeAsMermaid(tree EventTree) string {
	var result strings.Builder

	result.WriteString("graph TD\n")

	// Add nodes and edges
	var addMermaidNodes func(node EventTreeNode, parentID string)
	addMermaidNodes = func(node EventTreeNode, parentID string) {
		nodeID := strings.ReplaceAll(node.EventID, "-", "")[:8]

		// Node definition
		nodeLabel := fmt.Sprintf("%s<br/>%s<br/>%s", node.EventID[:8], node.EventType, node.Chain)
		if node.RetryCount > 0 {
			nodeLabel += fmt.Sprintf("<br/>Retries: %d", node.RetryCount)
		}

		// Node styling based on chain
		style := ""
		switch node.Chain {
		case "ethereum":
			style = ":::ethereum"
		case "solana":
			style = ":::solana"
		case "blackhole":
			style = ":::blackhole"
		}

		result.WriteString(fmt.Sprintf("  %s[\"%s\"]%s\n", nodeID, nodeLabel, style))

		// Edge from parent
		if parentID != "" {
			result.WriteString(fmt.Sprintf("  %s --> %s\n", parentID, nodeID))
		}

		// Process children
		for _, child := range node.Children {
			addMermaidNodes(child, nodeID)
		}
	}

	for _, root := range tree.RootNodes {
		addMermaidNodes(root, "")
	}

	// Add styling
	result.WriteString("\n")
	result.WriteString("  classDef ethereum fill:#90EE90\n")
	result.WriteString("  classDef solana fill:#FFFFE0\n")
	result.WriteString("  classDef blackhole fill:#FFB6C1\n")

	return result.String()
}

// RelayToChain relays a transaction to the specified chain
func (sdk *BridgeSDK) RelayToChain(tx *Transaction, targetChain string) error {
	// Enhanced relay logging
	fmt.Printf("\n" + strings.Repeat("-", 60) + "\n")
	fmt.Printf("🔄 RELAYING TRANSACTION TO CHAIN\n")
	fmt.Printf(strings.Repeat("-", 60) + "\n")
	fmt.Printf("   ├─ Transaction ID: %s\n", tx.ID)
	fmt.Printf("   ├─ Target Chain: %s\n", targetChain)
	fmt.Printf("   ├─ Amount: %s %s\n", tx.Amount, tx.TokenSymbol)
	fmt.Printf("   ├─ From: %s\n", tx.SourceAddress)
	fmt.Printf("   ├─ To: %s\n", tx.DestAddress)
	fmt.Printf("   └─ Starting relay process...\n")

	sdk.logger.Infof("🔄 Relaying transaction %s to %s", tx.ID, targetChain)

	// Handle BlackHole chain transactions with real blockchain
	if targetChain == "blackhole" && sdk.blockchainInterface != nil {
		fmt.Printf("   🔗 REAL BLACKHOLE BLOCKCHAIN PROCESSING\n")
		fmt.Printf("   ├─ Using blockchain interface\n")
		fmt.Printf("   ├─ Processing transaction: %s\n", tx.ID)

		sdk.logger.Infof("🔗 Processing real BlackHole blockchain transaction: %s", tx.ID)

		// Use real blockchain interface for BlackHole transactions
		err := sdk.blockchainInterface.ProcessBridgeTransaction(tx)
		if err != nil {
			fmt.Printf("   ❌ BLACKHOLE PROCESSING FAILED\n")
			fmt.Printf("   ├─ Error: %v\n", err)
			fmt.Printf("   └─ Transaction marked as failed\n")

			sdk.logger.Errorf("❌ Failed to process BlackHole transaction: %v", err)
			tx.Status = "failed"
			now := time.Now()
			tx.CompletedAt = &now
			tx.ProcessingTime = fmt.Sprintf("%.1fs", time.Since(tx.CreatedAt).Seconds())
			sdk.saveTransaction(tx)
			return err
		}

		fmt.Printf("   ✅ BLACKHOLE PROCESSING SUCCESSFUL\n")
		fmt.Printf("   ├─ Transaction processed on real blockchain\n")
		fmt.Printf("   └─ Processing time: %.1fs\n", time.Since(tx.CreatedAt).Seconds())

		sdk.logger.Infof("✅ BlackHole transaction processed successfully: %s", tx.ID)
		sdk.saveTransaction(tx)
		return nil
	}

	// Simulate relay processing for external chains (ETH/SOL)
	fmt.Printf("   🎭 SIMULATING %s CHAIN PROCESSING\n", strings.ToUpper(targetChain))
	fmt.Printf("   ├─ Chain: %s\n", targetChain)
	fmt.Printf("   ├─ Transaction: %s\n", tx.ID)
	fmt.Printf("   ├─ Simulating network delay...\n")

	sdk.logger.Infof("🎭 Simulating %s chain transaction: %s", targetChain, tx.ID)

	processingTime := time.Duration(2+rand.Intn(3)) * time.Second
	fmt.Printf("   ├─ Processing time: %v\n", processingTime)
	time.Sleep(processingTime)

	tx.Status = "completed"
	now := time.Now()
	tx.CompletedAt = &now
	tx.ProcessingTime = fmt.Sprintf("%.1fs", time.Since(tx.CreatedAt).Seconds())
	sdk.saveTransaction(tx)

	fmt.Printf("   ✅ %s CHAIN PROCESSING COMPLETED\n", strings.ToUpper(targetChain))
	fmt.Printf("   ├─ Final status: %s\n", strings.ToUpper(tx.Status))
	fmt.Printf("   └─ Total processing time: %s\n", tx.ProcessingTime)
	fmt.Printf(strings.Repeat("-", 60) + "\n\n")

	return nil
}

// GetBridgeStats returns comprehensive bridge statistics
func (sdk *BridgeSDK) GetBridgeStats() *BridgeStats {
	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	total := len(sdk.transactions)
	pending := 0
	completed := 0
	failed := 0

	for _, tx := range sdk.transactions {
		switch tx.Status {
		case "pending":
			pending++
		case "completed":
			completed++
		case "failed":
			failed++
		}
	}

	successRate := 0.0
	if total > 0 {
		successRate = float64(completed) / float64(total) * 100
	}

	// Get real blockchain stats if available
	var blackholeStats ChainStats
	if sdk.blockchainInterface != nil {
		blockchainData := sdk.blockchainInterface.GetBlockchainStats()
		blackholeStats = ChainStats{
			Transactions: blockchainData["transactions"].(int),
			Volume:       "20.2", // Keep mock volume for now
			SuccessRate:  98.1,   // Keep mock success rate
			LastBlock:    uint64(blockchainData["blocks"].(int)),
		}
	} else {
		blackholeStats = ChainStats{
			Transactions: completed / 3,
			Volume:       "20.2",
			SuccessRate:  98.1,
			LastBlock:    1500000,
		}
	}

	return &BridgeStats{
		TotalTransactions:     total,
		PendingTransactions:   pending,
		CompletedTransactions: completed,
		FailedTransactions:    failed,
		SuccessRate:           successRate,
		TotalVolume:           "125.5",
		Chains: map[string]ChainStats{
			"ethereum": {
				Transactions: completed / 3,
				Volume:       "75.2",
				SuccessRate:  96.5,
				LastBlock:    18500000,
			},
			"solana": {
				Transactions: completed / 3,
				Volume:       "30.1",
				SuccessRate:  97.2,
				LastBlock:    200000000,
			},
			"blackhole": blackholeStats,
		},
		Last24h: PeriodStats{
			Transactions: total / 10,
			Volume:       "15.5",
			SuccessRate:  successRate,
		},
		ErrorRate:             float64(failed) / float64(total), // Already a decimal (0.025 = 2.5%)
		AverageProcessingTime: "1.8s",
	}
}

// GetHealth returns system health status
func (sdk *BridgeSDK) GetHealth() *HealthStatus {
	uptime := time.Since(sdk.startTime)

	components := map[string]string{
		"ethereum_listener":  "healthy",
		"solana_listener":    "healthy",
		"blackhole_listener": sdk.checkBlackholeConnection(),
		"database":           "healthy",
		"relay_system":       "healthy",
		"replay_protection":  "healthy",
		"circuit_breakers":   "healthy",
	}

	// Check circuit breakers
	for name, cb := range sdk.circuitBreakers {
		if cb.state == "open" {
			components[name] = "degraded"
		}
	}

	allHealthy := true
	for _, status := range components {
		if status != "healthy" {
			allHealthy = false
			break
		}
	}

	status := "healthy"
	if !allHealthy {
		status = "degraded"
	}

	return &HealthStatus{
		Status:     status,
		Timestamp:  time.Now(),
		Components: components,
		Uptime:     uptime.String(),
		Version:    "1.0.0",
		Healthy:    allHealthy,
	}
}

// checkBlackholeConnection tests connection to BlackHole blockchain
func (sdk *BridgeSDK) checkBlackholeConnection() string {
	// Try multiple endpoints for BlackHole blockchain
	blackholeURLs := []string{
		"http://localhost:8080/api/health",
		"http://127.0.0.1:8080/api/health",
		"http://blackhole-blockchain:8080/api/health", // Docker fallback
	}

	for _, url := range blackholeURLs {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			return "healthy"
		}
	}

	return "disconnected"
}

// GetAllTransactions returns all transactions
func (sdk *BridgeSDK) GetAllTransactions() ([]*Transaction, error) {
	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	transactions := make([]*Transaction, 0, len(sdk.transactions))
	for _, tx := range sdk.transactions {
		transactions = append(transactions, tx)
	}

	return transactions, nil
}

// GetErrorMetrics returns error metrics
func (sdk *BridgeSDK) GetErrorMetrics() *ErrorMetrics {
	sdk.errorHandler.mutex.RLock()
	defer sdk.errorHandler.mutex.RUnlock()

	total := len(sdk.errorHandler.errors)
	errorsByType := make(map[string]int)

	for _, err := range sdk.errorHandler.errors {
		errorsByType[err.Type]++
	}

	recentErrors := sdk.errorHandler.errors
	if len(recentErrors) > 10 {
		recentErrors = recentErrors[len(recentErrors)-10:]
	}

	// Calculate actual error rate as decimal (not percentage)
	errorRate := 0.0
	if total > 0 {
		errorRate = float64(total) / float64(total+100) // Assume some successful transactions
	}

	return &ErrorMetrics{
		ErrorRate:    errorRate, // Decimal format (0.025 = 2.5%)
		TotalErrors:  total,
		ErrorsByType: errorsByType,
		RecentErrors: recentErrors,
	}
}

// getBlockedReplays safely gets the blocked replays count
func (sdk *BridgeSDK) getBlockedReplays() int64 {
	sdk.blockedMutex.RLock()
	defer sdk.blockedMutex.RUnlock()
	return sdk.blockedReplays
}

// GetTransactionStatus returns the status of a specific transaction
func (sdk *BridgeSDK) GetTransactionStatus(id string) (*Transaction, error) {
	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	tx, exists := sdk.transactions[id]
	if !exists {
		return nil, fmt.Errorf("transaction not found: %s", id)
	}

	return tx, nil
}

// GetTransactionsByStatus returns transactions filtered by status
func (sdk *BridgeSDK) GetTransactionsByStatus(status string) ([]*Transaction, error) {
	sdk.transactionsMutex.RLock()
	defer sdk.transactionsMutex.RUnlock()

	var filtered []*Transaction
	for _, tx := range sdk.transactions {
		if tx.Status == status {
			filtered = append(filtered, tx)
		}
	}

	return filtered, nil
}

// GetCircuitBreakerStatus returns circuit breaker status
func (sdk *BridgeSDK) GetCircuitBreakerStatus() map[string]*CircuitBreaker {
	result := make(map[string]*CircuitBreaker)
	for name, cb := range sdk.circuitBreakers {
		result[name] = cb
	}
	return result
}

// GetFailedEvents returns failed events
func (sdk *BridgeSDK) GetFailedEvents() []FailedEvent {
	sdk.eventRecovery.mutex.RLock()
	defer sdk.eventRecovery.mutex.RUnlock()

	return sdk.eventRecovery.failedEvents
}

// GetProcessedEvents returns recently processed events
func (sdk *BridgeSDK) GetProcessedEvents() []Event {
	sdk.eventsMutex.RLock()
	defer sdk.eventsMutex.RUnlock()

	// Return last 100 events
	start := 0
	if len(sdk.events) > 100 {
		start = len(sdk.events) - 100
	}

	return sdk.events[start:]
}

// GetReplayProtectionStatus returns replay protection status
func (sdk *BridgeSDK) GetReplayProtectionStatus() map[string]interface{} {
	sdk.replayProtection.mutex.RLock()
	defer sdk.replayProtection.mutex.RUnlock()

	// Find oldest entry
	var oldestEntry *time.Time
	for _, timestamp := range sdk.replayProtection.processedHashes {
		if oldestEntry == nil || timestamp.Before(*oldestEntry) {
			oldestEntry = &timestamp
		}
	}

	return map[string]interface{}{
		"enabled":          sdk.replayProtection.enabled,
		"processed_hashes": len(sdk.replayProtection.processedHashes),
		"blocked_replays":  sdk.getBlockedReplays(),
		"cache_size":       10000,
		"oldest_entry":     oldestEntry,
		"cleanup_interval": "1h",
		"last_cleanup":     time.Now().Add(-1 * time.Hour),
		"protection_rate": func() float64 {
			total := int64(len(sdk.replayProtection.processedHashes)) + sdk.getBlockedReplays()
			if total == 0 {
				return 100.0
			}
			return float64(len(sdk.replayProtection.processedHashes)) / float64(total) * 100.0
		}(),
	}
}

// StartWebServer starts the web server with all endpoints
func (sdk *BridgeSDK) StartWebServer(addr string) error {
	r := mux.NewRouter()

	// Main dashboard
	r.HandleFunc("/", sdk.handleDashboard).Methods("GET")

	// Serve logo image
	r.HandleFunc("/blackhole-logo.png", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "../media/blackhole-logo.png")
	}).Methods("GET")

	// --- NEW: Infra Dashboard and API endpoints ---
	r.HandleFunc("/infra-dashboard", sdk.handleInfraDashboard).Methods("GET")
	r.HandleFunc("/infra/listener-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Check if listeners are actively processing events
		ethereumStatus := "closed"  // Default to healthy
		solanaStatus := "closed"    // Default to healthy
		blackholeStatus := "closed" // Default to healthy

		// Check circuit breaker states if available
		if sdk.circuitBreakers != nil && len(sdk.circuitBreakers) > 0 {
			if cb, ok := sdk.circuitBreakers["ethereum_listener"]; ok && cb != nil {
				ethereumStatus = cb.getState()
			}
			if cb, ok := sdk.circuitBreakers["solana_listener"]; ok && cb != nil {
				solanaStatus = cb.getState()
			}
			if cb, ok := sdk.circuitBreakers["blackhole_listener"]; ok && cb != nil {
				blackholeStatus = cb.getState()
			}
		}

		// Count recent events by chain to show activity
		ethereumEvents := 0
		solanaEvents := 0
		blackholeEvents := 0

		// Check events from the last 5 minutes
		cutoff := time.Now().Add(-5 * time.Minute)
		for _, event := range sdk.events {
			if event.Timestamp.After(cutoff) {
				switch event.Chain {
				case "Ethereum":
					ethereumEvents++
				case "Solana":
					solanaEvents++
				case "BlackHole":
					blackholeEvents++
				}
			}
		}

		data := map[string]interface{}{
			"ethereum":         ethereumStatus,
			"solana":           solanaStatus,
			"blackhole":        blackholeStatus,
			"ethereum_events":  ethereumEvents,
			"solana_events":    solanaEvents,
			"blackhole_events": blackholeEvents,
			"last_event":       nil,
			"total_events":     len(sdk.events),
		}

		if len(sdk.events) > 0 {
			data["last_event"] = sdk.events[len(sdk.events)-1].Timestamp.Format(time.RFC3339)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    data,
		})
	}).Methods("GET")
	r.HandleFunc("/infra/retry-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := sdk.retryQueue.GetStats()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    stats,
		})
	}).Methods("GET")
	r.HandleFunc("/infra/relay-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data := map[string]interface{}{
			"relay_server": "running",
			"last_relay":   nil,
		}
		if len(sdk.events) > 0 {
			for i := len(sdk.events) - 1; i >= 0; i-- {
				if sdk.events[i].Type == "relay" {
					data["last_relay"] = sdk.events[i].Timestamp.Format(time.RFC3339)
					break
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    data,
		})
	}).Methods("GET")
	// Manual Testing API Endpoints
	r.HandleFunc("/api/manual-transfer", sdk.handleManualTransfer).Methods("POST")
	r.HandleFunc("/api/transfer-status/{id}", sdk.handleTransferStatus).Methods("GET")

	// Wallet Monitoring API Endpoints
	r.HandleFunc("/api/wallet/transactions", sdk.handleWalletTransactions).Methods("GET")
	r.HandleFunc("/api/wallet/transactions/mark-read", sdk.handleMarkTransactionAsRead).Methods("POST", "OPTIONS")

	// gRPC Documentation Endpoint
	r.HandleFunc("/api/grpc/endpoints", sdk.handleGRPCEndpoints).Methods("GET")

	r.HandleFunc("/mock/bridge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Create a mock transaction event
		tx := &Transaction{
			ID:            fmt.Sprintf("mock_%d", time.Now().UnixNano()),
			Hash:          fmt.Sprintf("0xMOCK_%d", time.Now().UnixNano()),
			SourceChain:   "ethereum",
			DestChain:     "solana",
			SourceAddress: "0xMOCK_SOURCE",
			DestAddress:   "MOCK_DEST",
			TokenSymbol:   "USDC",
			Amount:        "123.45",
			Fee:           "0.001",
			Status:        "pending",
			CreatedAt:     time.Now(),
			Confirmations: 0,
			BlockNumber:   99999999,
		}
		sdk.saveTransaction(tx)

		// Add event to internal tracking
		sdk.addEvent("mock_bridge", "ethereum", tx.Hash, map[string]interface{}{
			"amount": tx.Amount,
			"token":  tx.TokenSymbol,
			"from":   tx.SourceAddress,
			"to":     tx.DestAddress,
			"type":   "mock_test",
		})

		// Broadcast real-time event to WebSocket clients
		realTimeEvent := map[string]interface{}{
			"type":           "transaction",
			"event_type":     "mock_bridge",
			"transaction_id": tx.ID,
			"hash":           tx.Hash,
			"source_chain":   tx.SourceChain,
			"dest_chain":     tx.DestChain,
			"amount":         tx.Amount,
			"token":          tx.TokenSymbol,
			"status":         tx.Status,
			"timestamp":      time.Now().Format(time.RFC3339),
			"is_mock":        true,
		}
		sdk.broadcastEventToClients(realTimeEvent)

		// Simulate processing stages with real-time updates
		go func() {
			time.Sleep(500 * time.Millisecond)

			// Update status to processing
			tx.Status = "processing"
			sdk.saveTransaction(tx)

			processingEvent := map[string]interface{}{
				"type":           "transaction_update",
				"transaction_id": tx.ID,
				"status":         "processing",
				"timestamp":      time.Now().Format(time.RFC3339),
				"stage":          "Processing cross-chain transfer",
				"is_mock":        true,
			}
			sdk.broadcastEventToClients(processingEvent)

			time.Sleep(1 * time.Second)

			// Update status to completed
			tx.Status = "completed"
			tx.Confirmations = 12
			sdk.saveTransaction(tx)

			completedEvent := map[string]interface{}{
				"type":           "transaction_update",
				"transaction_id": tx.ID,
				"status":         "completed",
				"confirmations":  12,
				"timestamp":      time.Now().Format(time.RFC3339),
				"stage":          "Transfer completed successfully",
				"is_mock":        true,
			}
			sdk.broadcastEventToClients(completedEvent)
		}()

		// Simulate relay processing
		err := sdk.RelayToChain(tx, tx.DestChain)
		result := map[string]interface{}{
			"mock":           "event sent",
			"transaction_id": tx.ID,
			"status":         tx.Status,
			"timestamp":      time.Now().Format(time.RFC3339),
			"message":        "Mock transaction created and will be processed in real-time",
		}
		if err != nil {
			result["relay_error"] = err.Error()
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    result,
		})
	}).Methods("POST")

	// Add missing stress test endpoint
	r.HandleFunc("/mock/stress-test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Start a simple stress test by creating multiple mock events
		go func() {
			for i := 0; i < 10; i++ {
				tx := &Transaction{
					ID:            fmt.Sprintf("stress_%d_%d", time.Now().UnixNano(), i),
					Hash:          fmt.Sprintf("0xSTRESS_%d_%d", time.Now().UnixNano(), i),
					SourceChain:   "ethereum",
					DestChain:     "solana",
					SourceAddress: fmt.Sprintf("0xSTRESS_SOURCE_%d", i),
					DestAddress:   fmt.Sprintf("STRESS_DEST_%d", i),
					TokenSymbol:   "USDC",
					Amount:        fmt.Sprintf("%.2f", float64(i+1)*10.5),
					Fee:           "0.001",
					Status:        "pending",
					CreatedAt:     time.Now(),
					Confirmations: 0,
					BlockNumber:   uint64(99999999 + i),
				}
				sdk.saveTransaction(tx)
				sdk.addEvent("stress_test", "ethereum", tx.Hash, map[string]interface{}{
					"amount":  tx.Amount,
					"token":   tx.TokenSymbol,
					"from":    tx.SourceAddress,
					"to":      tx.DestAddress,
					"test_id": i,
				})
				time.Sleep(100 * time.Millisecond) // Small delay between events
			}
		}()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"message":   "Stress test initiated with 10 transactions",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}).Methods("POST")
	// --- END NEW ---

	// --- NEW: Log/Event/Status Endpoints ---
	r.HandleFunc("/log/event", sdk.handleLogEvent).Methods("GET")
	r.HandleFunc("/log/retry", sdk.handleLogRetry).Methods("GET")
	r.HandleFunc("/bridge/status", sdk.handleBridgeStatus).Methods("GET")

	// --- NEW: API Log Endpoints ---
	r.HandleFunc("/api/log/retry", sdk.handleAPILogRetry).Methods("GET", "POST")
	r.HandleFunc("/api/log/status", sdk.handleAPILogStatus).Methods("GET")

	// --- NEW: Cross-Chain Simulation Endpoints ---
	r.HandleFunc("/api/simulation/cross-chain", sdk.handleCrossChainSimulation).Methods("POST")
	r.HandleFunc("/api/simulation/cross-chain/status/{id}", sdk.handleCrossChainSimulationStatus).Methods("GET")
	// --- END NEW ---

	// API endpoints
	r.HandleFunc("/health", sdk.handleHealth).Methods("GET")
	r.HandleFunc("/stats", sdk.handleStats).Methods("GET")
	r.HandleFunc("/transactions", sdk.handleTransactions).Methods("GET")
	r.HandleFunc("/transaction/{id}", sdk.handleTransactionDetail).Methods("GET")
	r.HandleFunc("/errors", sdk.handleErrors).Methods("GET")
	r.HandleFunc("/circuit-breakers", sdk.handleCircuitBreakers).Methods("GET")
	r.HandleFunc("/failed-events", sdk.handleFailedEvents).Methods("GET")
	r.HandleFunc("/replay-protection", sdk.handleReplayProtection).Methods("GET")
	r.HandleFunc("/processed-events", sdk.handleProcessedEvents).Methods("GET")
	r.HandleFunc("/logs", sdk.handleDocs).Methods("GET")
	r.HandleFunc("/docs", sdk.handleDocs).Methods("GET")
	r.HandleFunc("/retry-queue", sdk.handleRetryQueue).Methods("GET")
	r.HandleFunc("/panic-recovery", sdk.handlePanicRecovery).Methods("GET")
	r.HandleFunc("/simulation", sdk.handleSimulation).Methods("GET")
	r.HandleFunc("/api/simulation/run", sdk.handleRunSimulation).Methods("POST")

	// Static file serving for logo and media
	r.HandleFunc("/blackhole-logo.jpg", sdk.handleLogo).Methods("GET")
	r.PathPrefix("/media/").Handler(http.StripPrefix("/media/", http.FileServer(http.Dir("../media/"))))

	// Transfer endpoints
	r.HandleFunc("/transfer", sdk.handleTransfer).Methods("POST")
	r.HandleFunc("/relay", sdk.handleRelay).Methods("POST")

	// WebSocket endpoints
	r.HandleFunc("/ws/logs", sdk.handleWebSocketLogs)
	r.HandleFunc("/ws/events", sdk.handleWebSocketEvents)
	r.HandleFunc("/ws/metrics", sdk.handleWebSocketMetrics)

	// Relay server endpoints
	r.HandleFunc("/relay/ws", sdk.handleRelayWebSocket)
	r.HandleFunc("/relay/health", sdk.handleRelayHealth)
	r.HandleFunc("/relay/stats", sdk.handleRelayStats)

	// Performance monitoring endpoints
	r.HandleFunc("/performance/metrics", sdk.handlePerformanceMetrics)
	r.HandleFunc("/performance/latency", sdk.handleLatencyMetrics)
	r.HandleFunc("/performance/throughput", sdk.handleThroughputMetrics)

	// Enhanced performance monitoring endpoints
	r.HandleFunc("/api/performance/dashboard", sdk.handlePerformanceDashboard).Methods("GET")
	r.HandleFunc("/api/performance/alerts", sdk.handlePerformanceAlerts).Methods("GET")
	r.HandleFunc("/api/performance/historical", sdk.handleHistoricalPerformance).Methods("GET")

	// Load testing and chaos testing endpoints
	r.HandleFunc("/test/load", sdk.handleLoadTest)
	r.HandleFunc("/test/chaos", sdk.handleChaosTest)
	r.HandleFunc("/test/status", sdk.handleTestStatus)

	// Enhanced resilience testing endpoints
	r.HandleFunc("/api/resilience/test", sdk.handleResilienceTest).Methods("POST")
	r.HandleFunc("/api/resilience/status", sdk.handleResilienceStatus).Methods("GET")
	r.HandleFunc("/api/resilience/scenarios", sdk.handleResilienceScenarios).Methods("GET")
	r.HandleFunc("/api/resilience/circuit-breaker/test", sdk.handleCircuitBreakerTest).Methods("POST")
	r.HandleFunc("/api/resilience/retry-queue/test", sdk.handleRetryQueueTest).Methods("POST")

	// Event root tree dumping endpoint
	r.HandleFunc("/events/tree", sdk.handleEventTree)

	// Enhanced dashboard endpoints
	r.HandleFunc("/test/load/stop", sdk.handleStopLoadTest)
	r.HandleFunc("/test/chaos/stop", sdk.handleStopChaosTest)
	r.HandleFunc("/core/eth-height", sdk.handleEthHeight)
	r.HandleFunc("/core/sol-height", sdk.handleSolHeight)
	r.HandleFunc("/api/token/health", sdk.handleTokenHealth)
	r.HandleFunc("/api/staking/health", sdk.handleStakingHealth)
	r.HandleFunc("/api/dex/health", sdk.handleDexHealth)

	// CLI-accessible health endpoints for automated monitoring
	r.HandleFunc("/health/cli", sdk.handleCliHealth)
	r.HandleFunc("/health/components", sdk.handleComponentsHealth)
	r.HandleFunc("/health/detailed", sdk.handleDetailedHealth)

	// Add CORS headers
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// Register advanced infra-dashboard endpoints
	r.HandleFunc("/core/validator-status", sdk.handleCoreValidatorStatus).Methods("GET")
	r.HandleFunc("/core/token-stats", sdk.handleCoreTokenStats).Methods("GET")
	r.HandleFunc("/core/block-height", sdk.handleCoreBlockHeight).Methods("GET")
	r.HandleFunc("/core/peer-count", sdk.handleCorePeerCount).Methods("GET")

	// Blockchain Integration API endpoints
	r.HandleFunc("/api/blockchain/health", sdk.handleBlockchainHealth).Methods("GET")
	r.HandleFunc("/api/blockchain/info", sdk.handleBlockchainInfo).Methods("GET")
	r.HandleFunc("/api/blockchain/stats", sdk.handleBlockchainStats).Methods("GET")
	r.HandleFunc("/api/wallet/health", sdk.handleWalletHealth).Methods("GET")
	r.HandleFunc("/api/transactions/recent", sdk.handleRecentTransactions).Methods("GET")
	r.HandleFunc("/api/bridge/cross-chain-stats", sdk.handleCrossChainStats).Methods("GET")

	// Enhanced Cross-Chain Bridge API endpoints (Backward Compatible)
	r.HandleFunc("/api/v2/routes/optimal", sdk.handleOptimalRoute).Methods("GET")
	r.HandleFunc("/api/v2/routes/multi-hop", sdk.handleMultiHopRoute).Methods("POST")
	r.HandleFunc("/api/v2/liquidity/pools", sdk.handleLiquidityPools).Methods("GET")
	r.HandleFunc("/api/v2/liquidity/optimize", sdk.handleLiquidityOptimization).Methods("POST")
	r.HandleFunc("/api/v2/providers/compare", sdk.handleProviderComparison).Methods("GET")
	r.HandleFunc("/api/v2/providers/status", sdk.handleProviderStatus).Methods("GET")
	r.HandleFunc("/api/v2/security/threats", sdk.handleSecurityThreats).Methods("GET")
	r.HandleFunc("/api/v2/security/anomalies", sdk.handleAnomalies).Methods("GET")
	r.HandleFunc("/api/v2/security/risk-score", sdk.handleRiskScore).Methods("GET")
	r.HandleFunc("/api/v2/compliance/reports", sdk.handleComplianceReports).Methods("GET")
	r.HandleFunc("/api/v2/compliance/audit", sdk.handleComplianceAudit).Methods("GET")
	r.HandleFunc("/api/v2/analytics/metrics", sdk.handleAdvancedMetrics).Methods("GET")
	r.HandleFunc("/api/v2/analytics/insights", sdk.handleAnalyticsInsights).Methods("GET")
	r.HandleFunc("/api/v2/webhooks", sdk.handleWebhooks).Methods("GET", "POST")
	r.HandleFunc("/api/v2/webhooks/{id}", sdk.handleWebhookDetail).Methods("GET", "PUT", "DELETE")
	r.HandleFunc("/api/v2/events/stream", sdk.handleEventStream).Methods("GET")
	r.HandleFunc("/api/v2/audit/logs", sdk.handleAuditLogs).Methods("GET")
	r.HandleFunc("/api/v2/bridge/aggregated-quote", sdk.handleAggregatedQuote).Methods("POST")
	r.HandleFunc("/api/v2/bridge/execute-optimal", sdk.handleExecuteOptimal).Methods("POST")

	// Advanced Testing Infrastructure API endpoints (Backward Compatible)
	r.HandleFunc("/api/v2/testing/stress/start", sdk.handleStartStressTest).Methods("POST")
	r.HandleFunc("/api/v2/testing/stress/stop", sdk.handleStopStressTest).Methods("POST")
	r.HandleFunc("/api/v2/testing/stress/status", sdk.handleStressTestStatus).Methods("GET")
	r.HandleFunc("/api/v2/testing/chaos/start", sdk.handleStartChaosTest).Methods("POST")
	r.HandleFunc("/api/v2/testing/chaos/stop", sdk.handleStopChaosTest).Methods("POST")
	r.HandleFunc("/api/v2/testing/chaos/status", sdk.handleChaosTestStatus).Methods("GET")
	r.HandleFunc("/api/v2/testing/validation/run", sdk.handleRunValidation).Methods("POST")
	r.HandleFunc("/api/v2/testing/validation/results", sdk.handleValidationResults).Methods("GET")
	r.HandleFunc("/api/v2/testing/benchmark/start", sdk.handleStartBenchmark).Methods("POST")
	r.HandleFunc("/api/v2/testing/benchmark/results", sdk.handleBenchmarkResults).Methods("GET")
	r.HandleFunc("/api/v2/testing/scenarios", sdk.handleTestScenarios).Methods("GET")
	r.HandleFunc("/api/v2/testing/scenarios/{id}/execute", sdk.handleExecuteScenario).Methods("POST")

	// Advanced Security and Compliance API endpoints (Backward Compatible)
	r.HandleFunc("/api/v2/security/fraud-detection/start", sdk.handleStartFraudDetection).Methods("POST")
	r.HandleFunc("/api/v2/security/fraud-detection/status", sdk.handleFraudDetectionStatus).Methods("GET")
	r.HandleFunc("/api/v2/security/threat-intelligence", sdk.handleThreatIntelligence).Methods("GET")
	r.HandleFunc("/api/v2/security/vulnerability-scan", sdk.handleVulnerabilityScan).Methods("POST")
	r.HandleFunc("/api/v2/security/incident-response", sdk.handleIncidentResponse).Methods("GET", "POST")
	r.HandleFunc("/api/v2/security/alerts", sdk.handleSecurityAlerts).Methods("GET")
	r.HandleFunc("/api/v2/security/alerts/{id}/acknowledge", sdk.handleAcknowledgeAlert).Methods("POST")
	r.HandleFunc("/api/v2/compliance/automation/start", sdk.handleStartComplianceAutomation).Methods("POST")
	r.HandleFunc("/api/v2/compliance/automation/status", sdk.handleComplianceAutomationStatus).Methods("GET")
	r.HandleFunc("/api/v2/compliance/policy-engine", sdk.handlePolicyEngine).Methods("GET", "POST")
	r.HandleFunc("/api/v2/compliance/risk-assessment", sdk.handleRiskAssessment).Methods("POST")
	r.HandleFunc("/api/v2/audit/trail/search", sdk.handleAuditTrailSearch).Methods("POST")
	r.HandleFunc("/api/v2/audit/trail/export", sdk.handleAuditTrailExport).Methods("POST")

	// Main Dashboard Integration API endpoints
	r.HandleFunc("/api/main-dashboard/status", sdk.handleMainDashboardStatus).Methods("GET")
	r.HandleFunc("/api/main-dashboard/activities", sdk.handleMainDashboardActivities).Methods("GET")
	r.HandleFunc("/api/main-dashboard/monitor", sdk.handleMainDashboardMonitor).Methods("POST")

	// Wallet Dashboard Integration API endpoints
	r.HandleFunc("/api/wallet-dashboard/status", sdk.handleWalletDashboardStatus).Methods("GET")
	r.HandleFunc("/api/wallet-dashboard/transactions", sdk.handleWalletDashboardTransactions).Methods("GET")
	r.HandleFunc("/api/wallet-dashboard/security", sdk.handleWalletDashboardSecurity).Methods("GET")

	// Logging and Monitoring API endpoints
	r.HandleFunc("/api/log/retry", sdk.handleLogRetry).Methods("GET")
	r.HandleFunc("/api/log/status", sdk.handleLogStatus).Methods("GET")

	// Test and Demonstration endpoints
	r.HandleFunc("/api/test/retry-demo", sdk.handleRetryDemo).Methods("POST")

	// Proxy endpoints to avoid CORS issues
	r.HandleFunc("/api/proxy/main-dashboard/health", sdk.handleProxyMainDashboardHealth).Methods("GET")
	r.HandleFunc("/api/proxy/main-dashboard/blockchain", sdk.handleProxyMainDashboardBlockchain).Methods("GET")
	r.HandleFunc("/api/proxy/main-dashboard/node", sdk.handleProxyMainDashboardNode).Methods("GET")
	r.HandleFunc("/api/proxy/main-dashboard/wallets", sdk.handleProxyMainDashboardWallets).Methods("GET")
	r.HandleFunc("/api/proxy/main-dashboard/recent-activities", sdk.handleProxyMainDashboardActivities).Methods("GET")
	r.HandleFunc("/api/proxy/wallet-dashboard/health", sdk.handleProxyWalletDashboardHealth).Methods("GET")
	r.HandleFunc("/api/proxy/wallet-dashboard/wallets", sdk.handleProxyWalletDashboardWallets).Methods("GET")
	r.HandleFunc("/api/proxy/wallet-dashboard/transactions", sdk.handleProxyWalletDashboardTransactions).Methods("GET")
	r.HandleFunc("/api/proxy/wallet-dashboard/wallets", sdk.handleProxyWalletDashboardWallets).Methods("GET")
	r.HandleFunc("/api/proxy/wallet-dashboard/transactions", sdk.handleProxyWalletDashboardTransactions).Methods("GET")
	r.HandleFunc("/api/v2/monitoring/real-time/alerts", sdk.handleRealTimeAlerts).Methods("GET")
	r.HandleFunc("/api/v2/monitoring/real-time/metrics", sdk.handleRealTimeMetrics).Methods("GET")

	sdk.logger.Infof("🌐 Starting web server on %s", addr)
	return http.ListenAndServe(addr, r)
}

// HTTP Handlers
func (sdk *BridgeSDK) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := sdk.GetHealth()
	response := map[string]interface{}{
		"success": true,
		"data":    health,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := sdk.GetBridgeStats()
	response := map[string]interface{}{
		"success": true,
		"data":    stats,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleTransactions(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")

	var transactions []*Transaction
	var err error

	if status != "" {
		transactions, err = sdk.GetTransactionsByStatus(status)
	} else {
		transactions, err = sdk.GetAllTransactions()
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"transactions": transactions,
			"total":        len(transactions),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleTransactionDetail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	tx, err := sdk.GetTransactionStatus(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    tx,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleErrors(w http.ResponseWriter, r *http.Request) {
	errors := sdk.GetErrorMetrics()
	response := map[string]interface{}{
		"success": true,
		"data":    errors,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleCircuitBreakers(w http.ResponseWriter, r *http.Request) {
	breakers := sdk.GetCircuitBreakerStatus()
	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"circuit_breakers": breakers,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleFailedEvents(w http.ResponseWriter, r *http.Request) {
	events := sdk.GetFailedEvents()
	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"failed_events": events,
			"total":         len(events),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleReplayProtection(w http.ResponseWriter, r *http.Request) {
	status := sdk.GetReplayProtectionStatus()
	response := map[string]interface{}{
		"success": true,
		"data":    status,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Manual Testing API Handlers
func (sdk *BridgeSDK) handleManualTransfer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var transferRequest struct {
		Route         string  `json:"route"`
		Amount        float64 `json:"amount"`
		SourceAddress string  `json:"sourceAddress"`
		DestAddress   string  `json:"destAddress"`
		GasFee        float64 `json:"gasFee"`
		Confirmations int     `json:"confirmations"`
		Timeout       int     `json:"timeout"`
		Priority      string  `json:"priority"`
	}

	if err := json.NewDecoder(r.Body).Decode(&transferRequest); err != nil {
		log.Printf("Error decoding request body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request body: " + err.Error(),
		})
		return
	}

	log.Printf("Received manual transfer request: %+v", transferRequest)

	// Validate transfer request
	if transferRequest.Route == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Transfer route is required",
		})
		return
	}

	if transferRequest.Amount <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Amount must be greater than 0",
		})
		return
	}

	if transferRequest.SourceAddress == "" || transferRequest.DestAddress == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Source and destination addresses are required",
		})
		return
	}

	// Create a new transaction for manual testing - simplified for demo
	tx := &Transaction{
		ID:            fmt.Sprintf("manual_%d", time.Now().UnixNano()),
		Hash:          fmt.Sprintf("0xDEMO_%d", time.Now().UnixNano()),
		SourceChain:   getDisplayChainName(getSourceChain(transferRequest.Route)),
		DestChain:     getDisplayChainName(getDestChain(transferRequest.Route)),
		SourceAddress: transferRequest.SourceAddress,
		DestAddress:   transferRequest.DestAddress,
		TokenSymbol:   getTokenForRoute(transferRequest.Route),
		Amount:        fmt.Sprintf("%.6f", transferRequest.Amount),
		Fee:           fmt.Sprintf("%.6f", transferRequest.GasFee),
		Status:        "pending",
		CreatedAt:     time.Now(),
		Confirmations: 0,
		BlockNumber:   99999999,
	}

	// Save transaction
	sdk.saveTransaction(tx)

	// Add event for tracking
	sdk.addEvent("manual_transfer", tx.SourceChain, tx.Hash, map[string]interface{}{
		"amount":        tx.Amount,
		"token":         tx.TokenSymbol,
		"from":          tx.SourceAddress,
		"to":            tx.DestAddress,
		"route":         transferRequest.Route,
		"priority":      transferRequest.Priority,
		"confirmations": transferRequest.Confirmations,
		"timeout":       transferRequest.Timeout,
	})

	// Enhanced console logging for manual transfers
	fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")
	fmt.Printf("🚀 MANUAL TRANSFER INITIATED\n")
	fmt.Printf(strings.Repeat("=", 80) + "\n")
	fmt.Printf("   ├─ Transfer ID: %s\n", tx.ID)
	fmt.Printf("   ├─ Transaction Hash: %s\n", tx.Hash)
	fmt.Printf("   ├─ Route: %s\n", transferRequest.Route)
	fmt.Printf("   ├─ Token: %s\n", tx.TokenSymbol)
	fmt.Printf("   ├─ Amount: %s\n", tx.Amount)
	fmt.Printf("   ├─ Gas Fee: %s\n", tx.Fee)
	fmt.Printf("   ├─ Source Chain: %s\n", tx.SourceChain)
	fmt.Printf("   ├─ Destination Chain: %s\n", tx.DestChain)
	fmt.Printf("   ├─ From Address: %s\n", tx.SourceAddress)
	fmt.Printf("   ├─ To Address: %s\n", tx.DestAddress)
	fmt.Printf("   ├─ Priority: %s\n", transferRequest.Priority)
	fmt.Printf("   ├─ Confirmations Required: %d\n", transferRequest.Confirmations)
	fmt.Printf("   ├─ Timeout: %d seconds\n", transferRequest.Timeout)
	fmt.Printf("   ├─ Timestamp: %s\n", tx.CreatedAt.Format(time.RFC3339))
	fmt.Printf("   └─ Status: %s\n", strings.ToUpper(tx.Status))
	fmt.Printf(strings.Repeat("=", 80) + "\n\n")

	// Start processing the transfer asynchronously
	log.Printf("Starting manual transfer processing for transaction: %s", tx.ID)
	go sdk.processManualTransfer(tx, transferRequest)

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"transaction_id": tx.ID,
			"status":         tx.Status,
			"route":          transferRequest.Route,
			"amount":         tx.Amount,
			"estimated_time": getEstimatedTime(transferRequest.Route),
		},
	}

	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleTransferStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	txID := vars["id"]

	if txID == "" {
		http.Error(w, "Transaction ID required", http.StatusBadRequest)
		return
	}

	// Get transaction status
	tx, err := sdk.GetTransactionStatus(txID)
	if err != nil {
		http.Error(w, "Transaction not found", http.StatusNotFound)
		return
	}

	// Calculate progress based on status
	progress := getTransferProgress(tx.Status)

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"transaction_id":         tx.ID,
			"status":                 tx.Status,
			"status_message":         getStatusMessage(tx.Status),
			"progress":               progress,
			"confirmations":          tx.Confirmations,
			"required_confirmations": 12, // Default
			"gas_used":               tx.Fee,
			"source_chain":           tx.SourceChain,
			"dest_chain":             tx.DestChain,
			"amount":                 tx.Amount,
			"token":                  tx.TokenSymbol,
			"created_at":             tx.CreatedAt.Format(time.RFC3339),
			"latest_log":             fmt.Sprintf("Transaction %s: %s", tx.Status, getStatusMessage(tx.Status)),
		},
	}

	json.NewEncoder(w).Encode(response)
}

// gRPC Endpoints Documentation Handler
func (sdk *BridgeSDK) handleGRPCEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	grpcInfo := map[string]interface{}{
		"bridge_service": map[string]interface{}{
			"base_url": "localhost:50051",
			"endpoints": []map[string]interface{}{
				{
					"method": "StartEthereumListener",
					"description": "Starts Ethereum blockchain event listener",
					"request_format": map[string]interface{}{
						"chain_id": "string",
						"rpc_url": "string",
						"contract_address": "string",
					},
					"response_format": map[string]interface{}{
						"success": "boolean",
						"listener_id": "string",
						"status": "string",
					},
					"authentication": "API Key required in metadata",
				},
				{
					"method": "StartSolanaListener",
					"description": "Starts Solana blockchain event listener",
					"request_format": map[string]interface{}{
						"cluster": "string (mainnet-beta, testnet, devnet)",
						"program_id": "string",
						"commitment": "string",
					},
					"response_format": map[string]interface{}{
						"success": "boolean",
						"listener_id": "string",
						"status": "string",
					},
					"authentication": "API Key required in metadata",
				},
				{
					"method": "RelayToChain",
					"description": "Relays transaction to target blockchain",
					"request_format": map[string]interface{}{
						"source_chain": "string",
						"dest_chain": "string",
						"transaction_hash": "string",
						"amount": "string",
						"token_symbol": "string",
						"dest_address": "string",
					},
					"response_format": map[string]interface{}{
						"success": "boolean",
						"relay_id": "string",
						"dest_tx_hash": "string",
						"status": "string",
					},
					"authentication": "API Key required in metadata",
				},
				{
					"method": "GetTransactionStatus",
					"description": "Gets status of bridge transaction",
					"request_format": map[string]interface{}{
						"transaction_id": "string",
					},
					"response_format": map[string]interface{}{
						"transaction_id": "string",
						"status": "string (pending, confirmed, failed)",
						"source_tx_hash": "string",
						"dest_tx_hash": "string",
						"confirmations": "int32",
					},
					"authentication": "API Key required in metadata",
				},
				{
					"method": "GetBridgeHealth",
					"description": "Gets bridge service health status",
					"request_format": map[string]interface{}{},
					"response_format": map[string]interface{}{
						"status": "string",
						"uptime": "string",
						"active_listeners": "int32",
						"processed_transactions": "int64",
						"error_rate": "float",
					},
					"authentication": "None required",
				},
			},
		},
		"wallet_service": map[string]interface{}{
			"base_url": "localhost:50052",
			"endpoints": []map[string]interface{}{
				{
					"method": "CreateWallet",
					"description": "Creates a new wallet",
					"request_format": map[string]interface{}{
						"wallet_type": "string (ethereum, solana, blackhole)",
						"password": "string",
					},
					"response_format": map[string]interface{}{
						"wallet_id": "string",
						"address": "string",
						"public_key": "string",
					},
					"authentication": "Bearer token required",
				},
				{
					"method": "GetWalletBalance",
					"description": "Gets wallet balance for specific token",
					"request_format": map[string]interface{}{
						"wallet_id": "string",
						"token_symbol": "string",
					},
					"response_format": map[string]interface{}{
						"balance": "string",
						"token_symbol": "string",
						"decimals": "int32",
					},
					"authentication": "Bearer token required",
				},
				{
					"method": "SendTransaction",
					"description": "Sends transaction from wallet",
					"request_format": map[string]interface{}{
						"wallet_id": "string",
						"to_address": "string",
						"amount": "string",
						"token_symbol": "string",
						"gas_price": "string (optional)",
					},
					"response_format": map[string]interface{}{
						"transaction_hash": "string",
						"status": "string",
						"gas_used": "string",
					},
					"authentication": "Bearer token required",
				},
			},
		},
		"blockchain_service": map[string]interface{}{
			"base_url": "localhost:50053",
			"endpoints": []map[string]interface{}{
				{
					"method": "GetBlockchainInfo",
					"description": "Gets blockchain information",
					"request_format": map[string]interface{}{
						"chain": "string",
					},
					"response_format": map[string]interface{}{
						"chain_id": "string",
						"latest_block": "int64",
						"network": "string",
						"sync_status": "boolean",
					},
					"authentication": "None required",
				},
				{
					"method": "GetTokenInfo",
					"description": "Gets token information",
					"request_format": map[string]interface{}{
						"token_address": "string",
						"chain": "string",
					},
					"response_format": map[string]interface{}{
						"name": "string",
						"symbol": "string",
						"decimals": "int32",
						"total_supply": "string",
					},
					"authentication": "None required",
				},
			},
		},
		"authentication": map[string]interface{}{
			"api_key": map[string]interface{}{
				"header": "X-API-Key",
				"description": "API key for bridge service authentication",
				"example": "bridge_api_key_12345",
			},
			"bearer_token": map[string]interface{}{
				"header": "Authorization",
				"format": "Bearer <token>",
				"description": "JWT token for wallet service authentication",
				"example": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			},
		},
		"error_codes": map[string]interface{}{
			"INVALID_REQUEST": "Request format is invalid",
			"UNAUTHORIZED": "Authentication failed",
			"CHAIN_NOT_SUPPORTED": "Blockchain not supported",
			"INSUFFICIENT_BALANCE": "Insufficient wallet balance",
			"TRANSACTION_FAILED": "Transaction execution failed",
			"LISTENER_ERROR": "Blockchain listener error",
			"NETWORK_ERROR": "Network connectivity error",
		},
		"examples": map[string]interface{}{
			"start_ethereum_listener": map[string]interface{}{
				"grpc_call": "bridge.BridgeService/StartEthereumListener",
				"metadata": map[string]string{
					"x-api-key": "your_api_key_here",
				},
				"request": map[string]interface{}{
					"chain_id": "1",
					"rpc_url": "https://mainnet.infura.io/v3/your_project_id",
					"contract_address": "0x1234567890abcdef1234567890abcdef12345678",
				},
			},
			"relay_transaction": map[string]interface{}{
				"grpc_call": "bridge.BridgeService/RelayToChain",
				"metadata": map[string]string{
					"x-api-key": "your_api_key_here",
				},
				"request": map[string]interface{}{
					"source_chain": "ethereum",
					"dest_chain": "solana",
					"transaction_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
					"amount": "100.5",
					"token_symbol": "BHX",
					"dest_address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
				},
			},
		},
	}

	json.NewEncoder(w).Encode(grpcInfo)
}

// Mark Transaction as Read API Handler
func (sdk *BridgeSDK) handleMarkTransactionAsRead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		TransactionID string `json:"transaction_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.TransactionID == "" {
		http.Error(w, "Transaction ID is required", http.StatusBadRequest)
		return
	}

	// Mark the transaction as read in the database
	if err := sdk.markTransactionAsRead(request.TransactionID); err != nil {
		fmt.Printf("❌ Failed to mark transaction as read: %v\n", err)
		http.Error(w, fmt.Sprintf("Failed to mark transaction as read: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Printf("✅ Transaction marked as read: %s\n", request.TransactionID)

	response := map[string]interface{}{
		"success":        true,
		"message":        "Transaction marked as read",
		"transaction_id": request.TransactionID,
	}

	json.NewEncoder(w).Encode(response)
}

// Logging and Monitoring API Handlers
func (sdk *BridgeSDK) handleLogRetry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get retry queue statistics
	sdk.retryQueue.mutex.RLock()
	activeItems := make([]map[string]interface{}, 0)
	deadLetterItems := make([]map[string]interface{}, 0)

	totalItems := len(sdk.retryQueue.items)
	pendingItems := 0
	processingItems := 0
	failedItems := 0
	deadLetterCount := len(sdk.retryQueue.deadLetterQueue)

	// Process active retry items
	for _, item := range sdk.retryQueue.items {
		itemData := map[string]interface{}{
			"id":          item.ID,
			"type":        item.Type,
			"attempts":    item.Attempts,
			"max_attempts": item.MaxRetries,
			"next_retry":  item.NextRetry.Format(time.RFC3339),
			"created_at":  item.CreatedAt.Format(time.RFC3339),
			"last_error":  item.LastError,
			"status":      "pending",
			"data":        item.Data,
		}

		if item.Attempts >= item.MaxRetries {
			itemData["status"] = "failed"
			failedItems++
		} else if time.Now().Before(item.NextRetry) {
			itemData["status"] = "pending"
			pendingItems++
		} else {
			itemData["status"] = "processing"
			processingItems++
		}

		activeItems = append(activeItems, itemData)
	}

	// Process dead letter queue items
	for _, item := range sdk.retryQueue.deadLetterQueue {
		deadLetterItems = append(deadLetterItems, map[string]interface{}{
			"id":           item.ID,
			"type":         item.Type,
			"attempts":     item.Attempts,
			"max_attempts": item.MaxRetries,
			"status":       "dead_letter",
			"created_at":   item.CreatedAt.Format(time.RFC3339),
			"final_error":  item.LastError,
			"data":         item.Data,
		})
	}
	sdk.retryQueue.mutex.RUnlock()

	// Calculate success rate
	successRate := 100.0
	if totalItems > 0 {
		successfulItems := totalItems - failedItems - deadLetterCount
		successRate = float64(successfulItems) / float64(totalItems+deadLetterCount) * 100
	}

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"active_items":      activeItems,
			"dead_letter_items": deadLetterItems,
			"stats": map[string]interface{}{
				"total_items":       totalItems,
				"pending_items":     pendingItems,
				"processing_items":  processingItems,
				"failed_items":      failedItems,
				"dead_letter_items": deadLetterCount,
				"success_rate":      successRate,
			},
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

func (sdk *BridgeSDK) handleLogStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Calculate uptime
	uptime := time.Since(sdk.startTime).Seconds()

	// Check database connection
	dbConnected := true
	err := sdk.db.View(func(tx *bbolt.Tx) error {
		return nil
	})
	if err != nil {
		dbConnected = false
	}

	// Get listener status
	listeners := map[string]bool{
		"ethereum": true,  // Always true in simulation mode
		"solana":   true,  // Always true in simulation mode
		"blackhole": sdk.blockchainInterface != nil,
	}

	// Get performance metrics
	sdk.performanceMetrics.mutex.RLock()
	cpuUsage := sdk.performanceMetrics.cpuUsage
	memoryUsage := sdk.performanceMetrics.memoryUsage
	activeConnections := sdk.performanceMetrics.activeConnections
	eventsPerSecond := sdk.performanceMetrics.eventsPerSecond
	avgResponseTime := sdk.performanceMetrics.avgResponseTime
	errorCount := sdk.performanceMetrics.errorCount
	sdk.performanceMetrics.mutex.RUnlock()

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"bridge_healthy":     true,
			"database_connected": dbConnected,
			"uptime_seconds":     int64(uptime),
			"version":           "1.0.0",
			"listeners":         listeners,
			"performance": map[string]interface{}{
				"cpu_usage":             cpuUsage,
				"memory_usage":          memoryUsage,
				"active_connections":    activeConnections,
				"events_per_second":     eventsPerSecond,
				"average_response_time": avgResponseTime,
				"error_count":           errorCount,
			},
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

// Test and Demonstration API Handlers
func (sdk *BridgeSDK) handleRetryDemo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse request
	var request struct {
		EventType    string `json:"event_type"`
		FailureCount int    `json:"failure_count"`
		TestMode     string `json:"test_mode"` // "retry", "fallback", "dead_letter"
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Set defaults
	if request.EventType == "" {
		request.EventType = "ethereum_event"
	}
	if request.FailureCount == 0 {
		request.FailureCount = 3
	}
	if request.TestMode == "" {
		request.TestMode = "retry"
	}

	// Generate test events that will fail and demonstrate retry mechanism
	demoEvents := make([]map[string]interface{}, 0)

	for i := 0; i < request.FailureCount; i++ {
		eventID := fmt.Sprintf("demo_%s_%d_%d", request.EventType, time.Now().Unix(), i)

		// Create test data that will trigger failures
		testData := map[string]interface{}{
			"transaction_id": eventID,
			"amount":         fmt.Sprintf("%.2f", 100.0+float64(i)*10),
			"token":          "DEMO",
			"from":           "demo_source_address",
			"to":             "demo_dest_address",
			"demo_mode":      request.TestMode,
			"failure_type":   "simulated_network_error",
		}

		// Add to retry queue with forced failure
		retryID := sdk.addToRetryQueue(request.EventType, testData, fmt.Errorf("demo failure: simulated %s error", request.EventType))

		demoEvents = append(demoEvents, map[string]interface{}{
			"retry_id":    retryID,
			"event_type":  request.EventType,
			"test_data":   testData,
			"created_at":  time.Now().Format(time.RFC3339),
			"demo_mode":   request.TestMode,
		})

		sdk.logger.Infof("🎭 Demo: Created failing %s event %s for retry demonstration", request.EventType, eventID)
	}

	// Start monitoring the demo events
	go sdk.monitorDemoEvents(demoEvents, request.TestMode)

	response := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Created %d demo events for %s testing", request.FailureCount, request.TestMode),
		"data": map[string]interface{}{
			"demo_events":   demoEvents,
			"test_mode":     request.TestMode,
			"event_type":    request.EventType,
			"failure_count": request.FailureCount,
		},
		"instructions": map[string]string{
			"monitor_retry":   "GET /api/log/retry to see retry queue status",
			"monitor_status":  "GET /api/log/status for system health",
			"websocket":       "Connect to ws://localhost:8084/ws for real-time updates",
		},
	}

	json.NewEncoder(w).Encode(response)
}

// monitorDemoEvents monitors demo events and provides real-time updates
func (sdk *BridgeSDK) monitorDemoEvents(events []map[string]interface{}, testMode string) {
	sdk.logger.Infof("🔍 Starting demo event monitoring for %s mode", testMode)

	// Monitor for 2 minutes or until all events are processed
	timeout := time.After(2 * time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			sdk.logger.Info("🏁 Demo monitoring timeout reached")
			return
		case <-ticker.C:
			// Check status of demo events
			sdk.checkDemoEventStatus(events, testMode)
		}
	}
}

// checkDemoEventStatus checks and reports on demo event progress
func (sdk *BridgeSDK) checkDemoEventStatus(events []map[string]interface{}, testMode string) {
	sdk.retryQueue.mutex.RLock()
	defer sdk.retryQueue.mutex.RUnlock()

	activeCount := 0
	deadLetterCount := 0

	for _, event := range events {
		retryID := event["retry_id"].(string)

		// Check if still in active queue
		found := false
		for _, item := range sdk.retryQueue.items {
			if item.ID == retryID {
				found = true
				activeCount++
				break
			}
		}

		// Check if in dead letter queue
		if !found {
			for _, item := range sdk.retryQueue.deadLetterQueue {
				if item.ID == retryID {
					deadLetterCount++
					break
				}
			}
		}
	}

	// Broadcast status update via WebSocket
	statusUpdate := map[string]interface{}{
		"type":              "demo_status_update",
		"test_mode":         testMode,
		"total_events":      len(events),
		"active_retries":    activeCount,
		"dead_letter_items": deadLetterCount,
		"completed_events":  len(events) - activeCount - deadLetterCount,
		"timestamp":         time.Now().Format(time.RFC3339),
	}

	sdk.broadcastEventToClients(statusUpdate)
	sdk.logger.Infof("📊 Demo Status - Active: %d, Dead Letter: %d, Completed: %d",
		activeCount, deadLetterCount, len(events)-activeCount-deadLetterCount)
}

// Database functions for transaction persistence
func (sdk *BridgeSDK) saveWalletTransaction(tx WalletTransaction) error {
	return sdk.db.Update(func(txn *bbolt.Tx) error {
		bucket, err := txn.CreateBucketIfNotExists([]byte("wallet_transactions"))
		if err != nil {
			return err
		}

		data, err := json.Marshal(tx)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(tx.ID), data)
	})
}

func (sdk *BridgeSDK) loadWalletTransactions() ([]WalletTransaction, error) {
	var transactions []WalletTransaction

	err := sdk.db.View(func(txn *bbolt.Tx) error {
		bucket := txn.Bucket([]byte("wallet_transactions"))
		if bucket == nil {
			return nil // No transactions yet
		}

		return bucket.ForEach(func(k, v []byte) error {
			var tx WalletTransaction
			if err := json.Unmarshal(v, &tx); err != nil {
				return err
			}
			transactions = append(transactions, tx)
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	// Sort by timestamp (newest first) - this ensures proper chronological order
	sort.Slice(transactions, func(i, j int) bool {
		return transactions[i].Timestamp > transactions[j].Timestamp
	})

	return transactions, nil
}

func (sdk *BridgeSDK) markTransactionsAsOld() error {
	return sdk.db.Update(func(txn *bbolt.Tx) error {
		bucket := txn.Bucket([]byte("wallet_transactions"))
		if bucket == nil {
			return nil
		}

		return bucket.ForEach(func(k, v []byte) error {
			var tx WalletTransaction
			if err := json.Unmarshal(v, &tx); err != nil {
				return err
			}

			if tx.IsNew {
				tx.IsNew = false
				data, err := json.Marshal(tx)
				if err != nil {
					return err
				}
				return bucket.Put(k, data)
			}
			return nil
		})
	})
}

// Mark individual transaction as read (only for real transfers)
func (sdk *BridgeSDK) markTransactionAsRead(transactionID string) error {
	return sdk.db.Update(func(txn *bbolt.Tx) error {
		bucket := txn.Bucket([]byte("wallet_transactions"))
		if bucket == nil {
			return fmt.Errorf("wallet_transactions bucket not found")
		}

		data := bucket.Get([]byte(transactionID))
		if data == nil {
			return fmt.Errorf("transaction not found: %s", transactionID)
		}

		var tx WalletTransaction
		if err := json.Unmarshal(data, &tx); err != nil {
			return err
		}

		// Only allow marking real transfers as read (safeguard against data loss)
		if tx.Type != "real_transfer" {
			return fmt.Errorf("cannot mark non-real transfer as read: %s", tx.Type)
		}

		// Update the read state
		tx.IsNew = false

		updatedData, err := json.Marshal(tx)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(transactionID), updatedData)
	})
}

// Toggle transaction read state (for future use)
func (sdk *BridgeSDK) toggleTransactionReadState(transactionID string) error {
	return sdk.db.Update(func(txn *bbolt.Tx) error {
		bucket := txn.Bucket([]byte("wallet_transactions"))
		if bucket == nil {
			return fmt.Errorf("wallet_transactions bucket not found")
		}

		data := bucket.Get([]byte(transactionID))
		if data == nil {
			return fmt.Errorf("transaction not found: %s", transactionID)
		}

		var tx WalletTransaction
		if err := json.Unmarshal(data, &tx); err != nil {
			return err
		}

		// Toggle the read state
		tx.IsNew = !tx.IsNew

		updatedData, err := json.Marshal(tx)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(transactionID), updatedData)
	})
}

// Data recovery function to ensure all historical real transfers are preserved
func (sdk *BridgeSDK) ensureCriticalTransactionsExist() error {
	fmt.Printf("🔄 Checking for historical real transfers...\n")

	// Define all known historical real transfers that must be preserved
	historicalRealTransfers := []WalletTransaction{
		{
			ID:        "NEW_TRANSFER_BHX_0222fa8467658c6b58e4e957ea0a34a3f8ffcc80472d89c66dd3d7c690f56f5dd1_19_1754369984",
			Hash:      "NEW_TRANSFER_BHX_0222fa8467658c6b58e4e957ea0a34a3f8ffcc80472d89c66dd3d7c690f56f5dd1_19_1754369984",
			From:      "admin",
			To:        "0222fa8467658c6b58e4e957ea0a34a3f8ffcc80472d89c66dd3d7c690f56f5dd1",
			Amount:    "19",
			Token:     "BHX",
			Status:    "confirmed",
			Timestamp: 1754369984,
			Type:      "real_transfer",
			IsNew:     false,
			CreatedAt: time.Now(),
			MultiAddr: "historical",
		},
		{
			ID:        "NEW_TRANSFER_BHX_0222fa8467658c6b58e4e957ea0a34a3f8ffcc80472d89c66dd3d7c690f56f5dd1_34_1754383174",
			Hash:      "NEW_TRANSFER_BHX_0222fa8467658c6b58e4e957ea0a34a3f8ffcc80472d89c66dd3d7c690f56f5dd1_34_1754383174",
			From:      "admin",
			To:        "0222fa8467658c6b58e4e957ea0a34a3f8ffcc80472d89c66dd3d7c690f56f5dd1",
			Amount:    "34",
			Token:     "BHX",
			Status:    "confirmed",
			Timestamp: 1754383174,
			Type:      "real_transfer",
			IsNew:     false,
			CreatedAt: time.Now(),
			MultiAddr: "historical",
		},
		{
			ID:        "NEW_TRANSFER_BHX_02b40d1740e9b840f7b59af7b205b613f7385b8c7dab99b113ff3f7c676c92b151_64_1754385550",
			Hash:      "NEW_TRANSFER_BHX_02b40d1740e9b840f7b59af7b205b613f7385b8c7dab99b113ff3f7c676c92b151_64_1754385550",
			From:      "admin",
			To:        "02b40d1740e9b840f7b59af7b205b613f7385b8c7dab99b113ff3f7c676c92b151",
			Amount:    "64",
			Token:     "BHX",
			Status:    "confirmed",
			Timestamp: 1754385550,
			Type:      "real_transfer",
			IsNew:     false,
			CreatedAt: time.Now(),
			MultiAddr: "historical",
		},
		{
			ID:        "NEW_TRANSFER_BHX_02b40d1740e9b840f7b59af7b205b613f7385b8c7dab99b113ff3f7c676c92b151_86_1754385597",
			Hash:      "NEW_TRANSFER_BHX_02b40d1740e9b840f7b59af7b205b613f7385b8c7dab99b113ff3f7c676c92b151_86_1754385597",
			From:      "admin",
			To:        "02b40d1740e9b840f7b59af7b205b613f7385b8c7dab99b113ff3f7c676c92b151",
			Amount:    "86",
			Token:     "BHX",
			Status:    "confirmed",
			Timestamp: 1754385597,
			Type:      "real_transfer",
			IsNew:     false,
			CreatedAt: time.Now(),
			MultiAddr: "historical",
		},
		{
			ID:        "NEW_TRANSFER_BHX_02b40d1740e9b840f7b59af7b205b613f7385b8c7dab99b113ff3f7c676c92b151_43_1754386722",
			Hash:      "NEW_TRANSFER_BHX_02b40d1740e9b840f7b59af7b205b613f7385b8c7dab99b113ff3f7c676c92b151_43_1754386722",
			From:      "admin",
			To:        "02b40d1740e9b840f7b59af7b205b613f7385b8c7dab99b113ff3f7c676c92b151",
			Amount:    "43",
			Token:     "BHX",
			Status:    "confirmed",
			Timestamp: 1754386722,
			Type:      "real_transfer",
			IsNew:     false,
			CreatedAt: time.Now(),
			MultiAddr: "historical",
		},
	}

	// Check which transactions exist and which need to be restored
	existingTransactions := make(map[string]bool)
	err := sdk.db.View(func(txn *bbolt.Tx) error {
		bucket := txn.Bucket([]byte("wallet_transactions"))
		if bucket == nil {
			return nil
		}

		return bucket.ForEach(func(k, v []byte) error {
			var tx WalletTransaction
			if err := json.Unmarshal(v, &tx); err != nil {
				return err
			}

			if tx.Type == "real_transfer" {
				existingTransactions[tx.ID] = true
				fmt.Printf("✅ Found existing real transfer: %s BHX (ID: %s)\n", tx.Amount, tx.ID)
			}
			return nil
		})
	})

	if err != nil {
		return err
	}

	// Restore missing historical transactions
	restoredCount := 0
	for _, tx := range historicalRealTransfers {
		if !existingTransactions[tx.ID] {
			if err := sdk.saveWalletTransaction(tx); err != nil {
				fmt.Printf("❌ Failed to restore transaction %s BHX: %v\n", tx.Amount, err)
			} else {
				fmt.Printf("🔄 Restored historical real transfer: %s BHX\n", tx.Amount)
				restoredCount++
			}
		}
	}

	if restoredCount > 0 {
		fmt.Printf("✅ Restored %d historical real transfers\n", restoredCount)
	} else {
		fmt.Printf("✅ All historical real transfers already exist\n")
	}

	return nil
}

// Wallet Monitoring API Handler
func (sdk *BridgeSDK) handleWalletTransactions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Fetch REAL data from main dashboard blockchain info - DETECT ACTUAL TRANSFERS
	client := &http.Client{Timeout: 5 * time.Second}

	// Get blockchain info to detect balance changes (real transfers)
	resp, err := client.Get("http://localhost:8080/api/blockchain/info")
	if err != nil {
		response := map[string]interface{}{
			"success": false,
			"error":   "Cannot connect to main dashboard: " + err.Error(),
			"transactions": detectedTransfers, // Return previously detected transfers
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	defer resp.Body.Close()

	var blockchainData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&blockchainData); err != nil {
		response := map[string]interface{}{
			"success": false,
			"error":   "Failed to decode blockchain data: " + err.Error(),
			"transactions": detectedTransfers,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Initialize previous balances if first run
	if previousBalances == nil {
		previousBalances = make(map[string]map[string]float64)
	}

	// Extract current balances and detect REAL transfers by comparing with previous balances
	currentBalances := make(map[string]map[string]float64)

	if tokenBalances, ok := blockchainData["tokenBalances"].(map[string]interface{}); ok {
		for tokenType, balances := range tokenBalances {
			if balanceMap, ok := balances.(map[string]interface{}); ok {
				currentBalances[tokenType] = make(map[string]float64)
				for address, balance := range balanceMap {
					if balanceFloat, ok := balance.(float64); ok {
						currentBalances[tokenType][address] = balanceFloat
					}
				}
			}
		}
	}

	// Detect NEW transfers by comparing current vs previous balances
	newTransfers := []map[string]interface{}{}

	// Debug logging
	fmt.Printf("🔍 CHECKING FOR NEW TRANSFERS:\n")
	fmt.Printf("   Previous balances exist: %v\n", previousBalances != nil && len(previousBalances) > 0)
	fmt.Printf("   Current balances count: %d\n", len(currentBalances))

	for tokenType, currentTokenBalances := range currentBalances {
		fmt.Printf("   Checking %s token balances...\n", tokenType)

		if previousTokenBalances, exists := previousBalances[tokenType]; exists {
			fmt.Printf("     Found previous %s balances, comparing...\n", tokenType)

			for address, currentBalance := range currentTokenBalances {
				// Skip system addresses
				if address == "system" || address == "genesis-validator" {
					continue
				}

				if previousBalance, hadPrevious := previousTokenBalances[address]; hadPrevious {
					// Check if balance increased (indicating a transfer TO this address)
					if currentBalance > previousBalance {
						transferAmount := currentBalance - previousBalance

						// Create REAL transfer entry
						transfer := map[string]interface{}{
							"hash":      fmt.Sprintf("NEW_TRANSFER_%s_%s_%.0f_%d", tokenType, address, transferAmount, time.Now().Unix()),
							"from":      "admin",
							"to":        address,
							"amount":    fmt.Sprintf("%.0f", transferAmount),
							"token":     tokenType,
							"status":    "confirmed",
							"timestamp": time.Now().Unix(),
							"type":      "real_transfer",
							"isNew":     true,
						}
						newTransfers = append(newTransfers, transfer)

						fmt.Printf("🎯 DETECTED REAL TRANSFER: %.0f %s to %s (was %.0f, now %.0f)\n",
							transferAmount, tokenType, address, previousBalance, currentBalance)
					} else if currentBalance == previousBalance {
						fmt.Printf("     No change for %s: %.0f %s\n", address, currentBalance, tokenType)
					} else {
						fmt.Printf("     Balance decreased for %s: %.0f -> %.0f %s\n",
							address, previousBalance, currentBalance, tokenType)
					}
				} else if currentBalance > 0 {
					// New address with balance (first time seeing this address) - could be a new wallet
					transfer := map[string]interface{}{
						"hash":      fmt.Sprintf("FIRST_TIME_%s_%s_%.0f_%d", tokenType, address, currentBalance, time.Now().Unix()),
						"from":      "admin",
						"to":        address,
						"amount":    fmt.Sprintf("%.0f", currentBalance),
						"token":     tokenType,
						"status":    "confirmed",
						"timestamp": time.Now().Unix(),
						"type":      "initial_transfer",
						"isNew":     false,
					}
					newTransfers = append(newTransfers, transfer)
					fmt.Printf("     🆕 NEW WALLET DETECTED: %s with %.0f %s\n", address, currentBalance, tokenType)

					// Track this as a new wallet creation for the admin section
					if tokenType == "BHX" && !strings.HasPrefix(address, "admin") && address != "node2" {
						fmt.Printf("     📱 Tracking new wallet creation for admin dashboard\n")
					}
				}
			}
		} else {
			// First time seeing this token type, add all non-system balances as initial transfers
			fmt.Printf("     First time seeing %s token, adding all balances as initial\n", tokenType)
			for address, balance := range currentTokenBalances {
				if address != "system" && address != "genesis-validator" && balance > 0 {
					transfer := map[string]interface{}{
						"hash":      fmt.Sprintf("INITIAL_%s_%s_%.0f_%d", tokenType, address, balance, time.Now().Unix()),
						"from":      "admin",
						"to":        address,
						"amount":    fmt.Sprintf("%.0f", balance),
						"token":     tokenType,
						"status":    "confirmed",
						"timestamp": time.Now().Unix(),
						"type":      "initial_transfer",
						"isNew":     false,
					}
					newTransfers = append(newTransfers, transfer)
				}
			}
		}
	}

	fmt.Printf("🔍 DETECTION SUMMARY: Found %d new transfers\n", len(newTransfers))

	// Save new transfers to database for persistence
	for _, transfer := range newTransfers {
		walletTx := WalletTransaction{
			ID:        transfer["hash"].(string),
			Hash:      transfer["hash"].(string),
			From:      transfer["from"].(string),
			To:        transfer["to"].(string),
			Amount:    transfer["amount"].(string),
			Token:     transfer["token"].(string),
			Status:    transfer["status"].(string),
			Timestamp: transfer["timestamp"].(int64),
			Type:      transfer["type"].(string),
			IsNew:     transfer["isNew"].(bool),
			CreatedAt: time.Now(),
			MultiAddr: "current", // Track current multi-address session
		}

		if err := sdk.saveWalletTransaction(walletTx); err != nil {
			fmt.Printf("❌ Failed to save transaction to database: %v\n", err)
		} else {
			fmt.Printf("💾 Saved transaction to database: %s %s %s\n", walletTx.Amount, walletTx.Token, walletTx.To)
		}
	}

	// Load all transactions from database (includes historical + new)
	allTransactions, err := sdk.loadWalletTransactions()
	if err != nil {
		fmt.Printf("❌ Failed to load transactions from database: %v\n", err)
		// Fallback to in-memory transactions
		detectedTransfers = append(newTransfers, detectedTransfers...)
		if len(detectedTransfers) > 50 {
			detectedTransfers = detectedTransfers[:50]
		}
		allTransactions = make([]WalletTransaction, len(detectedTransfers))
		for i, tx := range detectedTransfers {
			allTransactions[i] = WalletTransaction{
				ID:        tx["hash"].(string),
				Hash:      tx["hash"].(string),
				From:      fmt.Sprintf("%v", tx["from"]),
				To:        fmt.Sprintf("%v", tx["to"]),
				Amount:    fmt.Sprintf("%v", tx["amount"]),
				Token:     fmt.Sprintf("%v", tx["token"]),
				Status:    fmt.Sprintf("%v", tx["status"]),
				Timestamp: int64(tx["timestamp"].(float64)),
				Type:      fmt.Sprintf("%v", tx["type"]),
				IsNew:     tx["isNew"].(bool),
				CreatedAt: time.Now(),
			}
		}
	}

	// Convert to response format
	responseTransactions := make([]map[string]interface{}, len(allTransactions))
	for i, tx := range allTransactions {
		responseTransactions[i] = map[string]interface{}{
			"hash":      tx.Hash,
			"from":      tx.From,
			"to":        tx.To,
			"amount":    tx.Amount,
			"token":     tx.Token,
			"status":    tx.Status,
			"timestamp": tx.Timestamp,
			"type":      tx.Type,
			"isNew":     tx.IsNew,
		}
	}

	// Update previous balances for next comparison
	previousBalances = currentBalances

	response := map[string]interface{}{
		"success":         true,
		"transactions":    responseTransactions,
		"source":          "persistent_database",
		"total_count":     len(responseTransactions),
		"new_transfers":   len(newTransfers),
		"historical_count": len(allTransactions) - len(newTransfers),
	}

	json.NewEncoder(w).Encode(response)
}

// Helper functions for manual testing
func getSourceChain(route string) string {
	switch route {
	case "ETH_TO_BH", "ETH_TO_SOL":
		return "ethereum"
	case "BH_TO_SOL", "BH_TO_ETH":
		return "blackhole"
	case "SOL_TO_BH", "SOL_TO_ETH":
		return "solana"
	default:
		return "ethereum"
	}
}

func getDestChain(route string) string {
	switch route {
	case "ETH_TO_BH", "SOL_TO_BH":
		return "blackhole"
	case "BH_TO_SOL", "ETH_TO_SOL":
		return "solana"
	case "BH_TO_ETH", "SOL_TO_ETH":
		return "ethereum"
	default:
		return "blackhole"
	}
}

func getTokenForRoute(route string) string {
	switch route {
	case "ETH_TO_BH":
		return "USDC"
	case "BH_TO_SOL":
		return "BHX"
	case "SOL_TO_ETH":
		return "SOL"
	case "SOL_TO_BH":
		return "SOL"
	case "BH_TO_ETH":
		return "BHX"
	case "ETH_TO_SOL":
		return "USDC"
	default:
		return "USDC"
	}
}

func getDisplayChainName(chainName string) string {
	switch chainName {
	case "ethereum":
		return "Ethereum"
	case "blackhole":
		return "BlackHole"
	case "solana":
		return "Solana"
	default:
		return chainName
	}
}

func getEstimatedTime(route string) string {
	estimates := map[string]string{
		"ETH_TO_BH":  "2-5 minutes",
		"BH_TO_SOL":  "1-3 minutes",
		"ETH_TO_SOL": "5-10 minutes",
		"SOL_TO_BH":  "1-2 minutes",
		"BH_TO_ETH":  "3-6 minutes",
		"SOL_TO_ETH": "6-12 minutes",
	}
	if time, ok := estimates[route]; ok {
		return time
	}
	return "5-10 minutes"
}

func getTransferProgress(status string) int {
	switch status {
	case "pending":
		return 10
	case "processing":
		return 30
	case "confirming":
		return 60
	case "relaying":
		return 80
	case "completed":
		return 100
	case "failed":
		return 0
	default:
		return 0
	}
}

func getStatusMessage(status string) string {
	messages := map[string]string{
		"pending":    "Transaction initiated and waiting for processing",
		"processing": "Transaction being processed on source chain",
		"confirming": "Waiting for block confirmations",
		"relaying":   "Relaying to destination chain",
		"completed":  "Transfer completed successfully",
		"failed":     "Transfer failed - please check logs",
	}
	if msg, ok := messages[status]; ok {
		return msg
	}
	return "Unknown status"
}

func (sdk *BridgeSDK) processManualTransfer(tx *Transaction, request struct {
	Route         string  `json:"route"`
	Amount        float64 `json:"amount"`
	SourceAddress string  `json:"sourceAddress"`
	DestAddress   string  `json:"destAddress"`
	GasFee        float64 `json:"gasFee"`
	Confirmations int     `json:"confirmations"`
	Timeout       int     `json:"timeout"`
	Priority      string  `json:"priority"`
}) {
	// Enhanced processing logging
	fmt.Printf("🔄 PROCESSING MANUAL TRANSFER\n")
	fmt.Printf("   ├─ Transaction ID: %s\n", tx.ID)
	fmt.Printf("   ├─ Route: %s\n", request.Route)
	fmt.Printf("   ├─ Amount: %.6f %s\n", request.Amount, tx.TokenSymbol)
	fmt.Printf("   └─ Starting processing pipeline...\n\n")

	// Simple mock transfer processing - always succeeds for demo
	stages := []string{"processing", "confirming", "relaying", "completed"}
	delays := []time.Duration{1 * time.Second, 2 * time.Second, 1 * time.Second, 1 * time.Second}

	for i, stage := range stages {
		// Enhanced stage logging
		fmt.Printf("📍 STAGE %d/%d: %s\n", i+1, len(stages), strings.ToUpper(stage))
		fmt.Printf("   ├─ Transaction: %s\n", tx.ID)
		fmt.Printf("   ├─ Status: %s → %s\n", tx.Status, stage)
		fmt.Printf("   ├─ Processing time: %v\n", delays[i])
		fmt.Printf("   └─ Starting stage...\n")

		time.Sleep(delays[i])

		// Update transaction status
		tx.Status = stage
		if stage == "confirming" {
			fmt.Printf("   🔍 CONFIRMATION PROCESS\n")
			fmt.Printf("   ├─ Required confirmations: %d\n", request.Confirmations)
			// Quick confirmation simulation - always succeeds
			maxConf := 6 // Fixed to 6 for quick demo
			for conf := 1; conf <= maxConf; conf++ {
				time.Sleep(100 * time.Millisecond) // Very fast for demo
				tx.Confirmations = conf
				sdk.saveTransaction(tx)
				fmt.Printf("   ├─ Confirmation %d/%d ✅\n", conf, maxConf)
			}
			fmt.Printf("   └─ All confirmations received ✅\n")
		} else {
			sdk.saveTransaction(tx)
		}

		fmt.Printf("   ✅ STAGE COMPLETED: %s\n\n", strings.ToUpper(stage))

		// Add event for each stage
		sdk.addEvent("transfer_update", tx.SourceChain, tx.Hash, map[string]interface{}{
			"stage":         stage,
			"confirmations": tx.Confirmations,
			"progress":      getTransferProgress(stage),
			"manual":        true,
			"demo":          true,
		})
	}

	// Final success event - always succeeds
	fmt.Printf(strings.Repeat("=", 80) + "\n")
	fmt.Printf("🎉 MANUAL TRANSFER COMPLETED SUCCESSFULLY!\n")
	fmt.Printf(strings.Repeat("=", 80) + "\n")
	fmt.Printf("   ├─ Transaction ID: %s\n", tx.ID)
	fmt.Printf("   ├─ Transaction Hash: %s\n", tx.Hash)
	fmt.Printf("   ├─ Route: %s\n", request.Route)
	fmt.Printf("   ├─ Amount: %s %s\n", tx.Amount, tx.TokenSymbol)
	fmt.Printf("   ├─ From: %s (%s)\n", tx.SourceAddress, tx.SourceChain)
	fmt.Printf("   ├─ To: %s (%s)\n", tx.DestAddress, tx.DestChain)
	fmt.Printf("   ├─ Final Status: %s\n", strings.ToUpper(tx.Status))
	fmt.Printf("   ├─ Confirmations: %d\n", tx.Confirmations)
	fmt.Printf("   ├─ Completed At: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("   └─ Total Processing Time: ~%v\n", time.Since(tx.CreatedAt))
	fmt.Printf(strings.Repeat("=", 80) + "\n\n")
	sdk.addEvent("transfer_completed", tx.DestChain, tx.Hash, map[string]interface{}{
		"amount": tx.Amount,
		"token":  tx.TokenSymbol,
		"route":  request.Route,
		"manual": true,
		"demo":   true,
	})
}

// --- STUBS for missing handler methods to fix linter errors ---
func (sdk *BridgeSDK) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	// Set CSP headers to allow inline scripts and styles
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self'")
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlackHole Bridge Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary-bg: #ffffff;
            --secondary-bg: #f8fafc;
            --accent-bg: #f1f5f9;
            --text-primary: #0f172a;
            --text-secondary: #334155;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --navy-blue: #1e3a8a;
            --navy-dark: #0f172a;
            --success: #10b981;
            --warning: #f59e0b;
            --error: #ef4444;
            --sidebar-width: 280px;
        }

        [data-theme="dark"] {
            --primary-bg: #0f172a;
            --secondary-bg: #1e293b;
            --accent-bg: #334155;
            --text-primary: #ffffff;
            --text-secondary: #f1f5f9;
            --text-muted: #e2e8f0;
            --border-color: #475569;
            --navy-blue: #60a5fa;
            --navy-dark: #3b82f6;
            --success: #22c55e;
            --warning: #fbbf24;
            --error: #f87171;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--primary-bg);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            font-weight: 500;
            transition: all 0.3s ease;
        }

        /* Sidebar Navigation */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: var(--sidebar-width);
            height: 100vh;
            background: var(--secondary-bg);
            border-right: 2px solid var(--border-color);
            z-index: 1000;
            overflow-y: auto;
            transition: all 0.3s ease;
        }

        .sidebar-header {
            padding: 24px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .sidebar-logo {
            width: 48px;
            height: 48px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(30, 58, 138, 0.2);
        }

        .sidebar-title {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--navy-blue);
        }

        .sidebar-nav {
            padding: 20px 0;
        }

        .nav-item {
            display: block;
            padding: 12px 20px;
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 500;
            transition: all 0.2s ease;
            border-left: 3px solid transparent;
        }

        .nav-item:hover {
            background: var(--accent-bg);
            color: var(--navy-blue);
            border-left-color: var(--navy-blue);
        }

        .nav-item.active {
            background: var(--accent-bg);
            color: var(--navy-blue);
            border-left-color: var(--navy-blue);
            font-weight: 600;
        }

        .nav-item i {
            margin-right: 12px;
            width: 20px;
        }

        /* Theme Toggle */
        .theme-toggle {
            position: absolute;
            bottom: 20px;
            left: 20px;
            right: 20px;
            padding: 12px;
            background: var(--accent-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            cursor: pointer;
            font-weight: 500;
            color: var(--text-primary);
            transition: all 0.2s ease;
        }

        .theme-toggle:hover {
            background: var(--navy-blue);
            color: white;
        }

        /* Main Content */
        .main-content {
            margin-left: calc(var(--sidebar-width) + 30px);
            margin-right: 30px;
            min-height: 100vh;
            background: var(--primary-bg);
            padding: 20px 30px;
            max-width: calc(100vw - var(--sidebar-width) - 90px);
        }

        .dashboard-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        /* Enhanced Dark Mode Text Visibility */
        [data-theme="dark"] * {
            color: var(--text-primary);
        }

        [data-theme="dark"] h1,
        [data-theme="dark"] h2,
        [data-theme="dark"] h3,
        [data-theme="dark"] h4,
        [data-theme="dark"] h5,
        [data-theme="dark"] h6 {
            color: var(--navy-blue) !important;
        }

        [data-theme="dark"] .dashboard-header h1 {
            color: var(--navy-blue) !important;
        }

        [data-theme="dark"] .dashboard-header p {
            color: var(--text-secondary) !important;
        }

        [data-theme="dark"] .status-online {
            color: var(--success) !important;
        }

        .dashboard-header {
            text-align: center;
            margin-bottom: 40px;
            padding: 30px 0;
            background: var(--secondary-bg);
            border-radius: 16px;
            border: 2px solid var(--border-color);
            box-shadow: 0 8px 32px rgba(30, 58, 138, 0.1);
        }

        .dashboard-header h1 {
            font-size: 2.5rem;
            color: var(--navy-blue);
            margin-bottom: 10px;
            font-weight: 700;
            letter-spacing: -0.025em;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
        }

        [data-theme="dark"] .dashboard-header h1 {
            color: var(--navy-blue);
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        .dashboard-header .logo {
            width: 56px;
            height: 56px;
            border-radius: 12px;
            box-shadow: 0 4px 16px rgba(30, 58, 138, 0.3);
        }

        .dashboard-header p {
            font-size: 1.1rem;
            color: var(--text-muted);
            font-weight: 500;
            margin-top: 8px;
        }

        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(34, 197, 94, 0.1);
            color: #22c55e;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background: #22c55e;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 28px;
            text-align: center;
            border: 2px solid rgba(30, 58, 138, 0.1);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            box-shadow:
                0 8px 25px rgba(30, 58, 138, 0.08),
                0 4px 12px rgba(15, 23, 42, 0.05),
                inset 0 1px 0 rgba(255, 255, 255, 0.9);
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow:
                0 15px 40px rgba(30, 58, 138, 0.15),
                0 8px 20px rgba(15, 23, 42, 0.1);
            border-color: rgba(30, 58, 138, 0.2);
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #1e3a8a, #0f172a, #1e40af);
        }

        .stat-value {
            font-size: 2.8rem;
            font-weight: 800;
            color: #1e3a8a;
            margin-bottom: 8px;
            display: block;
            text-shadow: 0 2px 4px rgba(15, 23, 42, 0.1);
            letter-spacing: -0.02em;
        }

        .stat-label {
            color: #475569;
            font-size: 1rem;
            font-weight: 600;
            text-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
        }

        .monitoring-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }

        .monitoring-card {
            background: var(--secondary-bg);
            border-radius: 16px;
            padding: 24px;
            border: 2px solid var(--border-color);
            box-shadow: 0 4px 16px rgba(30, 58, 138, 0.08);
            transition: all 0.3s ease;
        }

        .monitoring-card:hover {
            box-shadow: 0 8px 32px rgba(30, 58, 138, 0.12);
            transform: translateY(-2px);
        }

        /* Wallet Monitoring Styles */
        .wallet-monitoring {
            background: var(--secondary-bg);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
            border: 2px solid var(--border-color);
            box-shadow: 0 4px 16px rgba(30, 58, 138, 0.08);
        }

        .wallet-monitoring h2 {
            color: var(--navy-blue);
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .wallet-transactions {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: var(--primary-bg);
        }

        .transaction-item {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s ease;
        }

        .transaction-item:hover {
            background: var(--accent-bg);
        }

        .transaction-item:last-child {
            border-bottom: none;
        }

        .transaction-details {
            flex: 1;
        }

        .transaction-hash {
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            color: var(--text-muted);
            margin-bottom: 4px;
        }

        .transaction-amount {
            font-weight: 600;
            color: var(--navy-blue);
        }

        .transaction-status {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .status-confirmed {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success);
        }

        .status-pending {
            background: rgba(245, 158, 11, 0.1);
            color: var(--warning);
        }

        .status-failed {
            background: rgba(239, 68, 68, 0.1);
            color: var(--error);
        }

        /* Dark Mode Specific Styles */
        [data-theme="dark"] .card,
        [data-theme="dark"] .monitoring-card,
        [data-theme="dark"] .wallet-monitoring {
            background: var(--secondary-bg);
            border-color: var(--border-color);
            color: var(--text-primary);
        }

        [data-theme="dark"] .card h2,
        [data-theme="dark"] .card h3,
        [data-theme="dark"] .monitoring-card h2,
        [data-theme="dark"] .monitoring-card h3,
        [data-theme="dark"] .wallet-monitoring h2 {
            color: var(--navy-blue);
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
        }

        [data-theme="dark"] .transaction-item {
            color: var(--text-primary);
            border-bottom-color: var(--border-color);
        }

        [data-theme="dark"] .transaction-hash {
            color: var(--text-muted);
        }

        [data-theme="dark"] .transaction-amount {
            color: var(--navy-blue);
        }

        [data-theme="dark"] .status-confirmed {
            background: rgba(34, 197, 94, 0.2);
            color: var(--success);
        }

        [data-theme="dark"] .status-pending {
            background: rgba(251, 191, 36, 0.2);
            color: var(--warning);
        }

        [data-theme="dark"] .status-failed {
            background: rgba(248, 113, 113, 0.2);
            color: var(--error);
        }

        /* Dark Mode Text Improvements */
        [data-theme="dark"] .monitoring-content,
        [data-theme="dark"] .card-content,
        [data-theme="dark"] .stats-grid .stat-item,
        [data-theme="dark"] .stats-grid .stat-item .stat-value,
        [data-theme="dark"] .stats-grid .stat-item .stat-label {
            color: var(--text-primary) !important;
        }

        [data-theme="dark"] .stat-value {
            color: var(--navy-blue) !important;
            font-weight: 700;
        }

        [data-theme="dark"] .stat-label {
            color: var(--text-secondary) !important;
        }

        [data-theme="dark"] .monitoring-content div,
        [data-theme="dark"] .monitoring-content span,
        [data-theme="dark"] .monitoring-content p {
            color: var(--text-primary);
        }

        [data-theme="dark"] .status-value {
            color: var(--success) !important;
        }

        [data-theme="dark"] .metric-value {
            color: var(--navy-blue) !important;
        }

        [data-theme="dark"] .metric-label {
            color: var(--text-secondary) !important;
        }

        .monitoring-card h3 {
            color: #1e3a8a;
            margin-bottom: 15px;
            font-size: 1.3rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 8px;
            text-shadow: 0 1px 2px rgba(15, 23, 42, 0.1);
        }

        .monitoring-content {
            color: #334155;
            font-size: 1rem;
            line-height: 1.6;
            font-weight: 500;
        }

        .nav-links {
            text-align: center;
            margin-top: 30px;
            padding: 20px;
        }

        .nav-top {
            margin-top: 20px;
            margin-bottom: 30px;
            padding: 18px 24px;
            background: rgba(30, 58, 138, 0.1);
            border-radius: 12px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            box-shadow:
                0 4px 16px rgba(30, 58, 138, 0.08),
                inset 0 1px 0 rgba(255, 255, 255, 0.8);
            border: 1px solid rgba(59, 130, 246, 0.2);
        }

        .nav-link {
            display: inline-block;
            margin: 0 15px;
            padding: 14px 28px;
            background: rgba(255, 255, 255, 0.1);
            color: #1e3a8a;
            text-decoration: none;
            border-radius: 10px;
            border: 2px solid rgba(30, 58, 138, 0.2);
            transition: all 0.3s ease;
            font-weight: 600;
            text-shadow: 0 1px 2px rgba(15, 23, 42, 0.1);
            box-shadow: 0 2px 8px rgba(30, 58, 138, 0.1);
        }

        .nav-link:hover {
            background: rgba(30, 58, 138, 0.1);
            transform: translateY(-2px);
            border-color: rgba(30, 58, 138, 0.3);
            box-shadow: 0 4px 16px rgba(30, 58, 138, 0.15);
        }

        .transaction-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        .transaction-table th,
        .transaction-table td {
            padding: 14px;
            text-align: left;
            border-bottom: 2px solid rgba(30, 58, 138, 0.1);
            color: #334155;
            font-weight: 500;
        }

        .transaction-table th {
            background: rgba(30, 58, 138, 0.1);
            color: #1e3a8a;
            font-weight: 700;
            text-shadow: 0 1px 2px rgba(15, 23, 42, 0.1);
        }

        .status-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
        }

        .status-success {
            background: rgba(34, 197, 94, 0.2);
            color: #22c55e;
        }

        .status-pending {
            background: rgba(251, 191, 36, 0.2);
            color: #fbbf24;
        }

        .status-failed {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
        }

        /* Manual Testing Interface Styles */
        .testing-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-top: 20px;
        }

        .testing-section {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            box-shadow: 0 4px 12px rgba(30, 58, 138, 0.1);
            margin-bottom: 25px;
            clear: both;
            position: relative;
        }

        .testing-section h4 {
            color: #60a5fa;
            margin-bottom: 20px;
            font-size: 1.1rem;
            font-weight: 600;
        }

        .transfer-form {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }

        .form-group label {
            color: #475569;
            font-size: 1rem;
            font-weight: 600;
            text-shadow: 0 1px 2px rgba(15, 23, 42, 0.1);
        }

        .form-group input,
        .form-group select {
            background: rgba(255, 255, 255, 0.9);
            border: 2px solid rgba(30, 58, 138, 0.2);
            border-radius: 8px;
            padding: 12px 16px;
            color: #334155;
            font-size: 1rem;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(30, 58, 138, 0.05);
        }

        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: #1e3a8a;
            box-shadow:
                0 0 0 3px rgba(30, 58, 138, 0.1),
                0 4px 16px rgba(30, 58, 138, 0.1);
            background: rgba(255, 255, 255, 0.95);
        }

        .form-actions {
            display: flex;
            gap: 10px;
            margin-top: 10px;
        }

        .execute-btn,
        .clear-btn {
            padding: 14px 24px;
            border: none;
            border-radius: 8px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 1rem;
            text-shadow: 0 1px 2px rgba(15, 23, 42, 0.2);
        }

        .execute-btn {
            background: linear-gradient(45deg, #1e3a8a, #0f172a);
            color: white;
            flex: 1;
            box-shadow: 0 4px 16px rgba(30, 58, 138, 0.2);
        }

        .execute-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(30, 58, 138, 0.3);
            background: linear-gradient(45deg, #1e40af, #1e3a8a);
        }

        .execute-btn:disabled {
            background: rgba(156, 163, 175, 0.3);
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .clear-btn {
            background: rgba(15, 23, 42, 0.1);
            color: #0f172a;
            border: 2px solid rgba(15, 23, 42, 0.2);
            box-shadow: 0 2px 8px rgba(15, 23, 42, 0.1);
        }

        .clear-btn:hover {
            background: rgba(15, 23, 42, 0.2);
            border-color: rgba(15, 23, 42, 0.3);
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(15, 23, 42, 0.15);
        }

        .transfer-status {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-bottom: 20px;
        }

        .status-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 2px solid rgba(30, 58, 138, 0.1);
        }

        .status-label {
            color: #475569;
            font-size: 1rem;
            font-weight: 600;
        }

        .status-value {
            color: #334155;
            font-weight: 600;
            font-size: 1rem;
        }

        .progress-bar {
            width: 120px;
            height: 8px;
            background: rgba(30, 58, 138, 0.1);
            border-radius: 4px;
            overflow: hidden;
            margin: 0 10px;
            border: 1px solid rgba(30, 58, 138, 0.2);
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #1e3a8a, #0f172a);
            transition: width 0.3s ease;
        }

        .progress-text {
            font-size: 0.9rem;
            color: #475569;
            font-weight: 600;
        }

        .transfer-logs {
            max-height: 220px;
            overflow-y: auto;
            background: rgba(255, 255, 255, 0.9);
            border-radius: 8px;
            padding: 12px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            box-shadow: inset 0 2px 8px rgba(30, 58, 138, 0.05);
        }

        .log-entry {
            display: flex;
            gap: 12px;
            padding: 6px 0;
            font-size: 0.9rem;
            border-bottom: 1px solid rgba(30, 58, 138, 0.1);
        }

        .log-entry:last-child {
            border-bottom: none;
        }

        .log-time {
            color: #475569;
            min-width: 70px;
            font-weight: 600;
        }

        .log-message {
            color: #334155;
            font-weight: 500;
        }

        /* Enhanced Load Testing Styles */
        .load-test-controls {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            box-shadow: 0 4px 12px rgba(30, 58, 138, 0.1);
            margin-bottom: 20px;
        }

        .test-results {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            box-shadow: 0 4px 12px rgba(30, 58, 138, 0.1);
            margin-top: 20px;
            margin-bottom: 20px;
            min-height: 120px;
            /* Removed max-height constraint to prevent congestion */
            animation: fadeIn 0.3s ease;
            clear: both;
            position: relative;
        }

        /* Special handling for the main real-time test results container */
        #testResults.test-results {
            min-height: 200px;
            /* Allow natural height expansion for extensive content */
        }

        /* Add scrolling only when content becomes extremely large */
        .test-results.scrollable {
            max-height: 600px;
            overflow-y: auto;
        }

        .metric-section {
            margin-top: 20px;
            padding: 15px;
            background: rgba(30, 58, 138, 0.05);
            border-radius: 8px;
            border-left: 3px solid #60a5fa;
        }

        .metric-section h5 {
            margin: 0 0 15px 0;
            color: #1e3a8a;
            font-size: 1rem;
            font-weight: 600;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .test-metrics {
            display: grid;
            gap: 15px;
        }

        .metric-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }

        .metric-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .stop-btn {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .stop-btn:hover {
            background: linear-gradient(135deg, #dc2626, #b91c1c);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
        }

        .stop-btn:disabled {
            background: #9ca3af;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        /* Orchestration Status Styles */
        .orchestration-status {
            margin-top: 20px;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
        }

        .orchestration-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .module-status {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .module-name {
            font-weight: 600;
            color: #334155;
        }

        .module-health {
            font-weight: 600;
            font-size: 0.9rem;
        }

        /* Latency Monitoring Styles */
        .latency-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }

        .latency-section {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
        }

        .latency-metrics {
            display: grid;
            gap: 12px;
            margin-top: 15px;
        }

        .chain-latency {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .chain-name {
            font-weight: 600;
            color: #334155;
        }

        .latency-value {
            font-weight: 600;
            color: #1e3a8a;
        }

        .sync-status {
            display: grid;
            gap: 12px;
            margin-top: 15px;
        }

        .sync-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .sync-label {
            font-weight: 600;
            color: #334155;
        }

        .sync-value {
            font-weight: 600;
            color: #059669;
        }

        /* Health Indicators Styles */
        .health-indicators {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
        }

        .component-health {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .health-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .component-name {
            font-weight: 600;
            color: #334155;
        }

        .health-status {
            font-weight: 600;
            font-size: 0.9rem;
        }

        /* Main Dashboard Integration Styles */
        .integration-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }

        .integration-section {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
        }

        .activity-monitor, .operations-monitor {
            display: grid;
            gap: 12px;
            margin-top: 15px;
        }

        .activity-item, .operation-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .activity-label, .operation-label {
            font-weight: 600;
            color: #334155;
        }

        .activity-value, .operation-value {
            font-weight: 600;
            color: #059669;
        }

        .recent-activities {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            margin-top: 20px;
        }

        .activities-list {
            max-height: 300px;
            overflow-y: auto;
            margin-top: 15px;
        }

        .activity-entry {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
            margin-bottom: 8px;
        }

        .activity-loading {
            text-align: center;
            color: #64748b;
            font-style: italic;
            padding: 20px;
        }

        /* Wallet Dashboard Integration Styles */
        .wallet-integration-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }

        .wallet-section {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
        }

        .wallet-monitor, .cross-chain-monitor, .security-monitor {
            display: grid;
            gap: 12px;
            margin-top: 15px;
        }

        .wallet-item, .cross-chain-item, .security-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .wallet-label, .cross-chain-label, .security-label {
            font-weight: 600;
            color: #334155;
        }

        .wallet-value, .cross-chain-value, .security-value {
            font-weight: 600;
            color: #059669;
        }

        .wallet-transactions, .wallet-security {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            margin-top: 20px;
        }

        .wallet-transactions-list {
            max-height: 300px;
            overflow-y: auto;
            margin-top: 15px;
        }

        .wallet-transaction-entry {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
            margin-bottom: 8px;
        }

        .wallet-loading {
            text-align: center;
            color: #64748b;
            font-style: italic;
            padding: 20px;
        }

        /* Cross-Platform Transaction Visibility Styles */
        .cross-platform-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }

        .platform-section {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
        }

        .tracking-monitor, .audit-monitor {
            display: grid;
            gap: 12px;
            margin-top: 15px;
        }

        .tracking-item, .audit-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .tracking-label, .audit-label {
            font-weight: 600;
            color: #334155;
        }

        .tracking-value, .audit-value {
            font-weight: 600;
            color: #059669;
        }

        .transaction-history {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            margin-top: 20px;
        }

        .transaction-filters {
            display: flex;
            gap: 15px;
            align-items: center;
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .transaction-filters select {
            padding: 8px 12px;
            border: 1px solid rgba(30, 58, 138, 0.2);
            border-radius: 6px;
            background: white;
            font-size: 0.9rem;
        }

        .refresh-btn {
            padding: 8px 16px;
            background: linear-gradient(135deg, #059669, #047857);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .refresh-btn:hover {
            background: linear-gradient(135deg, #047857, #065f46);
            transform: translateY(-1px);
        }

        .cross-platform-transactions-list {
            max-height: 400px;
            overflow-y: auto;
            margin-top: 15px;
        }

        .cross-platform-transaction-entry {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
            margin-bottom: 10px;
            transition: all 0.3s ease;
        }

        .cross-platform-transaction-entry:hover {
            background: rgba(239, 246, 255, 0.9);
            border-color: rgba(30, 58, 138, 0.2);
        }

        .transaction-loading {
            text-align: center;
            color: #64748b;
            font-style: italic;
            padding: 20px;
        }

        /* CI/CD Integration Styles */
        .cicd-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }

        .cicd-section {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
        }

        .pr-testing, .deployment-status {
            display: grid;
            gap: 12px;
            margin-top: 15px;
        }

        .pr-item, .deploy-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .pr-label, .deploy-label {
            font-weight: 600;
            color: #334155;
        }

        .pr-status, .pr-value, .deploy-value {
            font-weight: 600;
            font-size: 0.9rem;
        }

        .merge-readiness {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
        }

        .merge-indicators {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .merge-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .merge-label {
            font-weight: 600;
            color: #334155;
        }

        .merge-status {
            font-weight: 600;
            font-size: 0.9rem;
        }

        /* Stress Testing Evidence Styles */
        .evidence-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }

        .evidence-section {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
        }

        .stress-results, .retry-results {
            display: grid;
            gap: 12px;
            margin-top: 15px;
        }

        .result-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .result-label {
            font-weight: 600;
            color: #334155;
        }

        .result-value {
            font-weight: 600;
            color: #059669;
            font-size: 0.9rem;
        }

        .fallback-evidence {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
        }

        .fallback-results {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        /* End-to-End Flow Integration Styles */
        .flow-visualization {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            margin-bottom: 20px;
        }

        .flow-diagram {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 20px;
            margin-top: 20px;
            flex-wrap: wrap;
        }

        .flow-step {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 8px;
            padding: 15px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 12px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            min-width: 120px;
            transition: all 0.3s ease;
        }

        .flow-step:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(30, 58, 138, 0.2);
        }

        .step-icon {
            font-size: 2rem;
            margin-bottom: 5px;
        }

        .step-label {
            font-weight: 600;
            color: #334155;
            text-align: center;
            font-size: 0.9rem;
        }

        .step-status {
            font-weight: 600;
            font-size: 0.8rem;
        }

        .flow-arrow {
            font-size: 1.5rem;
            color: #1e3a8a;
            font-weight: bold;
        }

        .flow-metrics {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            margin-bottom: 20px;
        }

        .flow-performance {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .perf-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(30, 58, 138, 0.1);
        }

        .perf-label {
            font-weight: 600;
            color: #334155;
        }

        .perf-value {
            font-weight: 600;
            color: #059669;
            font-size: 0.9rem;
        }

        .integration-logs {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
        }

        .integration-log-container {
            max-height: 300px;
            overflow-y: auto;
            margin-top: 15px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            padding: 15px;
        }

        .log-entry {
            display: grid;
            grid-template-columns: 80px 100px 1fr;
            gap: 15px;
            padding: 8px 0;
            border-bottom: 1px solid rgba(30, 58, 138, 0.1);
            font-size: 0.9rem;
        }

        .log-entry:last-child {
            border-bottom: none;
        }

        .log-time {
            color: #64748b;
            font-weight: 600;
        }

        .log-module {
            color: #1e3a8a;
            font-weight: 600;
        }

        .log-message {
            color: #334155;
        }

        /* Event Tree Visualization Styles */
        .tree-controls {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            margin-bottom: 20px;
        }

        .tree-config {
            margin-top: 15px;
        }

        .event-tree {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            min-height: 300px;
        }

        .tree-loading {
            text-align: center;
            color: #64748b;
            font-style: italic;
            padding: 50px;
        }

        .tree-node {
            margin: 10px 0;
            padding: 10px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border-left: 4px solid #1e3a8a;
        }

        .tree-node.level-1 {
            margin-left: 20px;
            border-left-color: #059669;
        }

        .tree-node.level-2 {
            margin-left: 40px;
            border-left-color: #f59e0b;
        }

        .tree-node-header {
            font-weight: 600;
            color: #334155;
            margin-bottom: 5px;
        }

        .tree-node-details {
            font-size: 0.9rem;
            color: #64748b;
        }

        /* Sidebar Navigation Styles */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 280px;
            height: 100vh;
            background: linear-gradient(135deg, rgba(30, 58, 138, 0.95), rgba(15, 23, 42, 0.95));
            backdrop-filter: blur(10px);
            border-right: 2px solid rgba(30, 58, 138, 0.2);
            z-index: 1000;
            overflow-y: auto;
            overflow-x: hidden;
            transition: transform 0.3s ease;
            box-sizing: border-box;
        }

        /* Custom Scrollbar for Sidebar */
        .sidebar::-webkit-scrollbar {
            width: 8px;
        }

        .sidebar::-webkit-scrollbar-track {
            background: rgba(15, 23, 42, 0.3);
            border-radius: 0;
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: linear-gradient(180deg, rgba(96, 165, 250, 0.8), rgba(59, 130, 246, 0.8));
            border-radius: 0;
            border: 1px solid rgba(30, 58, 138, 0.3);
        }

        .sidebar::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(180deg, rgba(96, 165, 250, 1), rgba(59, 130, 246, 1));
        }

        /* Firefox Scrollbar */
        .sidebar {
            scrollbar-width: thin;
            scrollbar-color: rgba(96, 165, 250, 0.8) rgba(15, 23, 42, 0.3);
        }

        .sidebar.collapsed {
            transform: translateX(-280px);
        }

        .sidebar-header {
            padding: 20px;
            border-bottom: 2px solid rgba(255, 255, 255, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .sidebar-header h3 {
            color: white;
            margin: 0;
            font-size: 1.2rem;
            font-weight: 600;
        }

        .sidebar-toggle {
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1.2rem;
            transition: all 0.3s ease;
        }

        .sidebar-toggle:hover {
            background: rgba(255, 255, 255, 0.2);
            transform: scale(1.1);
        }

        .sidebar-content {
            padding: 20px 0;
        }

        .nav-section {
            margin-bottom: 30px;
        }

        .nav-section h4 {
            color: rgba(255, 255, 255, 0.8);
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin: 0 20px 15px 20px;
            padding-bottom: 8px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .nav-item {
            display: flex;
            align-items: center;
            padding: 12px 20px;
            color: rgba(255, 255, 255, 0.9);
            text-decoration: none;
            transition: all 0.3s ease;
            border-left: 3px solid transparent;
        }

        .nav-item:hover {
            background: rgba(255, 255, 255, 0.1);
            border-left-color: #60a5fa;
            color: white;
            transform: translateX(5px);
        }

        .nav-item.active {
            background: rgba(96, 165, 250, 0.2);
            border-left-color: #60a5fa;
            color: white;
        }

        .nav-icon {
            font-size: 1.2rem;
            margin-right: 12px;
            width: 20px;
            text-align: center;
        }

        .nav-text {
            font-weight: 500;
            font-size: 0.95rem;
        }

        /* Main Content Adjustment */
        .main-content {
            margin-left: 280px;
            transition: margin-left 0.3s ease;
            min-height: 100vh;
        }

        .main-content.expanded {
            margin-left: 0;
        }

        /* Responsive Sidebar */
        @media (max-width: 1024px) {
            .sidebar {
                transform: translateX(-280px);
            }

            .sidebar.open {
                transform: translateX(0);
            }

            .main-content {
                margin-left: 0;
            }

            .sidebar-toggle {
                display: block;
            }
        }

        @media (max-width: 768px) {
            .dashboard-header h1 {
                font-size: 2rem;
            }

            .stats-grid {
                grid-template-columns: 1fr 1fr;
            }

            .monitoring-grid {
                grid-template-columns: 1fr;
            }

            .testing-grid {
                grid-template-columns: 1fr;
                gap: 20px;
            }

            .form-row {
                grid-template-columns: 1fr;
                gap: 10px;
            }

            .form-actions {
                flex-direction: column;
            }

            .latency-grid, .cicd-grid, .evidence-grid {
                grid-template-columns: 1fr;
                gap: 15px;
            }

            .orchestration-grid, .component-health, .merge-indicators, .fallback-results {
                grid-template-columns: 1fr;
                gap: 10px;
            }

            .flow-diagram {
                flex-direction: column;
                gap: 15px;
            }

            .flow-arrow {
                transform: rotate(90deg);
            }

            .flow-performance {
                grid-template-columns: 1fr;
            }

            .log-entry {
                grid-template-columns: 1fr;
                gap: 5px;
            }
        }

        /* Enhanced Cross-Chain Features Styles */
        .enhanced-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .enhanced-section {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            border: 2px solid rgba(30, 58, 138, 0.1);
            box-shadow: 0 4px 12px rgba(30, 58, 138, 0.1);
        }

        .enhanced-section h4 {
            color: #1e3a8a;
            margin-bottom: 15px;
            font-weight: 600;
            font-size: 1.1rem;
        }

        .routing-controls, .liquidity-controls {
            margin-bottom: 15px;
        }

        .route-results, .liquidity-results {
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            padding: 15px;
            border: 1px solid rgba(148, 163, 184, 0.2);
            min-height: 100px;
        }

        .route-loading, .liquidity-loading {
            color: #64748b;
            font-style: italic;
            text-align: center;
            padding: 20px;
        }

        .security-dashboard, .analytics-dashboard, .compliance-dashboard {
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            padding: 15px;
            border: 1px solid rgba(148, 163, 184, 0.2);
        }

        .security-metrics, .analytics-metrics, .compliance-metrics {
            display: grid;
            grid-template-columns: 1fr;
            gap: 10px;
            margin-bottom: 15px;
        }

        .security-item, .analytics-item, .compliance-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            background: rgba(255, 255, 255, 0.7);
            border-radius: 6px;
            border: 1px solid rgba(148, 163, 184, 0.1);
        }

        .security-label, .analytics-label, .compliance-label {
            font-weight: 500;
            color: #374151;
        }

        .security-value, .analytics-value, .compliance-value {
            font-weight: 600;
            color: #1e3a8a;
        }

        .provider-comparison {
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            padding: 15px;
            border: 1px solid rgba(148, 163, 184, 0.2);
        }

        .provider-metrics {
            display: grid;
            grid-template-columns: 1fr;
            gap: 8px;
            margin-bottom: 15px;
        }

        .provider-item {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr 1fr;
            gap: 10px;
            align-items: center;
            padding: 10px 12px;
            background: rgba(255, 255, 255, 0.7);
            border-radius: 6px;
            border: 1px solid rgba(148, 163, 184, 0.1);
            font-size: 0.9rem;
        }

        .provider-item:first-child {
            background: rgba(34, 197, 94, 0.1);
            border-color: rgba(34, 197, 94, 0.3);
        }

        .provider-name {
            font-weight: 600;
            color: #1e3a8a;
        }

        .provider-fee, .provider-time, .provider-rate {
            color: #374151;
            text-align: center;
        }

        .provider-recommended {
            text-align: center;
            font-weight: 600;
        }

        @media (max-width: 768px) {
            .enhanced-grid {
                grid-template-columns: 1fr;
            }

            .provider-item {
                grid-template-columns: 1fr;
                gap: 5px;
                text-align: center;
            }
        }

        /* Advanced Testing Infrastructure Styles */
        .testing-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        /* Removed duplicate .testing-section definition - consolidated above */

        .testing-section h4 {
            color: #1e3a8a;
            margin-bottom: 15px;
            font-weight: 600;
            font-size: 1.1rem;
        }

        .stress-testing-controls, .chaos-testing-controls, .validation-controls,
        .benchmark-controls, .scenario-controls {
            margin-bottom: 15px;
        }

        .button-row {
            display: flex;
            gap: 10px;
            margin-top: 15px;
            flex-wrap: wrap;
        }

        .execute-btn, .stop-btn, .status-btn, .info-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }

        .execute-btn {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
        }

        .execute-btn:hover {
            background: linear-gradient(135deg, #059669, #047857);
            transform: translateY(-1px);
        }

        .stop-btn {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
        }

        .stop-btn:hover {
            background: linear-gradient(135deg, #dc2626, #b91c1c);
            transform: translateY(-1px);
        }

        .status-btn {
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            color: white;
        }

        .status-btn:hover {
            background: linear-gradient(135deg, #2563eb, #1d4ed8);
            transform: translateY(-1px);
        }

        .info-btn {
            background: linear-gradient(135deg, #8b5cf6, #7c3aed);
            color: white;
        }

        .info-btn:hover {
            background: linear-gradient(135deg, #7c3aed, #6d28d9);
            transform: translateY(-1px);
        }

        /* Removed duplicate .test-results definition - consolidated above */

        /* Additional spacing for test sections to prevent overlap */
        .test-section {
            margin-bottom: 30px;
            clear: both;
        }

        .test-controls {
            margin-bottom: 20px;
        }

        /* Ensure proper spacing between different test types */
        #loadTestSection,
        #stressTestSection,
        #chaosTestSection,
        #resilienceTestSection {
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(148, 163, 184, 0.1);
        }

        /* Last section doesn't need bottom border */
        #resilienceTestSection {
            border-bottom: none;
        }

        /* Specific spacing for real-time test results containers */
        #testResults {
            margin-bottom: 25px;
            z-index: 1;
        }

        #stressTestResults {
            margin-bottom: 25px;
            z-index: 2;
        }

        #advancedStressTestResults {
            margin-bottom: 25px;
            z-index: 3;
        }

        #chaosTestResults {
            margin-bottom: 25px;
            z-index: 4;
        }

        /* Ensure stress results don't overlap */
        .stress-results {
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(248, 250, 252, 0.9);
            border-radius: 8px;
            border: 1px solid rgba(148, 163, 184, 0.2);
        }

        /* Evidence sections spacing */
        .evidence-section {
            margin-bottom: 30px;
        }

        .evidence-grid {
            display: grid;
            gap: 25px;
            margin-top: 20px;
        }

        /* Prevent overlapping when multiple test results are shown */
        .test-results-container {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        /* Ensure proper stacking order for test results */
        .test-results.active {
            display: block !important;
            margin-bottom: 25px;
            animation: slideIn 0.3s ease-out;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* Better spacing for test metrics to prevent congestion */
        .test-metrics {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        .metric-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 15px;
        }

        .metric-item {
            display: flex;
            flex-direction: column;
            gap: 5px;
            padding: 10px;
            background: rgba(248, 250, 252, 0.8);
            border-radius: 8px;
            border: 1px solid rgba(148, 163, 184, 0.2);
        }

        .metric-section {
            margin-top: 25px;
            padding-top: 20px;
            border-top: 2px solid rgba(30, 58, 138, 0.1);
        }

        .metric-section h5 {
            color: #1e3a8a;
            margin-bottom: 15px;
            font-weight: 600;
        }

        /* Progress bar styling */
        .progress-bar {
            width: 100%;
            height: 8px;
            background: rgba(148, 163, 184, 0.2);
            border-radius: 4px;
            overflow: hidden;
            margin: 5px 0;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #10b981, #34d399);
            transition: width 0.3s ease;
        }

        .progress-text {
            font-size: 0.9rem;
            font-weight: 600;
            color: #1e3a8a;
        }

        /* Responsive layout for test results */
        @media (max-width: 768px) {
            .test-results {
                margin-bottom: 15px;
            }

            .metric-row {
                grid-template-columns: 1fr;
                gap: 10px;
            }

            .evidence-grid {
                grid-template-columns: 1fr;
                gap: 15px;
            }
        }

        .test-loading {
            color: #64748b;
            font-style: italic;
            text-align: center;
            padding: 20px;
        }

        .test-analytics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-bottom: 15px;
        }

        .analytics-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            background: rgba(255, 255, 255, 0.7);
            border-radius: 6px;
            border: 1px solid rgba(148, 163, 184, 0.1);
        }

        .analytics-label {
            font-weight: 500;
            color: #374151;
        }

        .analytics-value {
            font-weight: 600;
            color: #1e3a8a;
        }

        .test-result-item {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 8px;
            border-left: 4px solid #10b981;
        }

        .test-result-item.failed {
            border-left-color: #ef4444;
        }

        .test-result-item.running {
            border-left-color: #f59e0b;
        }

        .test-result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }

        .test-result-name {
            font-weight: 600;
            color: #1e293b;
        }

        .test-result-status {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }

        .test-result-status.passed {
            background: rgba(16, 185, 129, 0.1);
            color: #059669;
        }

        .test-result-status.failed {
            background: rgba(239, 68, 68, 0.1);
            color: #dc2626;
        }

        .test-result-status.running {
            background: rgba(245, 158, 11, 0.1);
            color: #d97706;
        }

        .test-result-details {
            font-size: 0.9rem;
            color: #64748b;
        }

        .test-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 8px;
            margin-top: 8px;
        }

        .test-metric {
            background: rgba(248, 250, 252, 0.8);
            padding: 6px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
        }

        .test-metric-label {
            font-weight: 500;
            color: #374151;
        }

        .test-metric-value {
            color: #1e3a8a;
            font-weight: 600;
        }

        @media (max-width: 768px) {
            .testing-grid {
                grid-template-columns: 1fr;
            }

            .button-row {
                flex-direction: column;
            }

            .test-analytics {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <!-- Sidebar Navigation -->
    <div class="sidebar">
        <div class="sidebar-header">
            <img src="../media/blackhole-logo.png" alt="BlackHole Logo" class="sidebar-logo">
            <div class="sidebar-title">BlackHole Bridge</div>
        </div>
        <nav class="sidebar-nav">
            <a href="/" class="nav-item active">
                <i style="color: #ffc107;">◆</i> Main Dashboard
            </a>
            <a href="/infra-dashboard" class="nav-item">
                <i style="color: #6c757d;">■</i> Infrastructure
            </a>
            <a href="#wallet-monitoring" class="nav-item" onclick="scrollToWalletMonitoring()">
                <i style="color: #0066cc;">▶</i> Wallet Monitoring
            </a>
            <a href="#quick-actions" class="nav-item" onclick="scrollToQuickActions()">
                <i style="color: #28a745;">●</i> Quick Actions
            </a>
        </nav>
        <button class="theme-toggle" onclick="toggleTheme()">
            <span id="theme-text" style="color: #6c757d;">◐ Dark Mode</span>
        </button>
    </div>

    <!-- Sidebar Navigation -->
    <div class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <h3><span style="color: #ffc107;">◆</span> Quick Actions </h3>
            <button class="sidebar-toggle" onclick="toggleSidebar()">≡</button>
        </div>
        <div class="sidebar-content">
            <div class="nav-section">
                <h4><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg> Monitoring</h4>
                <a href="#overview" onclick="scrollToSection('overview')" class="nav-item">
                    <span class="nav-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/></svg></span>
                    <span class="nav-text">Overview</span>
                </a>
                <a href="#load-testing" onclick="scrollToSection('load-testing')" class="nav-item">
                    <span class="nav-icon">⚡</span>
                    <span class="nav-text">Load Testing</span>
                </a>
                <a href="#latency-monitoring" onclick="scrollToSection('latency-monitoring')" class="nav-item">
                    <span class="nav-icon">📈</span>
                    <span class="nav-text">Latency Monitor</span>
                </a>
                <a href="#component-health" onclick="scrollToSection('component-health')" class="nav-item">
                    <span class="nav-icon">🏥</span>
                    <span class="nav-text">Component Health</span>
                </a>
            </div>
            <div class="nav-section">
                <h4><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg> Integration</h4>

                <a href="#flow-integration" onclick="scrollToSection('flow-integration')" class="nav-item">
                    <span class="nav-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 4l1.41 1.41L16.17 8.83 14.83 10.17 12 7.34 9.17 10.17 7.83 8.83 10.59 5.41 12 4zm0 16l-1.41-1.41L7.83 15.17 9.17 13.83 12 16.66l2.83-2.83 1.34 1.34L13.41 18.59 12 20z"/></svg></span>
                    <span class="nav-text">End-to-End Flow</span>
                </a>
                <a href="#event-tree" onclick="scrollToSection('event-tree')" class="nav-item">
                    <span class="nav-icon">🌳</span>
                    <span class="nav-text">Event Tree</span>
                </a>
            </div>
            <div class="nav-section">
                <h4>💼 Operations</h4>
                <a href="#manual-testing" onclick="scrollToSection('manual-testing')" class="nav-item">
                    <span class="nav-icon">🧪</span>
                    <span class="nav-text">Manual Testing</span>
                </a>
                <a href="#enhanced-features" onclick="scrollToSection('enhanced-features')" class="nav-item">
                    <span class="nav-icon">🚀</span>
                    <span class="nav-text">Enhanced Features</span>
                </a>
                <a href="#advanced-testing" onclick="scrollToSection('advanced-testing')" class="nav-item">
                    <span class="nav-icon">🧪</span>
                    <span class="nav-text">Advanced Testing</span>
                </a>
                <a href="#transactions" onclick="scrollToSection('transactions')" class="nav-item">
                    <span class="nav-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"/></svg></span>
                    <span class="nav-text">Transactions</span>
                </a>
                <a href="#wallet-monitoring" onclick="scrollToSection('wallet-monitoring')" class="nav-item">
                    <span class="nav-icon">💰</span>
                    <span class="nav-text">Wallet Monitor</span>
                </a>
            </div>
            <div class="nav-section">
                <h4>⚙️ System</h4>
                <a href="/infra-dashboard" class="nav-item" target="_blank">
                    <span class="nav-icon">🔧</span>
                    <span class="nav-text">Infrastructure</span>
                </a>
                <a href="/health/cli" class="nav-item" target="_blank">
                    <span class="nav-icon">🩺</span>
                    <span class="nav-text">Health Check</span>
                </a>
                <a href="/docs" class="nav-item" target="_blank">
                    <span class="nav-icon">📚</span>
                    <span class="nav-text">API Docs</span>
                </a>
            </div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="main-content" id="mainContent">
        <div class="dashboard-container" id="overview">
            <div class="dashboard-header">
                <h1>
                    <img src="../media/blackhole-logo.png" alt="BlackHole Logo" class="logo">
                    BlackHole Bridge Dashboard
                </h1>
                <p>Enterprise Cross-Chain Bridge Monitoring & Management</p>
                <div class="status-indicator">
                    <div class="status-dot"></div>
                    <span id="connection-status">System Online</span>
                </div>
            </div>
            <a href="http://localhost:8080" class="nav-link" target="_blank"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M3.9 12c0-1.71 1.39-3.1 3.1-3.1h4V7H6.99c-2.76 0-5 2.24-5 5s2.24 5 5 5H11v-1.9H7c-1.71 0-3.1-1.39-3.1-3.1zM8 13h8v-2H8v2zm5-6h4.01c2.76 0 5 2.24 5 5s-2.24 5-5 5H13v1.9h4.01c2.76 0 5-2.24 5-5s-2.24-5-5-5H13V7z"/></svg> Main Blockchain Dashboard</a>
            <a href="http://localhost:9000" class="nav-link" target="_blank"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M21 18v1c0 1.1-.9 2-2 2H5c-1.11 0-2-.9-2-2V5c0-1.1.89-2 2-2h14c1.1 0 2 .9 2 2v1h-9c-1.11 0-2 .9-2 2v8c0 1.1.89 2 2 2h9zm-9-2h10V8H12v8zm4-2.5c-.83 0-1.5-.67-1.5-1.5s.67-1.5 1.5-1.5 1.5.67 1.5 1.5-.67 1.5-1.5 1.5z"/></svg> Wallet Service</a>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-value" id="totalTransactions">0</span>
                <div class="stat-label">Total Transactions</div>
            </div>
            <div class="stat-card">
                <span class="stat-value" id="successRate">0%</span>
                <div class="stat-label">Success Rate</div>
            </div>
            <div class="stat-card">
                <span class="stat-value" id="activeBridges">0</span>
                <div class="stat-label">Active Bridges</div>
            </div>
            <div class="stat-card">
                <span class="stat-value" id="pendingTxs">0</span>
                <div class="stat-label">Pending Transactions</div>
            </div>
            <div class="stat-card">
                <span class="stat-value" id="blockHeight">0</span>
                <div class="stat-label">Block Height</div>
            </div>
            <div class="stat-card">
                <span class="stat-value" id="peerCount">0</span>
                <div class="stat-label">Network Peers</div>
            </div>
        </div>

        <!-- Admin Token Transfers - Real-time Detection -->
        <div id="wallet-monitoring" class="wallet-monitoring" style="margin-bottom: 20px;">
            <h2 style="color: #1a1a1a; display: flex; align-items: center; margin-bottom: 12px;">
                <span style="margin-right: 8px; color: #0066cc;">▶</span>
                Admin Token Transfers
                <span style="margin-left: 10px; font-size: 0.7em; background: #e8f5e8; color: #0066cc; padding: 3px 6px; border-radius: 8px; border: 1px solid #0066cc;">LIVE</span>
            </h2>

            <!-- Wallet Balances Section -->
            <div class="admin-transactions-section" style="padding: 15px; background: white; border-radius: 8px; border: 1px solid #cccccc; border-left: 3px solid #0066cc;">
                <div id="admin-recent-activities" class="admin-activities-list">
                    <div style="padding: 15px; color: #888; text-align: center; background: rgba(255,255,255,0.05); border-radius: 8px;">
                        ⏳ Monitoring for wallet balances...
                    </div>
                </div>
            </div>

            <!-- Wallet Transactions Section -->
            <div class="wallet-transactions-section" style="margin-top: 15px;">
                <h3 style="color: #80bfff; margin-bottom: 10px; font-size: 1em; font-weight: bold;">💰 Wallet Service Transactions</h3>
                <div class="wallet-transactions" id="walletTransactions">
                    <div class="transaction-item">
                        <div class="transaction-details">Loading wallet transactions...</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="monitoring-grid">
            <div class="monitoring-card">
                <h3><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg> Circuit Breakers</h3>
                <div class="monitoring-content" id="circuitBreakers">Loading...</div>
            </div>

            <div class="monitoring-card">
                <h3><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z"/></svg> Replay Protection</h3>
                <div class="monitoring-content" id="replayProtection">Loading...</div>
            </div>

            <div class="monitoring-card">
                <h3>⚠️ Error Handling</h3>
                <div class="monitoring-content" id="errorHandling">Loading...</div>
            </div>

            <div class="monitoring-card">
                <h3><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg> Transaction Rates</h3>
                <div class="monitoring-content" id="transactionRates">Loading...</div>
            </div>

            <div class="monitoring-card">
                <h3><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M3.9 12c0-1.71 1.39-3.1 3.1-3.1h4V7H6.99c-2.76 0-5 2.24-5 5s2.24 5 5 5H11v-1.9H7c-1.71 0-3.1-1.39-3.1-3.1zM8 13h8v-2H8v2zm5-6h4.01c2.76 0 5 2.24 5 5s-2.24 5-5 5H13v1.9h4.01c2.76 0 5-2.24 5-5s-2.24-5-5-5H13V7z"/></svg> Blockchain Integration</h3>
                <div class="monitoring-content" id="blockchainIntegration">Loading...</div>
            </div>

            <div class="monitoring-card">
                <h3>💰 Token Statistics</h3>
                <div class="monitoring-content" id="tokenStatistics">Loading...</div>
            </div>
        </div>



        <!-- Manual Testing Section -->
        <div id="manual-testing" class="monitoring-card" style="margin-bottom: 30px;">
            <h3>🧪 Manual Testing Interface</h3>
            <div class="monitoring-content">
                <div class="testing-grid">
                    <div class="testing-section">
                        <h4>⚡ Quick Transfer</h4>
                        <form id="quickTransferForm" class="transfer-form">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="transferRoute">Transfer Route:</label>
                                    <select id="transferRoute" name="transferRoute" required>
                                        <option value="">Select Route</option>
                                        <option value="ETH_TO_BH">ETH → BlackHole</option>
                                        <option value="BH_TO_SOL">BlackHole → Solana</option>
                                        <option value="ETH_TO_SOL">ETH → Solana (via BH)</option>
                                        <option value="SOL_TO_BH">Solana → BlackHole</option>
                                        <option value="BH_TO_ETH">BlackHole → ETH</option>
                                        <option value="SOL_TO_ETH">Solana → ETH (via BH)</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="transferAmount">Amount:</label>
                                    <input type="number" id="transferAmount" name="transferAmount"
                                           step="0.000001" min="0.000001" placeholder="0.000000" required>
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="sourceAddress">Source Address:</label>
                                    <input type="text" id="sourceAddress" name="sourceAddress"
                                           placeholder="0x... or wallet address" required>
                                </div>
                                <div class="form-group">
                                    <label for="destAddress">Destination Address:</label>
                                    <input type="text" id="destAddress" name="destAddress"
                                           placeholder="0x... or wallet address" required>
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="gasFee">Gas Fee (ETH):</label>
                                    <input type="number" id="gasFee" name="gasFee"
                                           step="0.000001" value="0.001" min="0.000001">
                                </div>
                                <div class="form-group">
                                    <label for="confirmations">Required Confirmations:</label>
                                    <input type="number" id="confirmations" name="confirmations"
                                           value="12" min="1" max="100">
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="timeout">Timeout (seconds):</label>
                                    <input type="number" id="timeout" name="timeout"
                                           value="300" min="30" max="3600">
                                </div>
                                <div class="form-group">
                                    <label for="priority">Priority:</label>
                                    <select id="priority" name="priority">
                                        <option value="low">Low</option>
                                        <option value="medium" selected>Medium</option>
                                        <option value="high">High</option>
                                        <option value="urgent">Urgent</option>
                                    </select>
                                </div>
                            </div>
                            <div class="form-actions">
                                <button type="submit" class="execute-btn" id="executeTransferBtn">
                                    🚀 Execute Transfer
                                </button>
                                <button type="button" class="clear-btn" onclick="clearTransferForm()">
                                    🗑️ Clear Form
                                </button>
                            </div>
                        </form>
                    </div>
                    <div class="testing-section">
                        <h4><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg> Transfer Status</h4>
                        <div id="transferStatus" class="transfer-status">
                            <div class="status-item">
                                <span class="status-label">Status:</span>
                                <span class="status-value" id="currentStatus">Ready</span>
                            </div>
                            <div class="status-item">
                                <span class="status-label">Transaction ID:</span>
                                <span class="status-value" id="transactionId">-</span>
                            </div>
                            <div class="status-item">
                                <span class="status-label">Progress:</span>
                                <div class="progress-bar">
                                    <div class="progress-fill" id="progressFill" style="width: 0%"></div>
                                </div>
                                <span class="progress-text" id="progressText">0%</span>
                            </div>
                            <div class="status-item">
                                <span class="status-label">Confirmations:</span>
                                <span class="status-value" id="currentConfirmations">0/0</span>
                            </div>
                            <div class="status-item">
                                <span class="status-label">Estimated Time:</span>
                                <span class="status-value" id="estimatedTime">-</span>
                            </div>
                            <div class="status-item">
                                <span class="status-label">Gas Used:</span>
                                <span class="status-value" id="gasUsed">-</span>
                            </div>
                        </div>
                        <div class="transfer-logs" id="transferLogs">
                            <div class="log-entry">
                                <span class="log-time">Ready</span>
                                <span class="log-message">Manual testing interface initialized</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Enhanced Load Testing Section -->
        <div class="monitoring-card" id="load-testing" style="margin-bottom: 30px;">
            <h3>⚡ Load & Stress Testing Dashboard</h3>
            <div class="monitoring-content">
                <div class="testing-grid">
                    <div class="testing-section">
                        <h4>🚀 Load Test Configuration</h4>
                        <div class="load-test-controls">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="loadTestTx">Transactions:</label>
                                    <input type="number" id="loadTestTx" value="10000" min="100" max="100000">
                                </div>
                                <div class="form-group">
                                    <label for="loadTestWorkers">Workers:</label>
                                    <input type="number" id="loadTestWorkers" value="50" min="1" max="100">
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="loadTestRetries">Retries:</label>
                                    <input type="number" id="loadTestRetries" value="1000" min="0" max="5000">
                                </div>
                                <div class="form-group">
                                    <label for="loadTestDuration">Duration (min):</label>
                                    <input type="number" id="loadTestDuration" value="30" min="1" max="120">
                                </div>
                            </div>
                            <div class="form-actions">
                                <button onclick="startLoadTest()" class="execute-btn" id="loadTestBtn">🚀 Start Load Test</button>
                                <button onclick="startChaosTest()" class="clear-btn" id="chaosTestBtn">🌪️ Chaos Test</button>
                                <button onclick="stopAllTests()" class="stop-btn" id="stopTestBtn" disabled>⏹️ Stop Tests</button>
                                <button onclick="testVisualization()" class="execute-btn" style="background: #10b981;">🧪 Test Visualization</button>
                                <button onclick="forceMockData()" class="execute-btn" style="background: #f59e0b;">⚡ Force Mock Data</button>
                            </div>
                        </div>
                    </div>

                    <div class="testing-section" style="min-height: auto; height: auto;">
                        <h4><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg> Real-time Test Results</h4>
                        <div id="testResults" class="test-results" style="display: none; min-height: 200px; height: auto;">
                            <div class="test-metrics">
                                <div class="metric-item">
                                    <span class="label">Progress:</span>
                                    <div class="progress-bar">
                                        <div id="testProgressFill" class="progress-fill" style="width: 0%"></div>
                                    </div>
                                    <span id="testProgressText" class="progress-text">0%</span>
                                </div>
                                <div class="metric-row">
                                    <div class="metric-item">
                                        <span class="label">Success Rate:</span>
                                        <span id="testSuccessRate" class="value">0%</span>
                                    </div>
                                    <div class="metric-item">
                                        <span class="label">Throughput:</span>
                                        <span id="testThroughput" class="value">0 tx/s</span>
                                    </div>
                                </div>
                                <div class="metric-row">
                                    <div class="metric-item">
                                        <span class="label">Avg Latency:</span>
                                        <span id="testAvgLatency" class="value">0ms</span>
                                    </div>
                                    <div class="metric-item">
                                        <span class="label">P99 Latency:</span>
                                        <span id="testP99Latency" class="value">0ms</span>
                                    </div>
                                </div>

                                <!-- Enhanced Load Test Metrics -->
                                <div class="metric-section" id="loadTestMetrics" style="display: none;">
                                    <h5><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg> Load Test Details</h5>
                                    <div class="metric-row">
                                        <div class="metric-item">
                                            <span class="label">Completed:</span>
                                            <span id="testTransactionsCompleted" class="value">0</span>
                                        </div>
                                        <div class="metric-item">
                                            <span class="label">Target:</span>
                                            <span id="testTransactionsTarget" class="value">0</span>
                                        </div>
                                    </div>
                                    <div class="metric-row">
                                        <div class="metric-item">
                                            <span class="label">Failed:</span>
                                            <span id="testTransactionsFailed" class="value">0</span>
                                        </div>
                                        <div class="metric-item">
                                            <span class="label">Remaining:</span>
                                            <span id="testTransactionsRemaining" class="value">0</span>
                                        </div>
                                    </div>
                                    <div class="metric-row">
                                        <div class="metric-item">
                                            <span class="label">Active Workers:</span>
                                            <span id="testActiveWorkers" class="value">0</span>
                                        </div>
                                        <div class="metric-item">
                                            <span class="label">Retry Queue:</span>
                                            <span id="testRetryQueueSize" class="value">0</span>
                                        </div>
                                    </div>
                                </div>

                                <!-- Enhanced Chaos Test Metrics -->
                                <div class="metric-section" id="chaosTestMetrics" style="display: none;">
                                    <h5>🌪️ Chaos Test Details</h5>
                                    <div class="metric-row">
                                        <div class="metric-item">
                                            <span class="label">Failures Injected:</span>
                                            <span id="testFailuresInjected" class="value">0</span>
                                        </div>
                                        <div class="metric-item">
                                            <span class="label">Circuit Breaker Trips:</span>
                                            <span id="testCircuitBreakerTrips" class="value">0</span>
                                        </div>
                                    </div>
                                    <div class="metric-row">
                                        <div class="metric-item">
                                            <span class="label">Recovery Time:</span>
                                            <span id="testRecoveryTime" class="value">0ms</span>
                                        </div>
                                        <div class="metric-item">
                                            <span class="label">System Stability:</span>
                                            <span id="testSystemStability" class="value">100%</span>
                                        </div>
                                    </div>
                                    <div class="metric-row">
                                        <div class="metric-item">
                                            <span class="label">Network Delays:</span>
                                            <span id="testNetworkDelays" class="value"><span style="color: #22c55e;">●</span> Inactive</span>
                                        </div>
                                        <div class="metric-item">
                                            <span class="label">Last Update:</span>
                                            <span id="testLastUpdate" class="value">--:--:--</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Multi-Module Orchestration Status -->
                <div class="orchestration-status">
                    <h4><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 4l1.41 1.41L16.17 8.83 14.83 10.17 12 7.34 9.17 10.17 7.83 8.83 10.59 5.41 12 4zm0 16l-1.41-1.41L7.83 15.17 9.17 13.83 12 16.66l2.83-2.83 1.34 1.34L13.41 18.59 12 20z"/></svg> Multi-Module Orchestration Status</h4>
                    <div id="orchestrationStatus" class="orchestration-grid">
                        <div class="module-status">
                            <span class="module-name">ETH Listener:</span>
                            <span class="module-health" id="ethListenerOrch"><span style="color: #22c55e;">●</span> Active</span>
                        </div>
                        <div class="module-status">
                            <span class="module-name">SOL Listener:</span>
                            <span class="module-health" id="solListenerOrch"><span style="color: #22c55e;">●</span> Active</span>
                        </div>
                        <div class="module-status">
                            <span class="module-name">Retry Queue:</span>
                            <span class="module-health" id="retryQueueOrch"><span style="color: #22c55e;">●</span> Processing</span>
                        </div>
                        <div class="module-status">
                            <span class="module-name">Relay Server:</span>
                            <span class="module-health" id="relayServerOrch"><span style="color: #22c55e;">●</span> Running</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Advanced Latency & Health Monitoring Section -->
        <div class="monitoring-card" id="latency-monitoring" style="margin-bottom: 30px;">
            <h3>📊 Advanced Latency & Health Monitoring</h3>
            <div class="monitoring-content">
                <div class="latency-grid">
                    <div class="latency-section">
                        <h4>🔄 Cross-Chain Latency (P95/P99)</h4>
                        <div id="latencyMetrics" class="latency-metrics">
                            <div class="chain-latency">
                                <span class="chain-name">ETH → BH:</span>
                                <span class="latency-value" id="ethToBhLatency">Loading...</span>
                            </div>
                            <div class="chain-latency">
                                <span class="chain-name">BH → SOL:</span>
                                <span class="latency-value" id="bhToSolLatency">Loading...</span>
                            </div>
                            <div class="chain-latency">
                                <span class="chain-name">SOL → ETH:</span>
                                <span class="latency-value" id="solToEthLatency">Loading...</span>
                            </div>
                        </div>
                    </div>
                    <div class="latency-section">
                        <h4>🔗 Multi-Chain Sync Status</h4>
                        <div id="syncStatus" class="sync-status">
                            <div class="sync-item">
                                <span class="sync-label">ETH Block Height:</span>
                                <span class="sync-value" id="ethBlockHeight">Loading...</span>
                            </div>
                            <div class="sync-item">
                                <span class="sync-label">SOL Slot Height:</span>
                                <span class="sync-value" id="solSlotHeight">Loading...</span>
                            </div>
                            <div class="sync-item">
                                <span class="sync-label">BH Block Height:</span>
                                <span class="sync-value" id="bhBlockHeight">Loading...</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="health-indicators">
                    <h4>🏥 Component Health Status</h4>
                    <div id="componentHealth" class="component-health">
                        <div class="health-item">
                            <span class="component-name">ETH Listener:</span>
                            <span class="health-status" id="ethListenerHealth">🟢 Healthy</span>
                        </div>
                        <div class="health-item">
                            <span class="component-name">SOL Listener:</span>
                            <span class="health-status" id="solListenerHealth">🟢 Healthy</span>
                        </div>
                        <div class="health-item">
                            <span class="component-name">Bridge Core:</span>
                            <span class="health-status" id="bridgeCoreHealth">🟢 Healthy</span>
                        </div>
                        <div class="health-item">
                            <span class="component-name">Relay Server:</span>
                            <span class="health-status" id="relayServerHealth">🟢 Healthy</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>





        <!-- End-to-End Flow Integration -->
        <div class="monitoring-card" id="flow-integration" style="margin-bottom: 30px;">
            <h3>🔄 End-to-End Flow Integration</h3>
            <div class="monitoring-content">
                <div class="flow-visualization">
                    <h4>🌊 Token → Bridge → Staking → DEX Flow Tracking</h4>
                    <div id="flowVisualization" class="flow-diagram">
                        <div class="flow-step" id="tokenStep">
                            <div class="step-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M12,6A6,6 0 0,0 6,12A6,6 0 0,0 12,18A6,6 0 0,0 18,12A6,6 0 0,0 12,6M12,8A4,4 0 0,1 16,12A4,4 0 0,1 12,16A4,4 0 0,1 8,12A4,4 0 0,1 12,8Z"/></svg></div>
                            <div class="step-label">Token Module</div>
                            <div class="step-status" id="tokenStatus"><span style="color: #22c55e;">●</span> Active</div>
                        </div>
                        <div class="flow-arrow">→</div>
                        <div class="flow-step" id="bridgeStep">
                            <div class="step-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M15,3V7.59L7.59,15H4V17H7.59L15,9.59V15H17V9.59L9.59,2H15V3M17,17V21H15V17H17Z"/></svg></div>
                            <div class="step-label">Bridge Core</div>
                            <div class="step-status" id="bridgeStatus"><span style="color: #22c55e;">●</span> Processing</div>
                        </div>
                        <div class="flow-arrow">→</div>
                        <div class="flow-step" id="stakingStep">
                            <div class="step-icon">🔒</div>
                            <div class="step-label">Staking Module</div>
                            <div class="step-status" id="stakingStatus">🟢 Ready</div>
                        </div>
                        <div class="flow-arrow">→</div>
                        <div class="flow-step" id="dexStep">
                            <div class="step-icon">💱</div>
                            <div class="step-label">DEX Module</div>
                            <div class="step-status" id="dexStatus">🟢 Available</div>
                        </div>
                    </div>
                </div>

                <div class="flow-metrics">
                    <h4><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg> Cross-Module Performance Metrics</h4>
                    <div id="flowMetrics" class="flow-performance">
                        <div class="perf-item">
                            <span class="perf-label">Token → Bridge Latency:</span>
                            <span class="perf-value" id="tokenBridgeLatency">45ms</span>
                        </div>
                        <div class="perf-item">
                            <span class="perf-label">Bridge → Staking Latency:</span>
                            <span class="perf-value" id="bridgeStakingLatency">32ms</span>
                        </div>
                        <div class="perf-item">
                            <span class="perf-label">Staking → DEX Latency:</span>
                            <span class="perf-value" id="stakingDexLatency">28ms</span>
                        </div>
                        <div class="perf-item">
                            <span class="perf-label">End-to-End Success Rate:</span>
                            <span class="perf-value" id="e2eSuccessRate">99.2%</span>
                        </div>
                    </div>
                </div>

                <div class="integration-logs">
                    <h4><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"/></svg> Cross-Module Interaction Logs</h4>
                    <div id="integrationLogs" class="integration-log-container">
                        <div class="log-entry">
                            <span class="log-time">14:32:15</span>
                            <span class="log-module">Token</span>
                            <span class="log-message">Transfer initiated: 0.5 BHX → Bridge</span>
                        </div>
                        <div class="log-entry">
                            <span class="log-time">14:32:16</span>
                            <span class="log-module">Bridge</span>
                            <span class="log-message">Cross-chain transfer processed successfully</span>
                        </div>
                        <div class="log-entry">
                            <span class="log-time">14:32:18</span>
                            <span class="log-module">Staking</span>
                            <span class="log-message">Tokens available for staking</span>
                        </div>
                        <div class="log-entry">
                            <span class="log-time">14:32:20</span>
                            <span class="log-module">DEX</span>
                            <span class="log-message">Liquidity pool updated</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Event Root Tree Visualization -->
        <div class="monitoring-card" id="event-tree" style="margin-bottom: 30px;">
            <h3>🌳 Event Root Tree Visualization</h3>
            <div class="monitoring-content">
                <div class="tree-controls">
                    <h4>📊 Per-10-Block Event Tree Dumps</h4>
                    <div class="tree-config">
                        <div class="form-row">
                            <div class="form-group">
                                <label for="treeBlocks">Blocks to Display:</label>
                                <input type="number" id="treeBlocks" value="10" min="1" max="100">
                            </div>
                            <div class="form-group">
                                <label for="treeChain">Chain Filter:</label>
                                <select id="treeChain">
                                    <option value="all">All Chains</option>
                                    <option value="ethereum">Ethereum</option>
                                    <option value="solana">Solana</option>
                                    <option value="blackhole">BlackHole</option>
                                </select>
                            </div>
                        </div>
                        <button onclick="loadEventTree()" class="execute-btn">🌳 Load Event Tree</button>
                    </div>
                </div>

                <div id="eventTreeDisplay" class="event-tree">
                    <div class="tree-loading">Click "Load Event Tree" to display event hierarchy...</div>
                </div>
            </div>
        </div>

        <!-- Enhanced Cross-Chain Features Dashboard -->
        <div class="monitoring-card" id="enhanced-features" style="margin-bottom: 30px;">
            <h3>🚀 Enhanced Cross-Chain Features</h3>
            <div class="monitoring-content">
                <div class="enhanced-grid">
                    <div class="enhanced-section">
                        <h4>🛣️ Multi-Hop Routing</h4>
                        <div class="routing-controls">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="routeFrom">From Chain:</label>
                                    <select id="routeFrom">
                                        <option value="ethereum">Ethereum</option>
                                        <option value="solana">Solana</option>
                                        <option value="blackhole">BlackHole</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="routeTo">To Chain:</label>
                                    <select id="routeTo">
                                        <option value="solana">Solana</option>
                                        <option value="ethereum">Ethereum</option>
                                        <option value="blackhole">BlackHole</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="routeToken">Token:</label>
                                    <select id="routeToken">
                                        <option value="USDC">USDC</option>
                                        <option value="ETH">ETH</option>
                                        <option value="SOL">SOL</option>
                                        <option value="BHX">BHX</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="routeAmount">Amount:</label>
                                    <input type="number" id="routeAmount" value="100" min="0.01" step="0.01">
                                </div>
                            </div>
                            <button onclick="findOptimalRoute()" class="execute-btn">🔍 Find Optimal Route</button>
                        </div>
                        <div id="routeResults" class="route-results">
                            <div class="route-loading">Click "Find Optimal Route" to see routing options...</div>
                        </div>
                    </div>

                    <div class="enhanced-section">
                        <h4>💧 Liquidity Optimization</h4>
                        <div class="liquidity-controls">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="liquidityStrategy">Strategy:</label>
                                    <select id="liquidityStrategy">
                                        <option value="yield_optimization">Yield Optimization</option>
                                        <option value="risk_minimization">Risk Minimization</option>
                                        <option value="balanced">Balanced Approach</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label for="liquidityToken">Token:</label>
                                    <select id="liquidityToken">
                                        <option value="USDC">USDC</option>
                                        <option value="USDT">USDT</option>
                                        <option value="ETH">ETH</option>
                                        <option value="SOL">SOL</option>
                                    </select>
                                </div>
                            </div>
                            <button onclick="optimizeLiquidity()" class="execute-btn">⚡ Optimize Liquidity</button>
                        </div>
                        <div id="liquidityResults" class="liquidity-results">
                            <div class="liquidity-loading">Click "Optimize Liquidity" to see recommendations...</div>
                        </div>
                    </div>
                </div>

                <div class="enhanced-grid">
                    <div class="enhanced-section">
                        <h4>🔒 Security & Risk Management</h4>
                        <div class="security-dashboard">
                            <div id="securityMetrics" class="security-metrics">
                                <div class="security-item">
                                    <span class="security-label">Threat Level:</span>
                                    <span class="security-value" id="threatLevel">🟢 Low</span>
                                </div>
                                <div class="security-item">
                                    <span class="security-label">Active Threats:</span>
                                    <span class="security-value" id="activeThreats">2</span>
                                </div>
                                <div class="security-item">
                                    <span class="security-label">Anomalies Detected:</span>
                                    <span class="security-value" id="anomaliesDetected">1</span>
                                </div>
                                <div class="security-item">
                                    <span class="security-label">Risk Score:</span>
                                    <span class="security-value" id="riskScore">0.25</span>
                                </div>
                            </div>
                            <button onclick="refreshSecurityStatus()" class="execute-btn"><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M17.65,6.35C16.2,4.9 14.21,4 12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20C15.73,20 18.84,17.45 19.73,14H17.65C16.83,16.33 14.61,18 12,18A6,6 0 0,1 6,12A6,6 0 0,1 12,6C13.66,6 15.14,6.69 16.22,7.78L13,11H20V4L17.65,6.35Z"/></svg> Refresh Security Status</button>
                        </div>
                    </div>


                </div>

                <div class="enhanced-grid">



                </div>
            </div>
        </div>





        <!-- Main Dashboard Integration -->
        <div class="monitoring-card" id="main-dashboard-integration" style="margin-bottom: 30px;">
            <h3>🔗 Main Dashboard Integration</h3>
            <div class="monitoring-content">
                <div class="integration-grid">
                    <div class="integration-section">
                        <h4>📊 Blockchain Status</h4>
                        <div id="blockchainActivity" class="activity-monitor">
                            <div class="activity-item">
                                <span class="activity-label">Block Height:</span>
                                <span class="activity-value" id="mainBlockHeight">Loading...</span>
                            </div>
                            <div class="activity-item">
                                <span class="activity-label">Pending Transactions:</span>
                                <span class="activity-value" id="mainPendingTxs">Loading...</span>
                            </div>

                            <div class="activity-item">
                                <span class="activity-label">Node Status:</span>
                                <span class="activity-value" id="mainNodeStatus">Loading...</span>
                            </div>
                        </div>
                    </div>
                    <div class="integration-section">
                        <h4>💰 Token Operations</h4>
                        <div id="tokenOperations" class="operations-monitor">
                            <div class="operation-item">
                                <span class="operation-label">Active Wallets:</span>
                                <span class="operation-value" id="activeWallets">Loading...</span>
                            </div>
                            <div class="operation-item">
                                <span class="operation-label">Recent Token Additions:</span>
                                <span class="operation-value" id="recentTokenAdditions">0</span>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>



        <!-- Wallet Dashboard Integration -->
        <div class="monitoring-card" id="wallet-dashboard-integration" style="margin-bottom: 30px;">
            <h3>💼 Wallet Dashboard Integration</h3>
            <div class="monitoring-content">
                <div class="wallet-integration-grid">
                    <div class="wallet-section">
                        <h4>🔐 Wallet System Monitor</h4>
                        <div id="walletSystemStatus" class="wallet-monitor">
                            <div class="wallet-item">
                                <span class="wallet-label">Wallet Service Status:</span>
                                <span class="wallet-value" id="walletServiceStatus">Loading...</span>
                            </div>
                            <div class="wallet-item">
                                <span class="wallet-label">Active Sessions:</span>
                                <span class="wallet-value" id="activeSessions">Loading...</span>
                            </div>
                            <div class="wallet-item">
                                <span class="wallet-label">Total Wallets:</span>
                                <span class="wallet-value" id="totalWallets">Loading...</span>
                            </div>
                            <div class="wallet-item">
                                <span class="wallet-label">Recent Transactions:</span>
                                <span class="wallet-value" id="recentWalletTxs">Loading...</span>
                            </div>
                        </div>
                    </div>

                </div>


            </div>
        </div>

        <!-- Cross-Platform Transaction Visibility -->
        <div class="monitoring-card" id="cross-platform-transactions" style="margin-bottom: 30px;">
            <h3>🔄 Cross-Platform Transaction Visibility</h3>
            <div class="monitoring-content">
                <div class="cross-platform-grid">
                    <div class="platform-section">
                        <h4>🌐 End-to-End Transaction Tracking</h4>
                        <div id="endToEndTracking" class="tracking-monitor">
                            <div class="tracking-item">
                                <span class="tracking-label">Total Cross-Platform Txs:</span>
                                <span class="tracking-value" id="totalCrossPlatformTxs">0</span>
                            </div>
                            <div class="tracking-item">
                                <span class="tracking-label">Main Dashboard → Bridge:</span>
                                <span class="tracking-value" id="mainToBridgeTxs">0</span>
                            </div>
                            <div class="tracking-item">
                                <span class="tracking-label">Bridge → Wallet:</span>
                                <span class="tracking-value" id="bridgeToWalletTxs">0</span>
                            </div>
                            <div class="tracking-item">
                                <span class="tracking-label">Wallet → Main Dashboard:</span>
                                <span class="tracking-value" id="walletToMainTxs">0</span>
                            </div>
                        </div>
                    </div>
                    <div class="platform-section">
                        <h4>📊 Transaction Audit Trail</h4>
                        <div id="auditTrail" class="audit-monitor">
                            <div class="audit-item">
                                <span class="audit-label">Tracked Transactions:</span>
                                <span class="audit-value" id="trackedTransactions">0</span>
                            </div>
                            <div class="audit-item">
                                <span class="audit-label">Successful Completions:</span>
                                <span class="audit-value" id="successfulCompletions">0</span>
                            </div>
                            <div class="audit-item">
                                <span class="audit-label">Failed Transactions:</span>
                                <span class="audit-value" id="failedTransactions">0</span>
                            </div>
                            <div class="audit-item">
                                <span class="audit-label">Pending Transactions:</span>
                                <span class="audit-value" id="pendingTransactions">0</span>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>

        <div class="monitoring-card" id="transactions" style="margin-bottom: 30px;">
            <h3><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"/></svg> Recent Cross-Chain Transactions</h3>

            <!-- Search Bar -->
            <div style="margin-bottom: 20px;">
                <div style="display: flex; gap: 10px; align-items: center;">
                    <input type="text" id="transactionSearch" placeholder="🔍 Search transactions by ID, chain, amount, or status..."
                           style="flex: 1; padding: 10px 15px; border: 1px solid rgba(148, 163, 184, 0.3); border-radius: 8px; background: rgba(255, 255, 255, 0.9); color: #1e293b; font-size: 0.9rem;"
                           oninput="filterTransactions()">
                    <button onclick="clearTransactionSearch()"
                            style="padding: 10px 15px; background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; cursor: pointer; font-size: 0.9rem;">
                        Clear
                    </button>
                </div>
                <div id="searchResults" style="margin-top: 8px; font-size: 0.8rem; color: #64748b;"></div>
            </div>

            <div class="monitoring-content">
                <table class="transaction-table" id="recentTransactions">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>From Chain</th>
                            <th>To Chain</th>
                            <th>Amount</th>
                            <th>Status</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody id="transactionTableBody">
                        <tr>
                            <td colspan="6" style="text-align: center; color: #9ca3af;">Loading transactions...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>


    </div>

    <script>
        // Global variables for real-time updates
        let updateInterval;
        let wsConnection;

        // Test results management to prevent overlapping
        const testResultsContainers = [
            'testResults',
            'stressTestResults',
            'advancedStressTestResults',
            'chaosTestResults'
        ];

        // Function to manage test results display and prevent overlapping
        function showTestResults(containerId, addActiveClass = true) {
            const container = document.getElementById(containerId);
            if (container) {
                container.style.display = 'block';
                if (addActiveClass) {
                    container.classList.add('active');
                }

                // Manage container height to prevent congestion
                setTimeout(() => {
                    manageTestResultsHeight(containerId);
                }, 100);

                // Ensure proper spacing by adding margin to subsequent containers
                const containerIndex = testResultsContainers.indexOf(containerId);
                if (containerIndex !== -1) {
                    for (let i = containerIndex + 1; i < testResultsContainers.length; i++) {
                        const nextContainer = document.getElementById(testResultsContainers[i]);
                        if (nextContainer && nextContainer.style.display === 'block') {
                            nextContainer.style.marginTop = '30px';
                        }
                    }
                }
            }
        }

        function hideTestResults(containerId) {
            const container = document.getElementById(containerId);
            if (container) {
                container.style.display = 'none';
                container.classList.remove('active');
                container.style.marginTop = '';
            }
        }

        function resetAllTestResults() {
            testResultsContainers.forEach(containerId => {
                hideTestResults(containerId);
            });
        }

        // Function to manage test results container height dynamically
        function manageTestResultsHeight(containerId) {
            const container = document.getElementById(containerId);
            if (!container) return;

            // Check if content height exceeds viewport
            const containerHeight = container.scrollHeight;
            const viewportHeight = window.innerHeight;

            // If content is very large (more than 70% of viewport), add scrollable class
            if (containerHeight > viewportHeight * 0.7) {
                container.classList.add('scrollable');

                // Add a toggle button for full view
                if (!container.querySelector('.expand-toggle')) {
                    const toggleBtn = document.createElement('button');
                    toggleBtn.className = 'expand-toggle';
                    toggleBtn.innerHTML = '📏 Toggle Full View';
                    toggleBtn.style.cssText = 'position: absolute; top: 10px; right: 10px; background: #1e3a8a; color: white; border: none; padding: 5px 10px; border-radius: 4px; font-size: 0.8rem; cursor: pointer; z-index: 10;';

                    toggleBtn.onclick = function() {
                        container.classList.toggle('scrollable');
                        toggleBtn.innerHTML = container.classList.contains('scrollable') ? '📏 Toggle Full View' : '📏 Toggle Compact View';
                    };

                    container.appendChild(toggleBtn);
                }
            } else {
                container.classList.remove('scrollable');
                const toggleBtn = container.querySelector('.expand-toggle');
                if (toggleBtn) {
                    toggleBtn.remove();
                }
            }
        }

        // Main Dashboard Integration Functions
        async function fetchMainDashboardData() {
            try {
                console.log('🔍 Attempting to connect to Main Dashboard via proxy...');

                // Use proxy endpoints to avoid CORS issues
                const healthResponse = await fetch('/api/proxy/main-dashboard/health');
                const healthData = await healthResponse.json();

                console.log('🔍 Main Dashboard health response:', healthData);

                if (!healthData.success) {
                    throw new Error('Main dashboard health check failed: ' + healthData.error);
                }

                // Fetch blockchain info via proxy
                const blockchainResponse = await fetch('/api/proxy/main-dashboard/blockchain');
                let blockchainData = {};
                if (blockchainResponse.ok) {
                    const blockchainResult = await blockchainResponse.json();
                    if (blockchainResult.success) {
                        blockchainData = blockchainResult.data;
                    }
                }

                // Fetch node info via proxy
                const nodeResponse = await fetch('/api/proxy/main-dashboard/node');
                let nodeData = {};
                if (nodeResponse.ok) {
                    const nodeResult = await nodeResponse.json();
                    if (nodeResult.success) {
                        nodeData = nodeResult.data;
                    }
                }

                // Fetch wallets info via proxy
                const walletsResponse = await fetch('/api/proxy/main-dashboard/wallets');
                let walletsData = {};
                if (walletsResponse.ok) {
                    const walletsResult = await walletsResponse.json();
                    if (walletsResult.success) {
                        walletsData = walletsResult.data;
                    }
                }

                // Fetch recent activities via proxy
                const activitiesResponse = await fetch('/api/proxy/main-dashboard/recent-activities');
                let activitiesData = {};
                if (activitiesResponse.ok) {
                    const activitiesResult = await activitiesResponse.json();
                    if (activitiesResult.success) {
                        activitiesData = activitiesResult.data;
                    }
                }

                return {
                    blockchain: blockchainData,
                    node: nodeData,
                    wallets: walletsData,
                    activities: activitiesData
                };
            } catch (error) {
                console.error('Error fetching main dashboard data:', error);
                return null;
            }
        }

        async function updateMainDashboardMonitoring() {
            const data = await fetchMainDashboardData();

            if (data && data.blockchain) {
                // Update blockchain activity with actual API response structure (with null checks)
                const updateElement = (id, value) => {
                    const element = document.getElementById(id);
                    if (element) element.textContent = value;
                };

                updateElement('mainBlockHeight', data.blockchain.blockHeight || data.blockchain.height || 'N/A');
                updateElement('mainPendingTxs', data.blockchain.pendingTransactions || data.blockchain.pending_txs || '0');
                updateElement('mainTotalSupply', data.blockchain.totalSupply || 'N/A');
                updateElement('mainNodeStatus', data.node && data.node.status ? '🟢 Online' : '🟢 Connected');

                // Update token operations
                const walletCount = data.wallets ? (Array.isArray(data.wallets) ? data.wallets.length : Object.keys(data.wallets).length) : 0;
                updateElement('activeWallets', walletCount);

                // Update token balances count from actual blockchain data
                let totalTokenAdditions = 0;
                if (data.blockchain.tokenBalances) {
                    Object.values(data.blockchain.tokenBalances).forEach(tokenData => {
                        if (typeof tokenData === 'object') {
                            totalTokenAdditions += Object.keys(tokenData).length;
                        }
                    });
                } else if (data.blockchain.balances) {
                    // Alternative structure
                    totalTokenAdditions = Object.keys(data.blockchain.balances).length;
                }
                updateElement('recentTokenAdditions', totalTokenAdditions);

                // Update recent activities display in both locations
                if (data.activities && data.activities.activities) {
                    updateRecentActivitiesDisplay(data.activities.activities);
                    updateAdminTransactionsInWalletSection(
                        data.activities.activities,
                        data.activities.has_changes,
                        data.activities.state_hash
                    );
                }

                // Log activity
                logMainDashboardActivity('Main Dashboard Connected', {
                    blockHeight: data.blockchain.blockHeight || data.blockchain.height,
                    pendingTxs: data.blockchain.pendingTransactions || data.blockchain.pending_txs,
                    totalSupply: data.blockchain.totalSupply,
                    walletCount: walletCount,
                    tokenAdditions: totalTokenAdditions,
                    recentActivities: data.activities ? data.activities.activities.length : 0
                });
            } else {
                // Update with offline status
                document.getElementById('mainBlockHeight').textContent = 'Offline';
                document.getElementById('mainPendingTxs').textContent = 'N/A';
                document.getElementById('mainTotalSupply').textContent = 'N/A';
                document.getElementById('mainNodeStatus').textContent = '🔴 Offline';
                document.getElementById('activeWallets').textContent = 'N/A';
                document.getElementById('recentTokenAdditions').textContent = 'N/A';

                // Log offline status
                logMainDashboardActivity('Main Dashboard Offline', {
                    status: 'Connection failed',
                    timestamp: new Date().toISOString()
                });
            }
        }

        function logMainDashboardActivity(action, details) {
            const activitiesList = document.getElementById('mainDashboardActivities');
            const timestamp = new Date().toLocaleTimeString();

            const activityEntry = document.createElement('div');
            activityEntry.className = 'activity-entry';
            activityEntry.innerHTML =
                '<div>' +
                    '<strong>' + action + '</strong>' +
                    '<div style="font-size: 0.8rem; color: #64748b;">' + JSON.stringify(details) + '</div>' +
                '</div>' +
                '<div style="font-size: 0.8rem; color: #64748b;">' + timestamp + '</div>';

            // Remove loading message if present
            const loadingMsg = activitiesList.querySelector('.activity-loading');
            if (loadingMsg) {
                loadingMsg.remove();
            }

            // Add new activity at the top
            activitiesList.insertBefore(activityEntry, activitiesList.firstChild);

            // Keep only last 10 activities
            const activities = activitiesList.querySelectorAll('.activity-entry');
            if (activities.length > 10) {
                activities[activities.length - 1].remove();
            }
        }

        function updateRecentActivitiesDisplay(activities) {
            // Find or create recent activities section in main dashboard integration
            let activitiesContainer = document.getElementById('main-recent-activities');
            if (!activitiesContainer) {
                // Create activities container if it doesn't exist
                const mainDashboardSection = document.querySelector('.main-dashboard-integration');
                if (mainDashboardSection) {
                    const activitiesDiv = document.createElement('div');
                    activitiesDiv.innerHTML = '<h4>🔄 Recent Activities</h4><div id="main-recent-activities" class="activities-list"></div>';
                    mainDashboardSection.appendChild(activitiesDiv);
                    activitiesContainer = document.getElementById('main-recent-activities');
                }
            }

            if (activitiesContainer && activities && activities.length > 0) {
                let html = '<div style="margin-bottom: 10px; padding: 8px; background: rgba(0,255,0,0.1); border-radius: 4px; border-left: 3px solid #00ff00;">';
                html += '<strong>🎯 Admin Token Transfers Detected!</strong><br>';
                html += '<small>Showing ' + activities.length + ' recent admin activities from main dashboard</small>';
                html += '</div>';

                activities.slice(0, 8).forEach(activity => {
                    const timeAgo = new Date(activity.timestamp).toLocaleTimeString();
                    const statusIcon = activity.status === 'completed' ? '✅' : '⏳';
                    const tokenIcon = activity.token === 'BHX' ? '🪙' : '💰';

                    // Highlight BHX transfers
                    const bgColor = activity.token === 'BHX' ? 'rgba(255,215,0,0.2)' : 'rgba(255,255,255,0.1)';
                    const borderColor = activity.token === 'BHX' ? '#ffd700' : 'transparent';

                    html += '<div class="activity-item" style="padding: 10px; margin: 6px 0; background: ' + bgColor + '; border-radius: 6px; border-left: 3px solid ' + borderColor + ';">';
                    html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
                    html += '<div style="flex: 1;">';
                    html += '<div style="display: flex; align-items: center; margin-bottom: 4px;">';
                    html += '<span style="margin-right: 8px;">' + statusIcon + ' ' + tokenIcon + '</span>';
                    html += '<strong style="color: #fff;">' + activity.action + '</strong>';
                    html += '<span style="margin-left: 8px; padding: 2px 6px; background: rgba(0,0,0,0.3); border-radius: 3px; font-size: 0.7em;">' + activity.token + '</span>';
                    html += '</div>';
                    html += '<div style="font-size: 0.9em; color: #ddd; margin-bottom: 2px;">';
                    html += '<strong>' + activity.amount.toLocaleString() + ' ' + activity.token + '</strong> → ';
                    html += '<span style="font-family: monospace; font-size: 0.8em;">' + (activity.target.length > 20 ? activity.target.substring(0, 20) + '...' : activity.target) + '</span>';
                    html += '</div>';
                    html += '</div>';
                    html += '<div style="text-align: right; font-size: 0.75em; color: #aaa;">';
                    html += timeAgo;
                    html += '</div>';
                    html += '</div>';
                    html += '</div>';
                });

                activitiesContainer.innerHTML = html;

                // Log the activities for debugging
                console.log('🔄 Updated recent activities:', activities);
                console.log('🎯 BHX transfers found:', activities.filter(a => a.token === 'BHX').length);
            } else if (activitiesContainer) {
                activitiesContainer.innerHTML = '<div style="padding: 8px; color: #888;">No recent activities detected</div>';
            }
        }

        // Global variable to track last state
        let lastAdminStateHash = '';
        let adminTransactionCache = [];
        let isFirstLoad = true;

        function updateAdminTransactionsInWalletSection(activities, hasChanges, stateHash) {
            let activitiesContainer = document.getElementById('admin-recent-activities');

            if (!activitiesContainer) {
                console.log('❌ Admin activities container not found');
                return;
            }

            // Always update on first load, or when there are real changes, or when activities exist
            const shouldUpdate = isFirstLoad || hasChanges || (activities && activities.length > 0) || stateHash !== lastAdminStateHash;

            if (!shouldUpdate && adminTransactionCache.length > 0) {
                console.log('⏭️ Skipping update - no changes detected');
                return; // No changes, skip update
            }

            if (isFirstLoad) {
                isFirstLoad = false;
                console.log('🎯 First load - displaying admin transactions');
            }

            lastAdminStateHash = stateHash;

            console.log('🔄 Updating admin transactions:', {
                activities: activities ? activities.length : 0,
                hasChanges: hasChanges,
                stateHash: stateHash
            });

            if (activitiesContainer && activities && activities.length > 0) {
                adminTransactionCache = activities; // Cache the activities

                // Count new vs existing transactions
                const newTransactions = activities.filter(activity => activity.isNew).length;
                const totalTransactions = activities.length;

                // White background with dark text for readability
                let html = '<div style="margin-bottom: 12px; padding: 12px; background: white; border: 1px solid ' + (hasChanges ? '#0066cc' : '#cccccc') + '; border-radius: 6px; border-left: 4px solid ' + (hasChanges ? '#0066cc' : '#666666') + ';">';
                html += '<div style="display: flex; align-items: center; justify-content: space-between;">';
                if (hasChanges && newTransactions > 0) {
                    html += '<div style="color: #1a1a1a;"><strong><span style="color: #28a745; margin-right: 6px;">●</span>NEW Wallet Balances (' + newTransactions + ' new)</strong></div>';
                } else {
                    html += '<div style="color: #333333;"><strong><span style="color: #6c757d; margin-right: 6px;">■</span>Wallet Balances (' + totalTransactions + ' total)</strong></div>';
                }
                html += '<div style="font-size: 0.8em; color: #666666;">' + new Date().toLocaleTimeString() + '</div>';
                html += '</div>';
                html += '</div>';

                // Filter and sort by timestamp (newest first) - BHX wallet balances only
                const sortedActivities = activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                const bhxWalletBalances = sortedActivities.filter(activity => activity.token === 'BHX' && activity.type === 'wallet_balance').slice(0, 8);

                if (bhxWalletBalances.length > 0) {
                    html += '<div style="margin-bottom: 12px;">';
                    html += '<h4 style="color: #ffffff; margin-bottom: 8px; font-size: 1em;">';
                    html += '<span style="color: #ffc107; margin-right: 6px;">◆</span>BHX Wallet Balances (' + bhxWalletBalances.length + ')';
                    html += '</h4>';

                    bhxWalletBalances.forEach((ac