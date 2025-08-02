package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// FlagInfo represents a fraud flag report
type FlagInfo struct {
	Timestamp  int64  `json:"timestamp"`
	ReporterID string `json:"reporter_id"`
	Reason     string `json:"reason"`
	Severity   int    `json:"severity"` // 1-5 scale
	IsActive   bool   `json:"is_active"`
}

// FraudDetectionContract implements fraud detection functionality
type FraudDetectionContract struct {
	// Contract state storage
	WalletFlags map[string][]FlagInfo      `json:"wallet_flags"`
	FlagCounts  map[string]int             `json:"flag_counts"`
	HasReported map[string]map[string]bool `json:"has_reported"`
	Owner       string                     `json:"owner"`
	DeployedAt  int64                      `json:"deployed_at"`
}

// ContractEvent is defined in the main testnet file

// NewFraudDetectionContract creates a new fraud detection contract instance
func NewFraudDetectionContract(owner string) *FraudDetectionContract {
	return &FraudDetectionContract{
		WalletFlags: make(map[string][]FlagInfo),
		FlagCounts:  make(map[string]int),
		HasReported: make(map[string]map[string]bool),
		Owner:       owner,
		DeployedAt:  time.Now().Unix(),
	}
}

// FlagWallet flags a wallet as suspicious
// This is the main function your fraud detection website needs
func (fdc *FraudDetectionContract) FlagWallet(walletAddress, reporterID, reason string, severity int) (map[string]interface{}, error) {
	// Input validation
	if walletAddress == "" {
		return nil, fmt.Errorf("wallet address cannot be empty")
	}
	if reporterID == "" {
		return nil, fmt.Errorf("reporter ID cannot be empty")
	}
	if reason == "" {
		return nil, fmt.Errorf("reason cannot be empty")
	}
	if severity < 1 || severity > 5 {
		return nil, fmt.Errorf("severity must be between 1 and 5")
	}

	// Check if reporter has already flagged this wallet
	if fdc.HasReported[walletAddress] == nil {
		fdc.HasReported[walletAddress] = make(map[string]bool)
	}

	if fdc.HasReported[walletAddress][reporterID] {
		return nil, fmt.Errorf("reporter has already flagged this wallet")
	}

	// Create new flag
	newFlag := FlagInfo{
		Timestamp:  time.Now().Unix(),
		ReporterID: reporterID,
		Reason:     reason,
		Severity:   severity,
		IsActive:   true,
	}

	// Add flag to wallet's flags
	fdc.WalletFlags[walletAddress] = append(fdc.WalletFlags[walletAddress], newFlag)

	// Increment flag count
	fdc.FlagCounts[walletAddress]++

	// Mark reporter as having reported this wallet
	fdc.HasReported[walletAddress][reporterID] = true

	// Return success response with event data
	result := map[string]interface{}{
		"success":        true,
		"wallet_address": walletAddress,
		"reporter_id":    reporterID,
		"reason":         reason,
		"severity":       severity,
		"timestamp":      newFlag.Timestamp,
		"flag_count":     fdc.FlagCounts[walletAddress],
		"message":        fmt.Sprintf("Wallet %s flagged successfully by %s", walletAddress, reporterID),
	}

	return result, nil
}

// GetReportCount returns the number of times a wallet has been flagged
// This is the second main function your fraud detection website needs
func (fdc *FraudDetectionContract) GetReportCount(walletAddress string) (map[string]interface{}, error) {
	if walletAddress == "" {
		return nil, fmt.Errorf("wallet address cannot be empty")
	}

	count := fdc.FlagCounts[walletAddress]

	result := map[string]interface{}{
		"success":        true,
		"wallet_address": walletAddress,
		"report_count":   count,
		"message":        fmt.Sprintf("Wallet %s has been flagged %d times", walletAddress, count),
	}

	return result, nil
}

// GetWalletFlags returns detailed flag information for a wallet
func (fdc *FraudDetectionContract) GetWalletFlags(walletAddress string) (map[string]interface{}, error) {
	if walletAddress == "" {
		return nil, fmt.Errorf("wallet address cannot be empty")
	}

	flags := fdc.WalletFlags[walletAddress]
	if flags == nil {
		flags = []FlagInfo{}
	}

	// Filter only active flags
	activeFlags := []FlagInfo{}
	for _, flag := range flags {
		if flag.IsActive {
			activeFlags = append(activeFlags, flag)
		}
	}

	result := map[string]interface{}{
		"success":        true,
		"wallet_address": walletAddress,
		"flags":          activeFlags,
		"total_flags":    len(activeFlags),
		"message":        fmt.Sprintf("Retrieved %d active flags for wallet %s", len(activeFlags), walletAddress),
	}

	return result, nil
}

// GetMaxSeverity returns the highest severity flag for a wallet
func (fdc *FraudDetectionContract) GetMaxSeverity(walletAddress string) (map[string]interface{}, error) {
	if walletAddress == "" {
		return nil, fmt.Errorf("wallet address cannot be empty")
	}

	flags := fdc.WalletFlags[walletAddress]
	maxSeverity := 0

	for _, flag := range flags {
		if flag.IsActive && flag.Severity > maxSeverity {
			maxSeverity = flag.Severity
		}
	}

	result := map[string]interface{}{
		"success":        true,
		"wallet_address": walletAddress,
		"max_severity":   maxSeverity,
		"risk_level":     getSeverityLevel(maxSeverity),
		"message":        fmt.Sprintf("Maximum severity for wallet %s is %d", walletAddress, maxSeverity),
	}

	return result, nil
}

// HasReporterFlagged checks if a specific reporter has flagged a wallet
func (fdc *FraudDetectionContract) HasReporterFlagged(walletAddress, reporterID string) (map[string]interface{}, error) {
	if walletAddress == "" {
		return nil, fmt.Errorf("wallet address cannot be empty")
	}
	if reporterID == "" {
		return nil, fmt.Errorf("reporter ID cannot be empty")
	}

	hasReported := false
	if fdc.HasReported[walletAddress] != nil {
		hasReported = fdc.HasReported[walletAddress][reporterID]
	}

	result := map[string]interface{}{
		"success":        true,
		"wallet_address": walletAddress,
		"reporter_id":    reporterID,
		"has_reported":   hasReported,
		"message":        fmt.Sprintf("Reporter %s has reported wallet %s: %v", reporterID, walletAddress, hasReported),
	}

	return result, nil
}

// RemoveFlag removes a specific flag (admin function)
func (fdc *FraudDetectionContract) RemoveFlag(walletAddress string, flagIndex int, caller string) (map[string]interface{}, error) {
	// Only owner can remove flags
	if caller != fdc.Owner {
		return nil, fmt.Errorf("only contract owner can remove flags")
	}

	if walletAddress == "" {
		return nil, fmt.Errorf("wallet address cannot be empty")
	}

	flags := fdc.WalletFlags[walletAddress]
	if flagIndex < 0 || flagIndex >= len(flags) {
		return nil, fmt.Errorf("invalid flag index")
	}

	if !flags[flagIndex].IsActive {
		return nil, fmt.Errorf("flag is already inactive")
	}

	// Mark flag as inactive
	fdc.WalletFlags[walletAddress][flagIndex].IsActive = false

	// Decrease flag count
	if fdc.FlagCounts[walletAddress] > 0 {
		fdc.FlagCounts[walletAddress]--
	}

	result := map[string]interface{}{
		"success":        true,
		"wallet_address": walletAddress,
		"flag_index":     flagIndex,
		"removed_by":     caller,
		"timestamp":      time.Now().Unix(),
		"message":        fmt.Sprintf("Flag %d removed from wallet %s by %s", flagIndex, walletAddress, caller),
	}

	return result, nil
}

// GetContractInfo returns contract metadata
func (fdc *FraudDetectionContract) GetContractInfo() (map[string]interface{}, error) {
	totalWallets := len(fdc.WalletFlags)
	totalFlags := 0
	for _, count := range fdc.FlagCounts {
		totalFlags += count
	}

	result := map[string]interface{}{
		"success":       true,
		"contract_name": "FraudDetectionContract",
		"owner":         fdc.Owner,
		"deployed_at":   fdc.DeployedAt,
		"total_wallets": totalWallets,
		"total_flags":   totalFlags,
		"version":       "1.0.0",
		"message":       "Fraud Detection Contract - Blackhole Blockchain",
	}

	return result, nil
}

// GetState returns the entire contract state (for debugging/admin)
func (fdc *FraudDetectionContract) GetState() (map[string]interface{}, error) {
	state := map[string]interface{}{
		"wallet_flags": fdc.WalletFlags,
		"flag_counts":  fdc.FlagCounts,
		"has_reported": fdc.HasReported,
		"owner":        fdc.Owner,
		"deployed_at":  fdc.DeployedAt,
	}

	return state, nil
}

// Helper function to convert severity to risk level
func getSeverityLevel(severity int) string {
	switch severity {
	case 1:
		return "very_low"
	case 2:
		return "low"
	case 3:
		return "medium"
	case 4:
		return "high"
	case 5:
		return "critical"
	default:
		return "unknown"
	}
}

// ExecuteFunction handles function calls to the contract
func (fdc *FraudDetectionContract) ExecuteFunction(functionName string, args []string) (map[string]interface{}, error) {
	switch functionName {
	case "flagWallet":
		if len(args) < 4 {
			return nil, fmt.Errorf("flagWallet requires 4 arguments: walletAddress, reporterID, reason, severity")
		}
		severity, err := strconv.Atoi(args[3])
		if err != nil {
			return nil, fmt.Errorf("invalid severity value: %s", args[3])
		}
		return fdc.FlagWallet(args[0], args[1], args[2], severity)

	case "getReportCount":
		if len(args) < 1 {
			return nil, fmt.Errorf("getReportCount requires 1 argument: walletAddress")
		}
		return fdc.GetReportCount(args[0])

	case "getWalletFlags":
		if len(args) < 1 {
			return nil, fmt.Errorf("getWalletFlags requires 1 argument: walletAddress")
		}
		return fdc.GetWalletFlags(args[0])

	case "getMaxSeverity":
		if len(args) < 1 {
			return nil, fmt.Errorf("getMaxSeverity requires 1 argument: walletAddress")
		}
		return fdc.GetMaxSeverity(args[0])

	case "hasReporterFlagged":
		if len(args) < 2 {
			return nil, fmt.Errorf("hasReporterFlagged requires 2 arguments: walletAddress, reporterID")
		}
		return fdc.HasReporterFlagged(args[0], args[1])

	case "removeFlag":
		if len(args) < 3 {
			return nil, fmt.Errorf("removeFlag requires 3 arguments: walletAddress, flagIndex, caller")
		}
		flagIndex, err := strconv.Atoi(args[1])
		if err != nil {
			return nil, fmt.Errorf("invalid flag index: %s", args[1])
		}
		return fdc.RemoveFlag(args[0], flagIndex, args[2])

	case "getContractInfo":
		return fdc.GetContractInfo()

	case "getState":
		return fdc.GetState()

	default:
		return nil, fmt.Errorf("unknown function: %s", functionName)
	}
}

// Serialize contract state to JSON
func (fdc *FraudDetectionContract) Serialize() ([]byte, error) {
	return json.Marshal(fdc)
}

// Deserialize contract state from JSON
func (fdc *FraudDetectionContract) Deserialize(data []byte) error {
	return json.Unmarshal(data, fdc)
}

// TestFraudDetectionContract tests the contract functionality (for debugging)
func TestFraudDetectionContract() {
	// This is just for testing the contract locally
	contract := NewFraudDetectionContract("test_owner")

	// Test flagging a wallet
	result, err := contract.FlagWallet("wallet123", "reporter1", "Suspicious activity", 3)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Flag result: %+v\n", result)

	// Test getting report count
	countResult, err := contract.GetReportCount("wallet123")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Count result: %+v\n", countResult)
}
