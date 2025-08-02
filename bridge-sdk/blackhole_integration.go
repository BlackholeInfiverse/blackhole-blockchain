package bridgesdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// BlackHoleIntegration handles integration with BlackHole blockchain
type BlackHoleIntegration struct {
	apiURL string
	logger interface{} // Will be *logrus.Logger
}

// NewBlackHoleIntegration creates a new BlackHole integration
func NewBlackHoleIntegration(apiURL string, logger interface{}) *BlackHoleIntegration {
	return &BlackHoleIntegration{
		apiURL: apiURL,
		logger: logger,
	}
}

// BlackHoleTransaction represents a transaction for BlackHole blockchain
type BlackHoleTransaction struct {
	Type      string `json:"type"`
	From      string `json:"from"`
	To        string `json:"to"`
	Amount    uint64 `json:"amount"`    // Changed to uint64
	TokenID   string `json:"token_id"`  // Correct for /api/relay/submit
	Fee       uint64 `json:"fee"`       // Changed to uint64
	Nonce     uint64 `json:"nonce"`     // Changed to uint64 to match API
	Timestamp int64  `json:"timestamp"`
}

// BlackHoleResponse represents response from BlackHole API
type BlackHoleResponse struct {
	Success       bool   `json:"success"`
	TransactionID string `json:"transaction_id"`
	Status        string `json:"status"`
	SubmittedAt   int64  `json:"submitted_at"`
	Error         string `json:"error,omitempty"`
}

// SubmitTransaction submits a transaction to BlackHole blockchain
func (bhi *BlackHoleIntegration) SubmitTransaction(bridgeTx *Transaction) (*BlackHoleResponse, error) {
	// Convert string amount to uint64
	amount, err := parseAmountToUint64(bridgeTx.Amount)
	if err != nil {
		return nil, fmt.Errorf("invalid amount format: %v", err)
	}

	// Convert bridge transaction to BlackHole format
	blackholeTx := &BlackHoleTransaction{
		Type:      "transfer",
		From:      bridgeTx.SourceAddress,
		To:        bridgeTx.DestAddress,
		Amount:    amount,           // Now uint64
		TokenID:   bridgeTx.TokenSymbol, // Correct for /api/relay/submit
		Fee:       1,               // Now uint64
		Nonce:     uint64(time.Now().Unix()), // Now uint64
		Timestamp: time.Now().Unix(),
	}

	// Convert to JSON
	jsonData, err := json.Marshal(blackholeTx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %v", err)
	}

	// Submit to BlackHole API
	submitURL := bhi.getAPIURL("/api/relay/submit")
	resp, err := http.Post(submitURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to submit to BlackHole: %v", err)
	}
	defer resp.Body.Close()

	// Parse response
	var result BlackHoleResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &result, nil
}

// GetBalance gets balance from BlackHole blockchain
func (bhi *BlackHoleIntegration) GetBalance(address, tokenSymbol string) (string, error) {
	balanceURL := bhi.getAPIURL(fmt.Sprintf("/api/balance/%s", address))
	
	resp, err := http.Get(balanceURL)
	if err != nil {
		return "0", fmt.Errorf("failed to get balance from BlackHole: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "0", fmt.Errorf("failed to decode balance response: %v", err)
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		if balance, ok := data["balance"].(string); ok {
			return balance, nil
		}
	}

	return "0", nil
}

// GetTransactionStatus gets transaction status from BlackHole blockchain
func (bhi *BlackHoleIntegration) GetTransactionStatus(txHash string) (string, error) {
	statusURL := bhi.getAPIURL(fmt.Sprintf("/api/transaction/%s", txHash))
	
	resp, err := http.Get(statusURL)
	if err != nil {
		return "unknown", fmt.Errorf("failed to get transaction status: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "unknown", fmt.Errorf("failed to decode status response: %v", err)
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		if status, ok := data["status"].(string); ok {
			return status, nil
		}
	}

	return "unknown", nil
}

// CheckHealth checks if BlackHole blockchain is accessible
func (bhi *BlackHoleIntegration) CheckHealth() error {
	healthURL := bhi.getAPIURL("/api/health")
	
	resp, err := http.Get(healthURL)
	if err != nil {
		return fmt.Errorf("failed to connect to BlackHole API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("BlackHole API returned status %d", resp.StatusCode)
	}

	return nil
}

// GetChainInfo gets information about BlackHole blockchain
func (bhi *BlackHoleIntegration) GetChainInfo() (map[string]interface{}, error) {
	infoURL := bhi.getAPIURL("/api/info")
	
	resp, err := http.Get(infoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain info: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode info response: %v", err)
	}

	return result, nil
}

// getAPIURL converts WebSocket URL to HTTP and appends endpoint
func (bhi *BlackHoleIntegration) getAPIURL(endpoint string) string {
	apiURL := bhi.apiURL
	
	// Convert WebSocket URL to HTTP
	if apiURL[:2] == "ws" {
		apiURL = "http" + apiURL[2:] // ws:// -> http://
	}
	
	// Remove trailing slash
	if apiURL[len(apiURL)-1] == '/' {
		apiURL = apiURL[:len(apiURL)-1]
	}
	
	return apiURL + endpoint
}

// ValidateAddress validates a BlackHole address format
func (bhi *BlackHoleIntegration) ValidateAddress(address string) bool {
	// Basic validation - BlackHole addresses should be non-empty strings
	// You can add more specific validation based on your address format
	return len(address) > 0 && len(address) <= 100
}

// EstimateFee estimates transaction fee for BlackHole blockchain
func (bhi *BlackHoleIntegration) EstimateFee(txType string, amount string) (string, error) {
	// For now, return a fixed fee
	// In production, this could call an API endpoint to get dynamic fees
	switch txType {
	case "transfer":
		return "1", nil
	case "token_transfer":
		return "2", nil
	default:
		return "1", nil
	}
}

// GetSupportedTokens gets list of supported tokens on BlackHole blockchain
func (bhi *BlackHoleIntegration) GetSupportedTokens() ([]string, error) {
	tokensURL := bhi.getAPIURL("/api/tokens")
	
	resp, err := http.Get(tokensURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get supported tokens: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode tokens response: %v", err)
	}

	if data, ok := result["data"].([]interface{}); ok {
		tokens := make([]string, len(data))
		for i, token := range data {
			if tokenStr, ok := token.(string); ok {
				tokens[i] = tokenStr
			}
		}
		return tokens, nil
	}

	// Return default supported tokens if API doesn't provide them
	return []string{"BHX", "USDT", "ETH", "SOL"}, nil
}

// parseAmountToUint64 converts string amount to uint64
// Handles both integer and decimal amounts
func parseAmountToUint64(amountStr string) (uint64, error) {
	// Try parsing as float first to handle decimals like "100.50"
	floatAmount, err := strconv.ParseFloat(amountStr, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse amount as float: %v", err)
	}

	// Convert to uint64 (this truncates decimals)
	// For production, you might want to handle decimals differently
	// e.g., multiply by 10^decimals to preserve precision
	if floatAmount < 0 {
		return 0, fmt.Errorf("amount cannot be negative: %f", floatAmount)
	}

	// Convert to uint64 (truncates decimals)
	return uint64(floatAmount), nil
}
