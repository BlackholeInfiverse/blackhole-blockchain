package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// TestResult represents the result of a test
type TestResult struct {
	TestName    string `json:"test_name"`
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	Duration    string `json:"duration"`
	Timestamp   string `json:"timestamp"`
}

// IntegrationTester handles testing of the bridge-sdk integration
type IntegrationTester struct {
	bridgeURL      string
	blockchainPort int
	results        []TestResult
}

// NewIntegrationTester creates a new integration tester
func NewIntegrationTester() *IntegrationTester {
	bridgeURL := os.Getenv("BRIDGE_URL")
	if bridgeURL == "" {
		bridgeURL = "http://localhost:8084"
	}

	blockchainPortStr := os.Getenv("BLOCKCHAIN_PORT")
	blockchainPort := 3000
	if blockchainPortStr != "" {
		if port, err := strconv.Atoi(blockchainPortStr); err == nil {
			blockchainPort = port
		}
	}

	return &IntegrationTester{
		bridgeURL:      bridgeURL,
		blockchainPort: blockchainPort,
		results:        make([]TestResult, 0),
	}
}

// RunAllTests runs all integration tests
func (it *IntegrationTester) RunAllTests() {
	fmt.Println("🧪 Starting BlackHole Bridge-SDK Integration Tests")
	fmt.Println("=" * 60)

	tests := []func(){
		it.TestBridgeHealth,
		it.TestBlockchainConnection,
		it.TestBridgeStats,
		it.TestRealBlockchainMode,
		it.TestTokenTransfer,
		it.TestDashboardAccess,
		it.TestWebSocketConnection,
		it.TestReplayProtection,
		it.TestCircuitBreaker,
		it.TestErrorHandling,
	}

	for _, test := range tests {
		test()
	}

	it.PrintResults()
}

// TestBridgeHealth tests if the bridge service is healthy
func (it *IntegrationTester) TestBridgeHealth() {
	start := time.Now()
	testName := "Bridge Health Check"

	resp, err := http.Get(it.bridgeURL + "/health")
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("Failed to connect: %v", err), start)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		it.addResult(testName, false, fmt.Sprintf("Health check failed with status: %d", resp.StatusCode), start)
		return
	}

	it.addResult(testName, true, "Bridge service is healthy", start)
}

// TestBlockchainConnection tests connection to real blockchain
func (it *IntegrationTester) TestBlockchainConnection() {
	start := time.Now()
	testName := "Blockchain Connection"

	// Try to connect to blockchain directly
	blockchainURL := fmt.Sprintf("http://localhost:%d/health", it.blockchainPort)
	resp, err := http.Get(blockchainURL)
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("Cannot connect to blockchain: %v", err), start)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		it.addResult(testName, false, fmt.Sprintf("Blockchain health check failed: %d", resp.StatusCode), start)
		return
	}

	it.addResult(testName, true, "Successfully connected to BlackHole blockchain", start)
}

// TestBridgeStats tests if bridge stats include real blockchain data
func (it *IntegrationTester) TestBridgeStats() {
	start := time.Now()
	testName := "Bridge Statistics"

	resp, err := http.Get(it.bridgeURL + "/stats")
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("Failed to get stats: %v", err), start)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("Failed to read response: %v", err), start)
		return
	}

	var statsResponse map[string]interface{}
	if err := json.Unmarshal(body, &statsResponse); err != nil {
		it.addResult(testName, false, fmt.Sprintf("Failed to parse stats: %v", err), start)
		return
	}

	// Check if stats contain blockchain data
	if data, ok := statsResponse["data"]; ok {
		if statsData, ok := data.(map[string]interface{}); ok {
			if chains, ok := statsData["chains"]; ok {
				if chainsData, ok := chains.(map[string]interface{}); ok {
					if blackhole, ok := chainsData["blackhole"]; ok {
						it.addResult(testName, true, fmt.Sprintf("Bridge stats include BlackHole data: %v", blackhole), start)
						return
					}
				}
			}
		}
	}

	it.addResult(testName, false, "Bridge stats missing BlackHole blockchain data", start)
}

// TestRealBlockchainMode tests if bridge is running in real blockchain mode
func (it *IntegrationTester) TestRealBlockchainMode() {
	start := time.Now()
	testName := "Real Blockchain Mode"

	// Check if USE_REAL_BLOCKCHAIN environment variable is set
	useRealBlockchain := os.Getenv("USE_REAL_BLOCKCHAIN")
	if useRealBlockchain != "true" {
		it.addResult(testName, false, "USE_REAL_BLOCKCHAIN not set to true", start)
		return
	}

	it.addResult(testName, true, "Bridge configured for real blockchain mode", start)
}

// TestTokenTransfer tests a real token transfer through the bridge
func (it *IntegrationTester) TestTokenTransfer() {
	start := time.Now()
	testName := "Token Transfer"

	// Create a test transfer request
	transferData := map[string]interface{}{
		"from_chain":    "ethereum",
		"to_chain":      "blackhole",
		"from_address":  "0x1234567890123456789012345678901234567890",
		"to_address":    "blackhole1234567890123456789012345678901234567890",
		"token_symbol":  "ETH",
		"amount":        "1000000000000000000", // 1 ETH in wei
	}

	jsonData, err := json.Marshal(transferData)
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("Failed to marshal transfer data: %v", err), start)
		return
	}

	resp, err := http.Post(it.bridgeURL+"/transfer", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("Failed to submit transfer: %v", err), start)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		it.addResult(testName, false, fmt.Sprintf("Transfer failed with status: %d", resp.StatusCode), start)
		return
	}

	it.addResult(testName, true, "Token transfer submitted successfully", start)
}

// TestDashboardAccess tests if the dashboard is accessible
func (it *IntegrationTester) TestDashboardAccess() {
	start := time.Now()
	testName := "Dashboard Access"

	resp, err := http.Get(it.bridgeURL)
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("Failed to access dashboard: %v", err), start)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		it.addResult(testName, false, fmt.Sprintf("Dashboard not accessible: %d", resp.StatusCode), start)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("Failed to read dashboard: %v", err), start)
		return
	}

	// Check if dashboard contains expected elements
	bodyStr := string(body)
	if !contains(bodyStr, "BlackHole Bridge") {
		it.addResult(testName, false, "Dashboard missing BlackHole Bridge title", start)
		return
	}

	it.addResult(testName, true, "Dashboard accessible and contains expected content", start)
}

// TestWebSocketConnection tests WebSocket connectivity
func (it *IntegrationTester) TestWebSocketConnection() {
	start := time.Now()
	testName := "WebSocket Connection"

	// For now, just test that the WebSocket endpoint exists
	resp, err := http.Get(it.bridgeURL + "/ws/logs")
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("WebSocket endpoint not accessible: %v", err), start)
		return
	}
	defer resp.Body.Close()

	// WebSocket upgrade will fail with HTTP GET, but endpoint should exist
	if resp.StatusCode == 400 || resp.StatusCode == 426 {
		it.addResult(testName, true, "WebSocket endpoint available", start)
		return
	}

	it.addResult(testName, false, fmt.Sprintf("Unexpected WebSocket response: %d", resp.StatusCode), start)
}

// TestReplayProtection tests replay protection functionality
func (it *IntegrationTester) TestReplayProtection() {
	start := time.Now()
	testName := "Replay Protection"

	resp, err := http.Get(it.bridgeURL + "/replay-protection")
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("Failed to get replay protection status: %v", err), start)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		it.addResult(testName, false, fmt.Sprintf("Replay protection endpoint failed: %d", resp.StatusCode), start)
		return
	}

	it.addResult(testName, true, "Replay protection system accessible", start)
}

// TestCircuitBreaker tests circuit breaker functionality
func (it *IntegrationTester) TestCircuitBreaker() {
	start := time.Now()
	testName := "Circuit Breaker"

	resp, err := http.Get(it.bridgeURL + "/circuit-breakers")
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("Failed to get circuit breaker status: %v", err), start)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		it.addResult(testName, false, fmt.Sprintf("Circuit breaker endpoint failed: %d", resp.StatusCode), start)
		return
	}

	it.addResult(testName, true, "Circuit breaker system accessible", start)
}

// TestErrorHandling tests error handling capabilities
func (it *IntegrationTester) TestErrorHandling() {
	start := time.Now()
	testName := "Error Handling"

	resp, err := http.Get(it.bridgeURL + "/errors")
	if err != nil {
		it.addResult(testName, false, fmt.Sprintf("Failed to get error metrics: %v", err), start)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		it.addResult(testName, false, fmt.Sprintf("Error handling endpoint failed: %d", resp.StatusCode), start)
		return
	}

	it.addResult(testName, true, "Error handling system accessible", start)
}

// Helper functions
func (it *IntegrationTester) addResult(testName string, success bool, message string, start time.Time) {
	result := TestResult{
		TestName:  testName,
		Success:   success,
		Message:   message,
		Duration:  time.Since(start).String(),
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
	}
	it.results = append(it.results, result)

	status := "✅ PASS"
	if !success {
		status = "❌ FAIL"
	}

	fmt.Printf("%s %s (%s)\n", status, testName, result.Duration)
	if !success {
		fmt.Printf("   Error: %s\n", message)
	}
}

func (it *IntegrationTester) PrintResults() {
	fmt.Println("\n" + "=" * 60)
	fmt.Println("🧪 Integration Test Results")
	fmt.Println("=" * 60)

	passed := 0
	total := len(it.results)

	for _, result := range it.results {
		if result.Success {
			passed++
		}
	}

	fmt.Printf("Total Tests: %d\n", total)
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", total-passed)
	fmt.Printf("Success Rate: %.1f%%\n", float64(passed)/float64(total)*100)

	// Save results to file
	resultsJSON, _ := json.MarshalIndent(it.results, "", "  ")
	os.WriteFile("integration-test-results.json", resultsJSON, 0644)
	fmt.Println("\nDetailed results saved to: integration-test-results.json")

	if passed == total {
		fmt.Println("\n🎉 All tests passed! Integration is working correctly.")
	} else {
		fmt.Println("\n⚠️  Some tests failed. Please check the configuration and try again.")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		 findInString(s, substr)))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func main() {
	tester := NewIntegrationTester()
	tester.RunAllTests()
}
